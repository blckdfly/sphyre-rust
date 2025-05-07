use crate::blockchain::contracts::credential::CredentialContractClient;
use crate::models::credential::{
    Credential, CredentialEvidence, CredentialProof, CredentialSchema, CredentialStatus,
    VerifiableCredential,
};
use crate::models::did::DIDDocument;
use crate::services::blockchain::BlockchainService;
use crate::utils::crypto::{generate_signature, verify_signature, hash_data};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ethers::signers::{LocalWallet, Signer};
use mongodb::{
    bson::{doc, to_bson, to_document},
    Client as MongoClient,
};
use serde_json::json;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

pub struct CredentialService<'a> {
    db: &'a MongoClient,
    blockchain: &'a BlockchainService,
    credential_contract: Option<CredentialContractClient>,
}

impl<'a> CredentialService<'a> {
    pub fn new(db: &'a MongoClient, blockchain: &'a BlockchainService) -> Self {
        Self {
            db,
            blockchain,
            credential_contract: None,
        }
    }

    // Initialize credential contract client if needed
    pub async fn init_credential_contract(&mut self) -> Result<()> {
        if self.credential_contract.is_none() {
            let credential_contract_address =
                env::var("CREDENTIAL_CONTRACT_ADDRESS").context("CREDENTIAL_CONTRACT_ADDRESS must be set")?;

            // Create ethereum client with the blockchain service's provider and wallet
            let provider = self.blockchain.get_provider().clone();
            let wallet = self.blockchain.get_wallet().clone();
            let client = Arc::new(SignerMiddleware::new(provider, wallet));

            // Initialize credential contract client
            let contract_client = CredentialContractClient::new(client, &credential_contract_address)?;
            self.credential_contract = Some(contract_client);
        }

        Ok(())
    }

    // Issue a new verifiable credential
    pub async fn issue_credential(
        &mut self,
        issuer_did: &str,
        subject_did: &str,
        credential_type: &str,
        claims: serde_json::Value,
        schema_id: Option<&str>,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<VerifiableCredential> {
        // Initialize credential contract if needed
        self.init_credential_contract().await?;

        let cred_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Create credential
        let credential = Credential {
            id: format!("vc:{}", cred_id),
            issuer: issuer_did.to_string(),
            issuance_date: now,
            expiration_date: expiration,
            credential_subject: json!({
                "id": subject_did,
                "type": credential_type,
                "claims": claims
            }),
            schema_id: schema_id.map(|s| s.to_string()),
        };

        // Generate signature for the credential
        let credential_json = serde_json::to_string(&credential)?;
        let credential_hash = hash_data(&credential_json);

        // Sign with wallet
        let wallet = self.blockchain.get_wallet();
        let signature = generate_signature(wallet, &credential_hash)?;

        // Create proof
        let proof = CredentialProof {
            signature,
            signature_type: "EcdsaSecp256k1Signature2019".to_string(),
            created: now,
            verification_method: format!("{}#keys-1", issuer_did),
            purpose: "assertionMethod".to_string(),
        };

        // Create verifiable credential
        let verifiable_credential = VerifiableCredential {
            credential,
            proof,
            status: CredentialStatus::Active,
            evidence: None,
        };

        // Store in database
        let credentials_collection = self.db.database("ssi_db").collection("credentials");
        credentials_collection
            .insert_one(to_document(&verifiable_credential)?, None)
            .await
            .context("Failed to insert credential into database")?;

        // Register on blockchain
        if let Some(contract) = &self.credential_contract {
            let metadata = json!({
                "type": credential_type,
                "schema": schema_id,
                "expiration": expiration,
            }).to_string();

            let credential_id = contract
                .issue_credential(
                    issuer_did,
                    subject_did,
                    &credential_hash,
                    &metadata,
                )
                .await?;

            // Create blockchain evidence
            let evidence = CredentialEvidence {
                id: credential_id,
                type_: "BlockchainRecording".to_string(),
                transaction_hash: "0x...".to_string(), // Would be actual tx hash
                blockchain: "Ethereum".to_string(),
                timestamp: now,
            };

            // Update credential with evidence
            let mut updated_credential = verifiable_credential;
            updated_credential.evidence = Some(evidence);

            credentials_collection
                .update_one(
                    doc! { "credential.id": format!("vc:{}", cred_id) },
                    doc! { "$set": to_document(&updated_credential)? },
                    None,
                )
                .await?;

            return Ok(updated_credential);
        }

        Ok(verifiable_credential)
    }

    // Verify a credential
    pub async fn verify_credential(&mut self, credential_id: &str) -> Result<bool> {
        // Initialize credential contract if needed
        self.init_credential_contract().await?;

        // Get credential from database
        let credential = self.get_credential(credential_id).await?;

        // Check if the credential is revoked
        if credential.status == CredentialStatus::Revoked {
            return Ok(false);
        }

        // Check expiration
        if let Some(expiration) = credential.credential.expiration_date {
            if expiration < Utc::now() {
                return Ok(false);
            }
        }

        // Verify cryptographic proof
        let credential_json = serde_json::to_string(&credential.credential)?;
        let credential_hash = hash_data(&credential_json);

        // Get issuer DID document to find verification key
        let issuer_did_doc = self.blockchain
            .resolve_did(&credential.credential.issuer)
            .await?
            .did_document;

        // Find the verification method referenced in the proof
        let verification_method = issuer_did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id == credential.proof.verification_method)
            .ok_or_else(|| anyhow::anyhow!("Verification method not found"))?;

        // Verify signature
        let signature_valid = verify_signature(
            &verification_method.public_key_hex,
            &credential_hash,
            &credential.proof.signature,
        )?;

        if !signature_valid {
            return Ok(false);
        }

        // Verify on blockchain if available
        if let Some(contract) = &self.credential_contract {
            let blockchain_valid = contract
                .verify_credential(credential_id)
                .await?;

            if !blockchain_valid {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Get a credential by ID
    pub async fn get_credential(&self, credential_id: &str) -> Result<VerifiableCredential> {
        let credentials_collection = self.db.database("ssi_db").collection("credentials");

        let result = credentials_collection
            .find_one(doc! { "credential.id": credential_id }, None)
            .await?;

        match result {
            Some(doc) => {
                let credential: VerifiableCredential = bson::from_document(doc)?;
                Ok(credential)
            }
            None => Err(anyhow::anyhow!("Credential not found")),
        }
    }

    // Get credentials for a subject
    pub async fn get_subject_credentials(&self, subject_did: &str) -> Result<Vec<VerifiableCredential>> {
        let credentials_collection = self.db.database("ssi_db").collection("credentials");

        let cursor = credentials_collection
            .find(
                doc! { "credential.credential_subject.id": subject_did },
                None,
            )
            .await?;

        let credentials: Vec<VerifiableCredential> = cursor
            .try_collect()
            .await
            .context("Failed to collect credentials")?;

        Ok(credentials)
    }

    // Get credentials issued by an issuer
    pub async fn get_issuer_credentials(&self, issuer_did: &str) -> Result<Vec<VerifiableCredential>> {
        let credentials_collection = self.db.database("ssi_db").collection("credentials");

        let cursor = credentials_collection
            .find(doc! { "credential.issuer": issuer_did }, None)
            .await?;

        let credentials: Vec<VerifiableCredential> = cursor
            .try_collect()
            .await
            .context("Failed to collect credentials")?;

        Ok(credentials)
    }

    // Revoke a credential
    pub async fn revoke_credential(&mut self, credential_id: &str, reason: &str) -> Result<()> {
        // Initialize credential contract if needed
        self.init_credential_contract().await?;

        // Update credential status in database
        let credentials_collection = self.db.database("ssi_db").collection("credentials");

        let update_result = credentials_collection
            .update_one(
                doc! { "credential.id": credential_id },
                doc! { "$set": { "status": "revoked", "revocation_reason": reason } },
                None,
            )
            .await?;

        if update_result.matched_count == 0 {
            return Err(anyhow::anyhow!("Credential not found"));
        }

        // Revoke on blockchain if available
        if let Some(contract) = &self.credential_contract {
            contract
                .revoke_credential(credential_id, reason)
                .await?;
        }

        Ok(())
    }

    // Create a new credential schema
    pub async fn create_schema(&self, name: &str, version: &str, attributes: Vec<String>) -> Result<CredentialSchema> {
        let schema_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let schema = CredentialSchema {
            id: format!("schema:{}", schema_id),
            name: name.to_string(),
            version: version.to_string(),
            attributes,
            created_at: now,
            updated_at: now,
        };

        // Store in database
        let schemas_collection = self.db.database("ssi_db").collection("credential_schemas");
        schemas_collection
            .insert_one(to_document(&schema)?, None)
            .await
            .context("Failed to insert schema into database")?;

        Ok(schema)
    }

    // Get schema by ID
    pub async fn get_schema(&self, schema_id: &str) -> Result<CredentialSchema> {
        let schemas_collection = self.db.database("ssi_db").collection("credential_schemas");

        let result = schemas_collection
            .find_one(doc! { "id": schema_id }, None)
            .await?;

        match result {
            Some(doc) => {
                let schema: CredentialSchema = bson::from_document(doc)?;
                Ok(schema)
            }
            None => Err(anyhow::anyhow!("Schema not found")),
        }
    }

    // Create a selective disclosure presentation from credentials
    pub async fn create_presentation(
        &self,
        credentials: Vec<VerifiableCredential>,
        holder_did: &str,
        disclosed_attributes: Vec<String>,
    ) -> Result<serde_json::Value> {
        // Filter out only the requested attributes from each credential
        let presentations = credentials
            .iter()
            .map(|vc| {
                let mut filtered_subject = serde_json::Map::new();

                // Always include the subject ID
                filtered_subject.insert(
                    "id".to_string(),
                    vc.credential.credential_subject["id"].clone(),
                );

                // Include the credential type
                filtered_subject.insert(
                    "type".to_string(),
                    vc.credential.credential_subject["type"].clone(),
                );

                // Filter claims based on disclosed attributes
                if let Some(claims) = vc.credential.credential_subject["claims"].as_object() {
                    let filtered_claims = claims
                        .iter()
                        .filter(|(key, _)| disclosed_attributes.contains(key))
                        .collect::<serde_json::Map<String, serde_json::Value>>();

                    filtered_subject.insert(
                        "claims".to_string(),
                        serde_json::Value::Object(filtered_claims),
                    );
                }

                // Create presentation object
                json!({
                    "credential_id": vc.credential.id,
                    "issuer": vc.credential.issuer,
                    "issuance_date": vc.credential.issuance_date,
                    "subject": filtered_subject,
                    "proof": vc.proof,
                })
            })
            .collect::<Vec<serde_json::Value>>();

        let presentation = json!({
            "id": format!("presentation:{}", Uuid::new_v4()),
            "holder": holder_did,
            "created": Utc::now(),
            "type": "VerifiablePresentation",
            "credentials": presentations
        });

        Ok(presentation)
    }
}