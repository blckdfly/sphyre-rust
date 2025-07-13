use crate::blockchain::contracts::credential::CredentialContractClient;
use crate::models::credential::{
    Credential, CredentialEvidence, CredentialProof, CredentialSchema, CredentialStatus,
    VerifiableCredential,
};

use crate::services::blockchain::BlockchainService;
use crate::blockchain::BlockchainService as ExternalBlockchainService;
use crate::utils::crypto::{generate_signature, verify_signature, hash_data};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ethers::middleware::SignerMiddleware;
use mongodb::{
    bson::{doc, to_document},
    Client as MongoClient,
};
use futures::TryStreamExt;
use serde_json::json;
use std::env;
use std::sync::Arc;
use uuid::Uuid;
use crate::models::CredentialSubject;
use crate::models::credential::CredentialInput;
use crate::models::credential::CredentialVerification;
use crate::db::mongodb::MongoDBClient;

// Standalone functions for use in handlers
pub async fn issue_credential(
    db: &MongoDBClient,
    blockchain: &ExternalBlockchainService,
    user_id: &str,
    credential_input: CredentialInput,
) -> Result<Credential> {
    let mut service = CredentialService::new(&db.client, blockchain);

    // Convert CredentialInput to the parameters needed by the service method
    let credential = service.issue_credential(
        user_id, // issuer_did
        &credential_input.subject_id, // subject_did
        &credential_input.credential_type, // credential_type
        credential_input.claims, // claims
        credential_input.schema_id.as_deref(), // schema_id
        credential_input.expiration, // expiration
    ).await?;

    // Convert VerifiableCredential to Credential for the API response
    Ok(Credential {
        id: credential.credential.id,
        issuer: credential.credential.issuer,
        subject_id: credential.credential.credential_subject["id"].as_str().unwrap_or("").to_string(),
        credential_type: credential.credential.credential_subject["type"].as_str().unwrap_or("").to_string(),
        issuance_date: credential.credential.issuance_date,
        expiration_date: credential.credential.expiration_date,
        credential_subject: Default::default(),
        status: credential.status,
        claims: credential.credential.credential_subject["claims"].clone(),
        schema_id: None,
    })
}

pub async fn list_user_credentials(
    db: &MongoDBClient,
    user_id: &str,
) -> Result<Vec<Credential>> {
    let service = CredentialService::new(&db.client, &BlockchainService::default());

    let verifiable_credentials = service.get_subject_credentials(user_id).await?;

    // Convert VerifiableCredential to Credential for the API response
    let credentials = verifiable_credentials.into_iter().map(|vc| {
        Credential {
            id: vc.credential.id,
            issuer: vc.credential.issuer,
            subject_id: vc.credential.credential_subject["id"].as_str().unwrap_or("").to_string(),
            credential_type: vc.credential.credential_subject["type"].as_str().unwrap_or("").to_string(),
            issuance_date: vc.credential.issuance_date,
            expiration_date: vc.credential.expiration_date,
            credential_subject: Default::default(),
            status: vc.status,
            claims: vc.credential.credential_subject["claims"].clone(),
            schema_id: None,
        }
    }).collect();

    Ok(credentials)
}

pub async fn get_credential_by_id(
    db: &MongoDBClient,
    credential_id: &str,
    user_id: &str,
) -> Result<Credential> {
    let service = CredentialService::new(&db.client, &BlockchainService::default());

    let verifiable_credential = service.get_credential(credential_id).await?;

    // Check if the credential belongs to the user
    let subject_id = verifiable_credential.credential.credential_subject["id"].as_str().unwrap_or("");
    if subject_id != user_id {
        return Err(anyhow::anyhow!("Credential not found"));
    }

    // Convert VerifiableCredential to Credential for the API response
    Ok(Credential {
        id: verifiable_credential.credential.id,
        issuer: verifiable_credential.credential.issuer,
        subject_id: subject_id.to_string(),
        credential_type: verifiable_credential.credential.credential_subject["type"].as_str().unwrap_or("").to_string(),
        issuance_date: verifiable_credential.credential.issuance_date,
        expiration_date: verifiable_credential.credential.expiration_date,
        credential_subject: Default::default(),
        status: verifiable_credential.status,
        claims: verifiable_credential.credential.credential_subject["claims"].clone(),
        schema_id: None,
    })
}

pub async fn verify_credential(
    db: &MongoDBClient,
    blockchain: &BlockchainService,
    verification_request: CredentialVerification,
) -> Result<bool> {
    let mut service = CredentialService::new(&db.client, blockchain);

    service.verify_credential(&verification_request.credential_id).await
}

pub async fn revoke_credential_by_id(
    db: &MongoDBClient,
    blockchain: &BlockchainService,
    credential_id: &str,
    user_id: &str,
) -> Result<bool> {
    let mut service = CredentialService::new(&db.client, blockchain);

    let verifiable_credential = service.get_credential(credential_id).await?;

    let subject_id = verifiable_credential.credential.credential_subject["id"].as_str().unwrap_or("");
    let issuer_id = verifiable_credential.credential.issuer.as_str();

    if subject_id != user_id && issuer_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to revoke this credential"));
    }

    // Revoke the credential
    service.revoke_credential(credential_id, "Revoked by user").await?;

    Ok(true)
}

pub async fn list_all_credentials(
    db: &MongoDBClient,
) -> Result<Vec<Credential>> {
    // For admin use only - list all credentials in the system
    let credentials_collection = db.client.database("ssi_db").collection("credentials");

    let cursor = credentials_collection.find(doc! {}, None).await?;

    let verifiable_credentials: Vec<VerifiableCredential> = cursor
        .try_collect()
        .await
        .context("Failed to collect credentials")?;

    // Convert VerifiableCredential to Credential for the API response
    let credentials = verifiable_credentials.into_iter().map(|vc| {
        Credential {
            id: vc.credential.id,
            issuer: vc.credential.issuer,
            subject_id: vc.credential.credential_subject["id"].as_str().unwrap_or("").to_string(),
            credential_type: vc.credential.credential_subject["type"].as_str().unwrap_or("").to_string(),
            issuance_date: vc.credential.issuance_date,
            expiration_date: vc.credential.expiration_date,
            credential_subject: Default::default(),
            status: vc.status,
            claims: vc.credential.credential_subject["claims"].clone(),
            schema_id: None,
        }
    }).collect();

    Ok(credentials)
}

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

    pub async fn init_credential_contract(&mut self) -> Result<()> {
        if self.credential_contract.is_none() {
            let credential_contract_address =
                env::var("CREDENTIAL_CONTRACT_ADDRESS").context("CREDENTIAL_CONTRACT_ADDRESS must be set")?;

            let provider = self.blockchain.get_provider_clone();
            let wallet = self.blockchain.get_wallet_clone();
            let client = Arc::new(SignerMiddleware::new(provider, wallet));

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
            subject_id: "".to_string(),
            credential_type: "".to_string(),
            status: None,
            claims,
        };


        // Sign with wallet
        let wallet = self.blockchain.get_wallet();
        let signature = generate_signature(wallet)?;

        // Create proof
        let proof = CredentialProof {
            type_: "".to_string(),
            signature,
            signature_type: "EcdsaSecp256k1Signature2019".to_string(),
            created: now,
            verification_method: format!("{}#keys-1", issuer_did),
            proof_purpose: "".to_string(),
            proof_value: "".to_string(),
            purpose: "assertionMethod".to_string(),
            jws: None,
        };

        // Create verifiable credential
        let verifiable_credential = VerifiableCredential {
            context: vec![],
            id: "".to_string(),
            type_: vec![],
            issuer: "".to_string(),
            issuance_date: Default::default(),
            expiration_date: None,
            credential,
            proof,
            status: CredentialStatus::Active,
            evidence: None,
            credential_subject: CredentialSubject { id: "".to_string(), claims: Default::default() },
        };

        let credentials_collection = self.db.database("ssi_db").collection("credentials");
        credentials_collection
            .insert_one(to_document(&verifiable_credential)?, None)
            .await
            .context("Failed to insert credential into database")?;

        // Register on blockchain
        if let Some(contract) = &self.credential_contract {
            json!({
                "type": credential_type,
                "schema": schema_id,
                "expiration": expiration,
            }).to_string();

            let credential_id = contract
                .issue_credential(
                    issuer_did,
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
        self.init_credential_contract().await?;

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
        let credential_hash = hash_data((&credential_json).as_ref());

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
        self.init_credential_contract().await?;

        // Update credential status in database
        let credentials_collection: mongodb::Collection<Credential> = self.db.database("ssi_db").collection("credentials");

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
