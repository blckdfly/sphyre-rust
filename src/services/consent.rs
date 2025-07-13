use std::sync::Arc;
use crate::models::consent::{Consent, ConsentBlockchainReceipt, ConsentEvidence, ConsentRequest, ConsentStatus, ConsentInput};
use crate::services::blockchain::{BlockchainService, IBlockchainService};
use anyhow::{Context, Result};
use chrono::Utc;
use mongodb::{
    bson::{doc, to_document},
    Client as MongoClient,
};
use uuid::Uuid;

pub struct ConsentService<'a> {
    db: &'a MongoClient,
    blockchain: &'a BlockchainService,
}

impl<'a> ConsentService<'a> {
    pub fn new(db: &'a MongoClient, blockchain: &'a BlockchainService) -> Self {
        Self { db, blockchain }
    }

    // Request consent from a user
    pub async fn request_consent(&self, user_id: &str, request: ConsentRequest) -> Result<Consent> {
        let consent_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let consent = Consent {
            id: consent_id,
            user_id: user_id.to_string(),
            requester_id: request.requester_id,
            requester_name: request.requester_name,
            purpose: request.purpose,
            scope: request.scope,
            expiration: request.expiration,
            status: ConsentStatus::Pending,
            evidence: None,
            created_at: now,
            updated_at: now,
        };

        // Store consent request in database
        let consents_collection = self.db.database("ssi_db").collection("consents");
        consents_collection
            .insert_one(to_document(&consent)?, None)
            .await
            .context("Failed to insert consent into database")?;

        Ok(consent)
    }

    // Grant consent
    pub async fn grant_consent(
        &self,
        consent_id: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Consent> {
        let consents_collection = self.db.database("ssi_db").collection("consents");

        // Find the consent
        let result = consents_collection
            .find_one(doc! { "id": consent_id }, None)
            .await?;

        let mut consent: Consent = match result {
            Some(doc) => bson::from_document::<Consent>(doc)?,
            None => return Err(anyhow::anyhow!("Consent not found")),
        };

        // Update consent status
        consent.status = ConsentStatus::Granted;
        consent.updated_at = Utc::now();

        // Create evidence
        let tx_hash = self
            .register_consent_on_blockchain(&consent_id, &consent.user_id, &consent.requester_id)
            .await?;

        consent.evidence = Some(ConsentEvidence {
            timestamp: Utc::now(),
            ip_address,
            user_agent,
            signature: None, // Would include user signature in a real system
            blockchain_receipt: Some(ConsentBlockchainReceipt {
                transaction_id: tx_hash,
                chain_id: "1".to_string(), // Ethereum mainnet
                block_number: 12345678,    // Would be actual block number
                timestamp: Utc::now(),
            }),
        });

        // Update in database
        consents_collection
            .update_one(
                doc! { "id": consent_id },
                doc! { "$set": to_document(&consent)? },
                None,
            )
            .await
            .context("Failed to update consent in database")?;

        Ok(consent)
    }

    // Revoke consent
    pub async fn revoke_consent(&self, consent_id: &str) -> Result<Consent> {
        let consents_collection = self.db.database("ssi_db").collection("consents");

        // Find the consent
        let result = consents_collection
            .find_one(doc! { "id": consent_id }, None)
            .await?;

        let mut consent: Consent = match result {
            Some(doc) => bson::from_document(doc)?,
            None => return Err(anyhow::anyhow!("Consent not found")),
        };

        // Update consent status
        consent.status = ConsentStatus::Revoked;
        consent.updated_at = Utc::now();

        let tx_hash = self
            .revoke_consent_on_blockchain(&consent_id)
            .await?;

        // Update blockchain receipt
        if let Some(evidence) = &mut consent.evidence {
            evidence.blockchain_receipt = Some(ConsentBlockchainReceipt {
                transaction_id: tx_hash,
                chain_id: "1".to_string(), // Ethereum mainnet
                block_number: 12345678,    // Would be actual block number
                timestamp: Utc::now(),
            });
        }

        // Update in database
        consents_collection
            .update_one(
                doc! { "id": consent_id },
                doc! { "$set": to_document(&consent)? },
                None,
            )
            .await
            .context("Failed to update consent in database")?;

        Ok(consent)
    }

    // Get consent by ID
    pub async fn get_consent(&self, consent_id: &str) -> Result<Consent> {
        let consents_collection = self.db.database("ssi_db").collection("consents");

        let result = consents_collection
            .find_one(doc! { "id": consent_id }, None)
            .await?;

        match result {
            Some(doc) => {
                let consent: Consent = bson::from_document(doc)?;
                Ok(consent)
            }
            None => Err(anyhow::anyhow!("Consent not found")),
        }
    }

    // Get consents for a user
    pub async fn get_user_consents(&self, user_id: &str) -> Result<Vec<Consent>> {
        use futures::TryStreamExt;
        let consents_collection = self.db.database("ssi_db").collection("consents");

        let cursor = consents_collection
            .find(doc! { "user_id": user_id }, None)
            .await?;

        let consents: Vec<Consent> = cursor
            .try_collect()
            .await
            .context("Failed to collect consents")?;

        Ok(consents)
    }

    // Get consents requested by a requester
    pub async fn get_requester_consents(&self, requester_id: &str) -> Result<Vec<Consent>> {
        use futures::TryStreamExt;
        let consents_collection = self.db.database("ssi_db").collection("consents");

        let cursor = consents_collection
            .find(doc! { "requester_id": requester_id }, None)
            .await?;

        let consents: Vec<Consent> = cursor
            .try_collect()
            .await
            .context("Failed to collect consents")?;

        Ok(consents)
    }

    // Check if consent exists and is valid
    pub async fn validate_consent(
        &self,
        user_id: &str,
        requester_id: &str,
        scope: &str,
    ) -> Result<bool> {
        let consents_collection = self.db.database("ssi_db").collection::<Consent>("consents");

        // Find active consents with matching scope
        let now = Utc::now();
        let result = consents_collection
            .find_one(
                doc! {
                    "user_id": user_id,
                    "requester_id": requester_id,
                    "status": "granted",
                    "$or": [
                        { "expiration": { "$exists": false } },
                        { "expiration": { "$gt": now } }
                    ],
                    "scope": { "$in": [scope] }
                },
                None,
            )
            .await?;

        Ok(result.is_some())
    }

    async fn register_consent_on_blockchain(
        &self,
        consent_id: &str,
        user_id: &str,
        requester_id: &str,
    ) -> Result<String> {
        // In a real implementation, this would call a smart contract
        // For simulation, we'll use the blockchain service

        let result = self
            .blockchain
            .call_contract(
                "consent_registry",
                "registerConsent",
                vec![
                    consent_id.to_string(),
                    user_id.to_string(),
                    requester_id.to_string(),
                ],
            )
            .await?;

        Ok(result["result"].as_str().unwrap_or_default().to_string())
    }

    // Revoke consent on blockchain
    async fn revoke_consent_on_blockchain(&self, consent_id: &str) -> Result<String> {
        // In a real implementation, this would call a smart contract
        // For simulation, we'll use the blockchain service

        let result = self
            .blockchain
            .call_contract(
                "consent_registry",
                "revokeConsent",
                vec![consent_id.to_string()],
            )
            .await?;

        Ok(result["result"].as_str().unwrap_or_default().to_string())
    }
}

// Wrapper functions for API handlers
pub async fn create_new_consent(
    db: &MongoClient,
    blockchain: &dyn IBlockchainService,
    user_id: &str,
    consent_input: ConsentInput,
) -> Result<Consent> {
    let consent_service = ConsentService::new(db, blockchain);
    let consent_request = ConsentRequest {
        requester_id: consent_input.requester_id,
        requester_name: consent_input.requester_name,
        purpose: consent_input.purpose,
        scope: consent_input.scope,
        expiration: consent_input.expiration,
    };

    let consent = consent_service.request_consent(user_id, consent_request).await?;

    // Auto-grant for now (in a real system, this would require user interaction)
    consent_service.grant_consent(&consent.id, None, None).await
}

pub async fn get_consent_by_id(
    db: &MongoClient,
    consent_id: &str,
    user_id: &str,
) -> Result<Consent> {
    let blockchain_service = BlockchainService::new("", "", Arc::new(()), "".to_string(), "".to_string());
    let consent_service = ConsentService::new(db, &blockchain_service);
    let consent = consent_service.get_consent(consent_id).await?;

    if consent.user_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to access this consent"));
    }

    Ok(consent)
}

pub async fn list_user_consents(
    db: &MongoClient,
    user_id: &str,
) -> Result<Vec<Consent>> {
    let blockchain_service = BlockchainService::new("", "", Arc::new(()), "".to_string(), "".to_string());
    let consent_service = ConsentService::new(db, &blockchain_service);
    consent_service.get_user_consents(user_id).await
}

pub async fn update_consent_by_id(
    db: &MongoClient,
    blockchain: &dyn IBlockchainService,
    consent_id: &str,
    user_id: &str,
    consent_input: ConsentInput,
) -> Result<Consent> {
    let consent_service = ConsentService::new(db, blockchain);

    let existing_consent = consent_service.get_consent(consent_id).await?;
    if existing_consent.user_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to update this consent"));
    }

    // Create a new consent with updated data (simplified approach)
    let consent_request = ConsentRequest {
        requester_id: consent_input.requester_id,
        requester_name: consent_input.requester_name,
        purpose: consent_input.purpose,
        scope: consent_input.scope,
        expiration: consent_input.expiration,
    };

    // For now, create a new consent (in a real system, you'd update the existing one)
    let updated_consent = consent_service.request_consent(user_id, consent_request).await?;
    consent_service.grant_consent(&updated_consent.id, None, None).await
}

pub async fn revoke_consent_by_id(
    db: &MongoClient,
    blockchain: &dyn IBlockchainService,
    consent_id: &str,
    user_id: &str,
) -> Result<bool> {
    let consent_service = ConsentService::new(db, blockchain);

    let existing_consent = consent_service.get_consent(consent_id).await?;
    if existing_consent.user_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to revoke this consent"));
    }

    consent_service.revoke_consent(consent_id).await?;
    Ok(true)
}
