use crate::models::access_log::{AccessAction, AccessLog, ResourceType, AccessPolicy, AccessPolicyInput};
use crate::models::user::User;
use anyhow::{Context, Result};
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc,  Document},
    Client as MongoClient, Collection,
};
use uuid::Uuid;

pub struct AccessControlService<'a> {
    db: &'a MongoClient,
}

impl<'a> AccessControlService<'a> {
    pub fn new(db: &'a MongoClient) -> Self {
        Self { db }
    }

    // Check if a user has permission to access a resource
    pub async fn check_permission(
        &self,
        user_id: &str,
        resource_id: &str,
        resource_type: ResourceType,
        action: AccessAction,
    ) -> Result<bool> {
        // Admin users have all permissions
        if self.is_admin(user_id).await? {
            return Ok(true);
        }

        // Check if the user owns the resource
        if self.is_owner(user_id, resource_id, &resource_type).await? {
            return Ok(true);
        }

        // Check if the user has consent to access the resource
        if self.has_consent(user_id, resource_id, &resource_type, &action).await? {
            return Ok(true);
        }

        // No permission found
        Ok(false)
    }

    // Log an access attempt
    pub async fn log_access(
        &self,
        user_id: &str,
        resource_id: &str,
        resource_type: ResourceType,
        action: AccessAction,
        success: bool,
        details: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        let logs_collection = self.get_access_logs_collection();

        let log = AccessLog {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            resource_id: resource_id.to_string(),
            resource_type,
            action,
            details,
            ip_address,
            user_agent,
            success,
            timestamp: Utc::now(),
            created_at: Utc::now(),
        };

        logs_collection
            .insert_one(log, None)
            .await
            .context("Failed to insert access log")?;

        Ok(())
    }

    async fn is_admin(&self, user_id: &str) -> Result<bool> {
        let users_collection = self.get_users_collection();

        let result = users_collection
            .find_one(doc! { "id": user_id }, None)
            .await?;

        match result {
            Some(doc) => {
                let user: User = bson::from_document(doc)?;
                Ok(user.is_admin)
            }
            None => Ok(false),
        }
    }

    pub(crate) async fn is_owner(&self, user_id: &str, resource_id: &str, resource_type: &ResourceType) -> Result<bool> {
        match resource_type {
            ResourceType::DID => {
                let users_collection = self.get_users_collection();
                let result = users_collection
                    .find_one(doc! { "id": user_id, "did": resource_id }, None)
                    .await?;
                Ok(result.is_some())
            }
            ResourceType::Credential => {
                // Check if the credential belongs to the user
                let credentials_collection: Collection<Document> = self.db.database("ssi_db").collection("credentials");
                let result = credentials_collection
                    .find_one(
                        doc! {
                            "id": resource_id,
                            "credential_subject.id": user_id
                        },
                        None,
                    )
                    .await?;
                Ok(result.is_some())
            }
            ResourceType::Consent => {
                // Check if the consent involves the user
                let consents_collection: Collection<Document> = self.db.database("ssi_db").collection("consents");
                let result = consents_collection
                    .find_one(
                        doc! {
                            "id": resource_id,
                            "$or": [
                                { "user_id": user_id },
                                { "requester_id": user_id }
                            ]
                        },
                        None,
                    )
                    .await?;
                Ok(result.is_some())
            }
            ResourceType::Profile => {
                // Check if it's the user's profile
                Ok(user_id == resource_id)
            }
            ResourceType::Other => {
                // For other resource types, we'd need more specific logic
                // For now, return false to be safe
                Ok(false)
            }
        }
    }

    async fn has_consent(
        &self,
        user_id: &str,
        resource_id: &str,
        resource_type: &ResourceType,
        action: &AccessAction,
    ) -> Result<bool> {
        let consents_collection: Collection<Document> = self.db.database("ssi_db").collection("consents");

        // Find relevant active consents
        let now = Utc::now();
        let result = consents_collection
            .find_one(
                doc! {
                    "requester_id": user_id,
                    "status": "granted",
                    "$or": [
                        { "expiration": { "$exists": false } },
                        { "expiration": { "$gt": now } }
                    ],
                    "scope": {
                        "$elemMatch": {
                            "$or": [
                                // General resource type consent
                                { "$eq": resource_type.to_string() },
                                // Specific resource consent
                                {
                                    "$eq": {
                                        match resource_type {
                                            ResourceType::Credential => format!("credential:{}", resource_id),
                                            ResourceType::DID => format!("did:{}", resource_id),
                                            ResourceType::Profile => format!("profile:{}", resource_id),
                                            _ => resource_id.to_string(),
                                        }
                                    }
                                }
                            ]
                        }
                    }
                },
                None,
            )
            .await?;

        Ok(result.is_some())
    }

    // Get access logs for a user
    pub async fn get_user_logs(&self, user_id: &str, limit: Option<i64>) -> Result<Vec<AccessLog>> {
        let logs_collection = self.get_access_logs_collection();
        let options = mongodb::options::FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .limit(limit)
            .build();

        let cursor = logs_collection
            .find(doc! { "user_id": user_id }, options)
            .await?;

        let logs: Vec<AccessLog> = cursor
            .try_collect()
            .await
            .context("Failed to collect access logs")?;

        Ok(logs)
    }

    // Get resource access logs
    pub async fn get_resource_logs(
        &self,
        resource_id: &str,
        resource_type: &ResourceType,
        limit: Option<i64>,
    ) -> Result<Vec<AccessLog>> {
        let logs_collection = self.get_access_logs_collection();
        let options = mongodb::options::FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .limit(limit)
            .build();

        let cursor = logs_collection
            .find(
                doc! {
                    "resource_id": resource_id,
                    "resource_type": resource_type.to_string()
                },
                options,
            )
            .await?;

        let logs: Vec<AccessLog> = cursor
            .try_collect()
            .await
            .context("Failed to collect resource access logs")?;

        Ok(logs)
    }

    // Helper functions to get collections
    fn get_users_collection(&self) -> Collection<Document> {
        self.db.database("ssi_db").collection("users")
    }

    fn get_access_logs_collection(&self) -> Collection<AccessLog> {
        self.db.database("ssi_db").collection("access_logs")
    }
}

// Standalone functions for use in handlers
pub async fn list_user_policies(db: &MongoClient, user_id: &str) -> Result<Vec<AccessPolicy>> {
    let collection: Collection<AccessPolicy> = db.database("ssi_db").collection("access_policies");
    let cursor = collection
        .find(doc! { "user_id": user_id }, None)
        .await?;
    let policies = cursor.try_collect().await?;
    Ok(policies)
}

pub async fn get_policy_by_id(
    db: &MongoClient,
    policy_id: &str,
    user_id: &str,
) -> Result<AccessPolicy> {
    let collection: Collection<AccessPolicy> = db.database("ssi_db").collection("access_policies");
    let result = collection
        .find_one(doc! { "id": policy_id, "user_id": user_id }, None)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Access policy not found"))?;
    Ok(result)
}

pub async fn create_access_policy(
    db: &MongoClient,
    _blockchain: &impl std::fmt::Debug,
    user_id: &str,
    input: AccessPolicyInput,
) -> Result<AccessPolicy> {
    let new_policy = AccessPolicy {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        resource_id: input.resource_id,
        resource_type: input.resource_type,
        action: input.action,
        created_at: Utc::now(),
    };

    let collection: Collection<AccessPolicy> = db.database("ssi_db").collection("access_policies");
    collection
        .insert_one(new_policy.clone(), None)
        .await?;

    Ok(new_policy)
}

pub async fn update_policy_by_id(
    db: &MongoClient,
    _blockchain: &impl std::fmt::Debug,
    policy_id: &str,
    user_id: &str,
    input: AccessPolicyInput,
) -> Result<AccessPolicy> {
    let collection: Collection<AccessPolicy> = db.database("ssi_db").collection("access_policies");

    let update_doc = doc! {
        "$set": {
            "resource_id": input.resource_id,
            "resource_type": input.resource_type.to_string(),
            "action": input.action.to_string(),
        }
    };

    let result = collection
        .find_one_and_update(
            doc! { "id": policy_id, "user_id": user_id },
            update_doc,
            None,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("Access policy not found"))?;

    Ok(result)
}

pub async fn revoke_policy_by_id(
    db: &MongoClient,
    _blockchain: &impl std::fmt::Debug,
    policy_id: &str,
    user_id: &str,
) -> Result<bool> {
    let collection: Collection<AccessPolicy> = db.database("ssi_db").collection("access_policies");
    let result = collection
        .delete_one(doc! { "id": policy_id, "user_id": user_id }, None)
        .await?;
    if result.deleted_count == 0 {
        Err(anyhow::anyhow!("Access policy not found"))
    } else {
        Ok(true)
    }
}
