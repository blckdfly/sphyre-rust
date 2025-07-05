use crate::models::access_log::{AccessAction, ResourceType};
use crate::models::user::User;
use crate::services::access_control::AccessControlService;
use anyhow::{Context, Result};
use chrono::Utc;
use futures::StreamExt;
use mongodb::{
    bson::{doc, to_bson, to_document, Bson, Document},
    Client as MongoClient, Collection,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};
use uuid::Uuid;

// Define storage item model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageItem {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub content_type: String,
    pub size: usize,
    pub hash: String,
    pub path: String,
    pub metadata: Option<serde_json::Value>,
    pub is_encrypted: bool,
    pub encryption_method: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub tags: Vec<String>,
}

// Define encryption options
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionOptions {
    pub method: String,
    pub key: Option<String>,
    pub use_user_key: bool,
}

pub struct StorageService<'a> {
    db: &'a MongoClient,
    base_path: String,
    access_control: AccessControlService<'a>,
}

impl<'a> StorageService<'a> {
    pub fn new(db: &'a MongoClient, base_path: String) -> Self {
        let access_control = AccessControlService::new(db);
        Self {
            db,
            base_path,
            access_control,
        }
    }

    // Store a file with optional encryption
    pub async fn store_file(
        &self,
        user_id: &str,
        name: &str,
        content_type: &str,
        data: Vec<u8>,
        metadata: Option<serde_json::Value>,
        tags: Vec<String>,
        encryption: Option<EncryptionOptions>,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<StorageItem> {
        // Generate unique ID and path
        let file_id = Uuid::new_v4().to_string();
        let file_path = format!("{}/{}", self.base_path, file_id);
        let now = Utc::now();

        // Process encryption if requested
        let (final_data, is_encrypted, encryption_method) = match encryption {
            Some(options) => {
                let encrypted = self.encrypt_data(&data, &options).await?;
                (encrypted, true, Some(options.method))
            }
            None => (data, false, None),
        };

        // Calculate hash of the data
        let hash = self.calculate_hash(&final_data);

        // Create storage item record
        let storage_item = StorageItem {
            id: file_id.clone(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            content_type: content_type.to_string(),
            size: final_data.len(),
            hash,
            path: file_path.clone(),
            metadata,
            is_encrypted,
            encryption_method,
            created_at: now,
            updated_at: now,
            tags,
        };

        // Write data to file
        let mut file = File::create(&file_path).await.context("Failed to create file")?;
        file.write_all(&final_data)
            .await
            .context("Failed to write data to file")?;

        // Store metadata in database
        let storage_collection = self.get_storage_collection();
        storage_collection
            .insert_one(to_document(&storage_item)?, None)
            .await
            .context("Failed to insert storage item into database")?;

        // Log the storage action
        self.access_control
            .log_access(
                user_id,
                &file_id,
                ResourceType::Other,
                AccessAction::Create,
                true,
                Some("File stored".to_string()),
                requester_ip,
                user_agent,
            )
            .await?;

        Ok(storage_item)
    }

    // Retrieve a file with permission check
    pub async fn retrieve_file(
        &self,
        user_id: &str,
        file_id: &str,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(StorageItem, Vec<u8>)> {
        // Check access permission
        let has_permission = self
            .access_control
            .check_permission(user_id, file_id, ResourceType::Other, AccessAction::Read)
            .await?;

        if !has_permission {
            // Log failed access attempt
            self.access_control
                .log_access(
                    user_id,
                    file_id,
                    ResourceType::Other,
                    AccessAction::Read,
                    false,
                    Some("Permission denied".to_string()),
                    requester_ip.clone(),
                    user_agent.clone(),
                )
                .await?;

            return Err(anyhow::anyhow!("Permission denied"));
        }

        // Get file metadata
        let storage_collection = self.get_storage_collection();
        let result = storage_collection
            .find_one(doc! { "id": file_id }, None)
            .await?;

        let storage_item: StorageItem = match result {
            Some(doc) => bson::from_document(doc)?,
            None => {
                // Log failed access attempt
                self.access_control
                    .log_access(
                        user_id,
                        file_id,
                        ResourceType::Other,
                        AccessAction::Read,
                        false,
                        Some("File not found".to_string()),
                        requester_ip,
                        user_agent,
                    )
                    .await?;

                return Err(anyhow::anyhow!("File not found"));
            }
        };

        // Read file data
        let mut file = File::open(&storage_item.path)
            .await
            .context("Failed to open file")?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .context("Failed to read file")?;

        // Decrypt if necessary
        let final_data = if storage_item.is_encrypted {
            // Get user for decryption key if needed
            let users_collection = self.db.database("ssi_db").collection("users");
            let user_doc = users_collection
                .find_one(doc! { "id": user_id }, None)
                .await?
                .context("User not found")?;
            let user: User = bson::from_document(user_doc)?;

            self.decrypt_data(&data, &storage_item, &user).await?
        } else {
            data
        };

        // Log successful access
        self.access_control
            .log_access(
                user_id,
                file_id,
                ResourceType::Other,
                AccessAction::Read,
                true,
                Some("File retrieved".to_string()),
                requester_ip,
                user_agent,
            )
            .await?;

        Ok((storage_item, final_data))
    }

    // Delete a file
    pub async fn delete_file(
        &self,
        user_id: &str,
        file_id: &str,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        // Check access permission
        let has_permission = self
            .access_control
            .check_permission(user_id, file_id, ResourceType::Other, AccessAction::Delete)
            .await?;

        if !has_permission {
            // Log failed access attempt
            self.access_control
                .log_access(
                    user_id,
                    file_id,
                    ResourceType::Other,
                    AccessAction::Delete,
                    false,
                    Some("Permission denied".to_string()),
                    requester_ip,
                    user_agent,
                )
                .await?;

            return Err(anyhow::anyhow!("Permission denied"));
        }

        // Get file metadata
        let storage_collection = self.get_storage_collection();
        let result = storage_collection
            .find_one(doc! { "id": file_id }, None)
            .await?;

        let storage_item: StorageItem = match result {
            Some(doc) => bson::from_document(doc)?,
            None => {
                return Err(anyhow::anyhow!("File not found"));
            }
        };

        // Delete from database
        storage_collection
            .delete_one(doc! { "id": file_id }, None)
            .await?;

        // Delete the physical file
        if let Err(e) = tokio::fs::remove_file(&storage_item.path).await {
            // Log error but don't fail if file is already gone
            eprintln!("Error removing file {}: {}", storage_item.path, e);
        }

        // Log successful deletion
        self.access_control
            .log_access(
                user_id,
                file_id,
                ResourceType::Other,
                AccessAction::Delete,
                true,
                Some("File deleted".to_string()),
                requester_ip,
                user_agent,
            )
            .await?;

        Ok(())
    }

    // List files for a user
    pub async fn list_user_files(
        &self,
        user_id: &str,
        tags: Option<Vec<String>>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<StorageItem>> {
        let storage_collection = self.get_storage_collection();

        // Build filter
        let mut filter = doc! { "user_id": user_id };
        if let Some(tag_list) = tags {
            filter.insert("tags", doc! { "$all": tag_list });
        }

        // Configure options
        let find_options = mongodb::options::FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .limit(limit)
            .skip(offset)
            .build();

        // Query database
        let cursor = storage_collection.find(filter, find_options).await?;
        let items = cursor
            .map(|res| -> Result<StorageItem, anyhow::Error> {
                let doc = res?;
                let item: StorageItem = bson::from_document(doc)?;
                Ok(item)
            })
            .collect::<Vec<Result<StorageItem, anyhow::Error>>>()
            .await;

        // Extract results, propagating any errors
        let mut storage_items = Vec::new();
        for item_result in items {
            storage_items.push(item_result?);
        }

        Ok(storage_items)
    }

    // Update file metadata
    pub async fn update_file_metadata(
        &self,
        user_id: &str,
        file_id: &str,
        name: Option<String>,
        metadata: Option<serde_json::Value>,
        tags: Option<Vec<String>>,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<StorageItem> {
        // Check access permission
        let has_permission = self
            .access_control
            .check_permission(user_id, file_id, ResourceType::Other, AccessAction::Update)
            .await?;

        if !has_permission {
            // Log failed access attempt
            self.access_control
                .log_access(
                    user_id,
                    file_id,
                    ResourceType::Other,
                    AccessAction::Update,
                    false,
                    Some("Permission denied".to_string()),
                    requester_ip,
                    user_agent,
                )
                .await?;

            return Err(anyhow::anyhow!("Permission denied"));
        }

        let storage_collection = self.get_storage_collection();
        let now = Utc::now();

        // Build update document
        let mut update_doc = Document::new();
        if let Some(new_name) = name {
            update_doc.insert("name", new_name);
        }
        if let Some(new_metadata) = metadata {
            update_doc.insert("metadata", to_bson(&new_metadata)?);
        }
        if let Some(new_tags) = tags {
            update_doc.insert("tags", to_bson(&new_tags)?);
        }
        update_doc.insert("updated_at", now);

        // Update in database
        let update_result = storage_collection
            .find_one_and_update(
                doc! { "id": file_id, "user_id": user_id },
                doc! { "$set": update_doc },
                mongodb::options::FindOneAndUpdateOptions::builder()
                    .return_document(mongodb::options::ReturnDocument::After)
                    .build(),
            )
            .await?;

        match update_result {
            Some(doc) => {
                let storage_item: StorageItem = bson::from_document(doc)?;

                // Log successful update
                self.access_control
                    .log_access(
                        user_id,
                        file_id,
                        ResourceType::Other,
                        AccessAction::Update,
                        true,
                        Some("Metadata updated".to_string()),
                        requester_ip,
                        user_agent,
                    )
                    .await?;

                Ok(storage_item)
            }
            None => Err(anyhow::anyhow!("File not found or access denied")),
        }
    }

    // Share file with another user
    pub async fn share_file(
        &self,
        owner_id: &str,
        file_id: &str,
        recipient_id: &str,
        expiration: Option<chrono::DateTime<Utc>>,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        // Check if owner has permission
        let is_owner = self
            .access_control
            .is_owner(owner_id, file_id, &ResourceType::Other)
            .await?;

        if !is_owner {
            // Log failed sharing attempt
            self.access_control
                .log_access(
                    owner_id,
                    file_id,
                    ResourceType::Other,
                    AccessAction::Share,
                    false,
                    Some(format!("Not owner, cannot share with {}", recipient_id)),
                    requester_ip.clone(),
                    user_agent.clone(),
                )
                .await?;

            return Err(anyhow::anyhow!("Only the owner can share this file"));
        }

        // Create sharing record in the database
        let shares_collection = self.db.database("ssi_db").collection("file_shares");
        let share_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let share_doc = doc! {
            "id": share_id,
            "file_id": file_id,
            "owner_id": owner_id,
            "recipient_id": recipient_id,
            "created_at": now,
            "expiration": expiration,
            "is_active": true
        };

        shares_collection
            .insert_one(share_doc, None)
            .await
            .context("Failed to create sharing record")?;

        // Log successful sharing
        self.access_control
            .log_access(
                owner_id,
                file_id,
                ResourceType::Other,
                AccessAction::Share,
                true,
                Some(format!("Shared with {}", recipient_id)),
                requester_ip,
                user_agent,
            )
            .await?;

        Ok(())
    }

    // Revoke sharing
    pub async fn revoke_sharing(
        &self,
        owner_id: &str,
        file_id: &str,
        recipient_id: &str,
        requester_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        // Check if owner has permission
        let is_owner = self
            .access_control
            .is_owner(owner_id, file_id, &ResourceType::Other)
            .await?;

        if !is_owner {
            // Log failed revocation attempt
            self.access_control
                .log_access(
                    owner_id,
                    file_id,
                    ResourceType::Other,
                    AccessAction::Revoke,
                    false,
                    Some(format!("Not owner, cannot revoke sharing from {}", recipient_id)),
                    requester_ip.clone(),
                    user_agent.clone(),
                )
                .await?;

            return Err(anyhow::anyhow!("Only the owner can revoke sharing"));
        }

        // Update sharing record
        let shares_collection = self.db.database("ssi_db").collection("file_shares");
        let update_result = shares_collection
            .update_one(
                doc! {
                    "file_id": file_id,
                    "owner_id": owner_id,
                    "recipient_id": recipient_id,
                    "is_active": true
                },
                doc! {
                    "$set": { "is_active": false }
                },
                None,
            )
            .await?;

        if update_result.matched_count == 0 {
            return Err(anyhow::anyhow!("Sharing record not found"));
        }

        // Log successful revocation
        self.access_control
            .log_access(
                owner_id,
                file_id,
                ResourceType::Other,
                AccessAction::Revoke,
                true,
                Some(format!("Revoked sharing from {}", recipient_id)),
                requester_ip,
                user_agent,
            )
            .await?;

        Ok(())
    }

    // Helper function to get storage collection
    fn get_storage_collection(&self) -> Collection<Document> {
        self.db.database("ssi_db").collection("storage_items")
    }

    // Helper function to encrypt data
    async fn encrypt_data(&self, data: &[u8], options: &EncryptionOptions) -> Result<Vec<u8>> {
        // In a real implementation, this would use a proper encryption library
        // For this example, we'll simulate encryption with a placeholder

        // Choose encryption method
        match options.method.as_str() {
            "aes256" => {
                // Simulate AES-256 encryption
                // In a real implementation, this would use a proper encryption library
                let mut encrypted = Vec::with_capacity(data.len());

                // Simple XOR with a key derived from the provided key or a default
                let key = match &options.key {
                    Some(k) => k.as_bytes().to_vec(),
                    None => b"default_encryption_key_for_simulation".to_vec(),
                };

                for (i, byte) in data.iter().enumerate() {
                    encrypted.push(byte ^ key[i % key.len()]);
                }

                Ok(encrypted)
            }
            "none" => {
                // No encryption, return data as is
                Ok(data.to_vec())
            }
            _ => Err(anyhow::anyhow!("Unsupported encryption method")),
        }
    }

    // Helper function to decrypt data
    async fn decrypt_data(
        &self,
        data: &[u8],
        item: &StorageItem,
        user: &User,
    ) -> Result<Vec<u8>> {
        // In a real implementation, this would use a proper decryption library
        // For this example, we'll simulate decryption with a placeholder

        // Choose decryption method based on the stored encryption method
        match item.encryption_method.as_deref() {
            Some("aes256") => {
                // Simulate AES-256 decryption
                // In a real implementation, this would use a proper decryption library
                let mut decrypted = Vec::with_capacity(data.len());

                // Simple XOR with a key derived from the user's key or a default
                // This matches our simulated encryption above
                let key = b"default_encryption_key_for_simulation".to_vec();

                for (i, byte) in data.iter().enumerate() {
                    decrypted.push(byte ^ key[i % key.len()]);
                }

                Ok(decrypted)
            }
            Some("none") | None => {
                // No encryption was used, return data as is
                Ok(data.to_vec())
            }
            _ => Err(anyhow::anyhow!("Unsupported encryption method")),
        }
    }

    // Helper function to calculate file hash
    fn calculate_hash(&self, data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}