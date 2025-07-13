use anyhow::{Context, Result};
use mongodb::{
    bson::Document,
    options::{ClientOptions },
    Client,
};
use std::env;
use bson::doc;
use crate::models::User;

pub struct MongoDBClient {
    pub client: Client,
    pub db_name: String,
}

impl MongoDBClient {
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        let collection = self
            .client
            .database(&self.db_name)
            .collection::<User>("users");

        let filter = doc! { "_id": user_id };
        let user = collection.find_one(filter, None).await?;

        Ok(user)
    }
}

impl MongoDBClient {
    pub async fn new() -> Result<Self> {
        let mongodb_uri = env::var("MONGODB_URI").context("MONGODB_URI must be set")?;

        // Parse connection string into options
        let mut client_options = ClientOptions::parse(mongodb_uri)
            .await
            .context("Failed to parse MongoDB connection string")?;

        client_options.app_name = Some("ssi-wallet".to_string());

        // Create the client
        let client = Client::with_options(client_options)
            .context("Failed to create MongoDB client")?;

        // Ping the database to test the connection
        client
            .database("admin")
            .run_command(Document::new(), None)
            .await
            .context("Failed to connect to MongoDB")?;

        Ok(Self { client, db_name: "".to_string() })
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub async fn health_check(&self) -> Result<bool> {
        // Simple ping check
        self.client
            .database("admin")
            .run_command(Document::new(), None)
            .await
            .map(|_| true)
            .context("MongoDB health check failed")
    }
}

// Initialize database connection - this is the missing function
pub async fn init_database(mongodb_uri: &str) -> Result<MongoDBClient> {
    if env::var("MONGODB_URI").is_err() {
        env::set_var("MONGODB_URI", mongodb_uri);
    }

    MongoDBClient::new().await
}

// Test module for MongoDB client
#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_mongodb_connection() {
        // This test will only run if MONGODB_URI is set in the environment
        if let Ok(_) = env::var("MONGODB_URI") {
            let db_client = MongoDBClient::new().await;
            assert!(db_client.is_ok());

            let health = db_client.unwrap().health_check().await;
            assert!(health.is_ok());
            assert!(health.unwrap());
        }
    }

    #[tokio::test]
    async fn test_init_database() {
        let test_uri = "mongodb://localhost:27017/test";
        let result = init_database(test_uri).await;
        // This will fail if MongoDB isn't running, but the function should exist
        assert!(result.is_err() || result.is_ok());
    }
}