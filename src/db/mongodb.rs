use anyhow::{Context, Result};
use mongodb::{
    bson::Document,
    options::{ClientOptions, ReplicaSet},
    Client,
};
use std::env;

pub struct MongoDBClient {
    client: Client,
}

impl MongoDBClient {
    pub async fn new() -> Result<Self> {
        let mongodb_uri = env::var("MONGODB_URI").context("MONGODB_URI must be set")?;

        // Parse connection string into options
        let mut client_options = ClientOptions::parse(mongodb_uri)
            .await
            .context("Failed to parse MongoDB connection string")?;

        // Set application name
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

        Ok(Self { client })
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
}