use crate::constant::{IPFS_API_URL, IPFS_GATEWAY_URL};
use crate::utils::errors::WalletError;
use reqwest::Client;
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Type alias for Result with WalletError
pub type Result<T> = std::result::Result<T, WalletError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct IpfsAddResponse {
    pub name: String,
    pub hash: String,
    pub size: String,
}

/// Basic IPFS client for SSI Wallet
pub struct IpfsClient {
    client: Client,
    api_url: String,
    gateway_url: String,
}

impl Default for IpfsClient {
    fn default() -> Self {
        Self::new(IPFS_API_URL, IPFS_GATEWAY_URL)
    }
}

impl IpfsClient {
    /// Create a new IPFS client
    pub fn new(api_url: &str, gateway_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_url: api_url.to_string(),
            gateway_url: gateway_url.to_string(),
        }
    }

    /// Add data to IPFS
    pub async fn add_data(&self, data: &[u8]) -> Result<String> {
        let form = Form::new()
            .part("file", Part::stream(data.to_vec()));

        let response = self.client
            .post(&format!("{}/add", self.api_url))
            .multipart(form)
            .send()
            .await
            .map_err(|e| WalletError::IpfsError(format!("Failed to upload to IPFS: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WalletError::IpfsError(format!("IPFS add failed with status {}: {}", status, error_text)));
        }

        let ipfs_response: IpfsAddResponse = response.json().await
            .map_err(|e| WalletError::IpfsError(format!("Failed to parse IPFS response: {}", e)))?;

        Ok(ipfs_response.hash)
    }

    /// Upload a file to IPFS
    pub async fn add_file(&self, file_path: &str) -> Result<String> {
        let mut file = File::open(file_path).await
            .map_err(|e| WalletError::IpfsError(format!("Failed to open file: {}", e)))?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await
            .map_err(|e| WalletError::IpfsError(format!("Failed to read file: {}", e)))?;

        self.add_data(&buffer).await
    }

    /// Get data from IPFS
    pub async fn get_data(&self, cid: &str) -> Result<Vec<u8>> {
        let response = self.client
            .get(&format!("{}/{}", self.gateway_url, cid))
            .send()
            .await
            .map_err(|e| WalletError::IpfsError(format!("Failed to get data from IPFS: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WalletError::IpfsError(format!("IPFS get failed with status {}: {}", status, error_text)));
        }

        let bytes = response.bytes().await
            .map_err(|e| WalletError::IpfsError(format!("Failed to read IPFS response: {}", e)))?;

        Ok(bytes.to_vec())
    }

    /// Pin content in IPFS to ensure persistence
    pub async fn pin(&self, cid: &str) -> Result<()> {
        let response = self.client
            .post(&format!("{}/pin/add?arg={}", self.api_url, cid))
            .send()
            .await
            .map_err(|e| WalletError::IpfsError(format!("Failed to pin data in IPFS: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WalletError::IpfsError(format!("IPFS pin failed with status {}: {}", status, error_text)));
        }

        Ok(())
    }

    /// Unpin content from IPFS
    pub async fn unpin(&self, cid: &str) -> Result<()> {
        let response = self.client
            .post(&format!("{}/pin/rm?arg={}", self.api_url, cid))
            .send()
            .await
            .map_err(|e| WalletError::IpfsError(format!("Failed to unpin data from IPFS: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WalletError::IpfsError(format!("IPFS unpin failed with status {}: {}", status, error_text)));
        }

        Ok(())
    }

    /// Store credential JSON in IPFS
    pub async fn store_credential<T: Serialize>(&self, credential: &T) -> Result<String> {
        let json = serde_json::to_vec(credential)
            .map_err(|e| WalletError::SerializationError(format!("Failed to serialize credential: {}", e)))?;

        let cid = self.add_data(&json).await?;
        self.pin(&cid).await?;

        Ok(cid)
    }

    /// Retrieve credential from IPFS and deserialize
    pub async fn get_credential<T: for<'de> Deserialize<'de>>(&self, cid: &str) -> Result<T> {
        let data = self.get_data(cid).await?;

        let credential = serde_json::from_slice(&data)
            .map_err(|e| WalletError::SerializationError(format!("Failed to deserialize credential: {}", e)))?;

        Ok(credential)
    }

    /// Get IPFS gateway URL for a CID
    pub fn get_gateway_url(&self, cid: &str) -> String {
        format!("{}/{}", self.gateway_url, cid)
    }
}

// Helper function to create a default IPFS client
pub fn create_ipfs_client() -> IpfsClient {
    IpfsClient::default()
}