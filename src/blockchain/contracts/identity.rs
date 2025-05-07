use anyhow::{Context, Result};
use ethers::prelude::{abigen, Middleware, SignerMiddleware, Provider};
use ethers::types::{Address, H256, U256};
use ethers::providers::Http;
use ethers::signers::LocalWallet;
use std::str::FromStr;
use std::sync::Arc;

// Generate type-safe contract bindings
abigen!(
    IdentityContract,
    r#"[
        function createDID(string memory userId) external returns (string memory)
        function resolveDID(string memory did) external view returns (string memory document)
        function updateDIDDocument(string memory did, string memory document) external returns (bool)
        function deactivateDID(string memory did) external returns (bool)
        event DIDCreated(string indexed did, address indexed controller, uint256 timestamp)
        event DIDUpdated(string indexed did, uint256 timestamp)
        event DIDDeactivated(string indexed did, uint256 timestamp)
    ]"#,
);

pub struct IdentityContractClient {
    contract: IdentityContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl IdentityContractClient {
    pub fn new(
        client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
        contract_address: &str,
    ) -> Result<Self> {
        let address = Address::from_str(contract_address)
            .context("Failed to parse contract address")?;

        let contract = IdentityContract::new(address, client);

        Ok(Self { contract })
    }

    // Create a new DID for a user
    pub async fn create_did(&self, user_id: &str) -> Result<String> {
        let tx = self.contract.create_did(user_id.to_string()).send().await?;
        let receipt = tx.await?
            .context("Transaction failed")?;

        // Parse logs to extract DID
        // This is simplified and would need actual log parsing in real implementation
        let did = format!("did:ssi:{}", user_id);

        Ok(did)
    }

    // Resolve a DID to get its document
    pub async fn resolve_did(&self, did: &str) -> Result<String> {
        let document = self.contract.resolve_did(did.to_string()).call().await?;
        Ok(document)
    }

    // Update a DID document
    pub async fn update_did_document(&self, did: &str, document: &str) -> Result<H256> {
        let tx = self.contract
            .update_did_document(did.to_string(), document.to_string())
            .send()
            .await?;

        let receipt = tx.await?
            .context("Transaction failed")?;

        Ok(receipt.transaction_hash)
    }

    // Deactivate a DID
    pub async fn deactivate_did(&self, did: &str) -> Result<H256> {
        let tx = self.contract
            .deactivate_did(did.to_string())
            .send()
            .await?;

        let receipt = tx.await?
            .context("Transaction failed")?;

        Ok(receipt.transaction_hash)
    }
}