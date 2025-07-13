use anyhow::{Context, Result};
use ethers::prelude::*;
use ethers::types::{H256};
use ethers::providers::Http;
use ethers::signers::LocalWallet;

// Generate type-safe contract bindings
abigen!(
    IdentityContract,
    r#"[
        {
            "inputs": [{"name": "userId", "type": "string"}],
            "name": "createDID",
            "outputs": [{"name": "", "type": "string"}],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [{"name": "did", "type": "string"}],
            "name": "resolveDID",
            "outputs": [{"name": "", "type": "string"}],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [{"name": "did", "type": "string"}, {"name": "document", "type": "string"}],
            "name": "updateDIDDocument",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [{"name": "did", "type": "string"}],
            "name": "deactivateDID",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]"#
);

// Re-export the generated contract type
pub use self::IdentityContract;

pub struct IdentityContractClient {
    contract: IdentityContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl IdentityContractClient {
    pub fn new(contract: IdentityContract<SignerMiddleware<Provider<Http>, LocalWallet>>) -> Self {
        Self { contract }
    }

    pub async fn create_did(&self, user_id: String) -> Result<String, ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>> {
        let result = self.contract.create_did(user_id).call().await?;
        Ok(result)
    }

    // Resolve a DID to get its document
    pub async fn resolve_did(&self, did: &str) -> Result<String> {
        let document = self.contract.resolve_did(did.to_string()).call().await?;
        Ok(document)
    }

    // Update a DID document
    pub async fn update_did_document(&self, did: &str, document: &str) -> Result<H256> {
        let update_call = self.contract.update_did_document(did.to_string(), document.to_string());
        let pending_tx = update_call.send().await?;
        let receipt = pending_tx.await?.context("Transaction failed")?;
        Ok(receipt.transaction_hash)
    }

    // Deactivate a DID
    pub async fn deactivate_did(&self, did: &str) -> Result<H256> {
        let deactivate_call = self.contract.deactivate_did(did.to_string());
        let pending_tx = deactivate_call.send().await?;
        let receipt = pending_tx.await?.context("Transaction failed")?;
        Ok(receipt.transaction_hash)
    }
}
