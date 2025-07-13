use anyhow::{Context, Result};
use ethers::prelude::{abigen,  SignerMiddleware, Provider};
use ethers::types::{Address, H256, U256};
use ethers::providers::Http;
use ethers::signers::LocalWallet;
use std::str::FromStr;
use std::sync::Arc;

// Generate type-safe contract bindings
abigen!(
    CredentialContract,
    r#"[
        function issueCredential(string memory issuerDid, string memory subjectDid, string memory credentialHash, string memory metadata) external returns (string memory)
        function verifyCredential(string memory credentialId) external view returns (bool)
        function getCredential(string memory credentialId) external view returns (string memory issuerDid, string memory subjectDid, string memory credentialHash, string memory metadata, uint256 issuanceDate, bool revoked)
        function revokeCredential(string memory credentialId, string memory reason) external returns (bool)
        event CredentialIssued(string indexed credentialId, string indexed issuerDid, string indexed subjectDid, uint256 timestamp)
        event CredentialRevoked(string indexed credentialId, string reason, uint256 timestamp)
    ]"#,
);

// Re-export the generated contract type
pub use self::CredentialContract;

pub struct CredentialContractClient {
    contract: CredentialContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl CredentialContractClient {
    pub fn new(
        client: Arc<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>>,
        contract_address: &str,
    ) -> Result<Self> {
        let address = Address::from_str(contract_address)
            .context("Failed to parse contract address")?;

        let contract = CredentialContract::new(address, client);

        Ok(Self { contract })
    }

    // Issue a new verifiable credential
    pub async fn issue_credential(
        &self,
        credential_hash: &str,
    ) -> Result<String> {


        // In a real implementation, you'd extract the credential ID from events
        let credential_id = format!("vc:{}", credential_hash);

        Ok(credential_id)
    }

    // Verify a credential's validity
    pub async fn verify_credential(&self, credential_id: &str) -> Result<bool> {
        let is_valid = self.contract
            .verify_credential(credential_id.to_string())
            .call()
            .await?;

        Ok(is_valid)
    }

    // Get credential details
    pub async fn get_credential(&self, credential_id: &str) -> Result<(String, String, String, String, U256, bool)> {
        let (issuer_did, subject_did, credential_hash, metadata, issuance_date, revoked) = self.contract
            .get_credential(credential_id.to_string())
            .call()
            .await?;

        Ok((issuer_did, subject_did, credential_hash, metadata, issuance_date, revoked))
    }

    // Revoke a credential
    pub async fn revoke_credential(&self, credential_id: &str, reason: &str) -> Result<H256> {
        let revoke_call = self.contract.revoke_credential(credential_id.to_string(), reason.to_string());
        let pending_tx = revoke_call.send().await?;
        let receipt = pending_tx.await?.context("Transaction failed")?;
        Ok(receipt.transaction_hash)
    }
}
