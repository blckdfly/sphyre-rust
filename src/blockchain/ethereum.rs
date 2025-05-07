use crate::config::settings::Settings;
use crate::models::did::DIDDocument;
use crate::models::smart_contract::ContractEvent;
use anyhow::{Context, Result};
use ethers::{
    prelude::{Http, Provider, SignerMiddleware},
    signers::{LocalWallet, Signer},
    types::{Address, TransactionReceipt, H256, U256},
};
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;
use web3::{
    contract::{Contract, Options},
    transports::Http as Web3Http,
    types::{Bytes, TransactionParameters},
    Web3,
};

// Ethereum blockchain service implementation
pub struct EthereumService {
    web3: Web3<Web3Http>,
    provider: Arc<Provider<Http>>,
    wallet: Option<LocalWallet>,
    identity_contract_address: Option<Address>,
    credential_contract_address: Option<Address>,
    access_control_contract_address: Option<Address>,
}

impl EthereumService {
    pub async fn new(blockchain_uri: &str) -> Result<Self> {
        // Initialize Web3 connection
        let transport = web3::transports::Http::new(blockchain_uri)?;
        let web3 = Web3::new(transport);

        // Initialize ethers provider
        let provider = Provider::<Http>::try_from(blockchain_uri)
            .context("Failed to initialize Ethereum provider")?;

        Ok(Self {
            web3,
            provider: Arc::new(provider),
            wallet: None,
            identity_contract_address: None,
            credential_contract_address: None,
            access_control_contract_address: None,
        })
    }

    // Set wallet for signing transactions
    pub fn with_wallet(mut self, private_key: &str) -> Result<Self> {
        let wallet = LocalWallet::from_str(private_key)
            .context("Invalid private key format")?;
        self.wallet = Some(wallet);
        Ok(self)
    }

    // Set contract addresses
    pub fn with_contracts(
        mut self,
        identity_address: Option<&str>,
        credential_address: Option<&str>,
        access_control_address: Option<&str>,
    ) -> Result<Self> {
        if let Some(addr) = identity_address {
            self.identity_contract_address = Some(Address::from_str(addr)?);
        }

        if let Some(addr) = credential_address {
            self.credential_contract_address = Some(Address::from_str(addr)?);
        }

        if let Some(addr) = access_control_address {
            self.access_control_contract_address = Some(Address::from_str(addr)?);
        }

        Ok(self)
    }

    // Get identity contract
    pub fn get_identity_contract(&self) -> Result<Contract<Web3Http>> {
        let address = self.identity_contract_address
            .ok_or_else(|| anyhow::anyhow!("Identity contract address not set"))?;

        // Load ABI from embedded file
        let contract_abi = include_str!("./contracts/identity_abi.json");

        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            contract_abi.as_bytes(),
        )?;

        Ok(contract)
    }

    // Get credential contract
    pub fn get_credential_contract(&self) -> Result<Contract<Web3Http>> {
        let address = self.credential_contract_address
            .ok_or_else(|| anyhow::anyhow!("Credential contract address not set"))?;

        // Load ABI from embedded file
        let contract_abi = include_str!("./contracts/credential_abi.json");

        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            contract_abi.as_bytes(),
        )?;

        Ok(contract)
    }

    // Get access control contract
    pub fn get_access_control_contract(&self) -> Result<Contract<Web3Http>> {
        let address = self.access_control_contract_address
            .ok_or_else(|| anyhow::anyhow!("Access control contract address not set"))?;

        // Load ABI from embedded file
        let contract_abi = include_str!("./contracts/access_control_abi.json");

        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            contract_abi.as_bytes(),
        )?;

        Ok(contract)
    }

    // Generate a new DID
    pub async fn generate_did(&self, user_id: &str) -> Result<String> {
        let contract = self.get_identity_contract()?;

        // Create DID using the identity contract
        let tx_params = Options::default();
        let result = contract.call("createDID", (user_id,), None, tx_params, None).await?;

        // Parse result to string
        let did: String = result;
        Ok(did)
    }

    // Register a credential on the blockchain
    pub async fn register_credential(
        &self,
        issuer_did: &str,
        subject_did: &str,
        credential_hash: &str,
        metadata: &str,
    ) -> Result<H256> {
        let contract = self.get_credential_contract()?;

        // Create credential using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "issueCredential",
                (issuer_did, subject_did, credential_hash, metadata),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Verify a credential on the blockchain
    pub async fn verify_credential(&self, credential_id: &str) -> Result<bool> {
        let contract = self.get_credential_contract()?;

        // Verify using contract
        let result: bool = contract
            .query(
                "verifyCredential",
                (credential_id,),
                None,
                Options::default(),
                None,
            )
            .await?;

        Ok(result)
    }

    // Revoke a credential
    pub async fn revoke_credential(&self, credential_id: &str, revocation_reason: &str) -> Result<H256> {
        let contract = self.get_credential_contract()?;

        // Revoke using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "revokeCredential",
                (credential_id, revocation_reason),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Create access policy on blockchain
    pub async fn create_access_policy(
        &self,
        owner_did: &str,
        resource_id: &str,
        accessor_did: &str,
        permissions: u32,
        expiration: u64,
    ) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Create policy using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "createAccessPolicy",
                (owner_did, resource_id, accessor_did, permissions, expiration),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Update access policy
    pub async fn update_access_policy(
        &self,
        policy_id: &str,
        permissions: u32,
        expiration: u64,
    ) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Update policy using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "updateAccessPolicy",
                (policy_id, permissions, expiration),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Revoke access policy
    pub async fn revoke_access_policy(&self, policy_id: &str) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Revoke policy using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "revokeAccessPolicy",
                (policy_id,),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Create consent record on blockchain
    pub async fn create_consent(
        &self,
        user_did: &str,
        data_controller_did: &str,
        purpose: &str,
        data_categories: &str,
        expiration: u64,
    ) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Create consent using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "createConsent",
                (user_did, data_controller_did, purpose, data_categories, expiration),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Update consent record
    pub async fn update_consent(
        &self,
        consent_id: &str,
        purpose: &str,
        data_categories: &str,
        expiration: u64,
    ) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Update consent using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "updateConsent",
                (consent_id, purpose, data_categories, expiration),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Revoke consent
    pub async fn revoke_consent(&self, consent_id: &str) -> Result<H256> {
        let contract = self.get_access_control_contract()?;

        // Revoke consent using contract
        let tx_params = Options::default();
        let result: TransactionReceipt = contract
            .call(
                "revokeConsent",
                (consent_id,),
                None,
                tx_params,
                None,
            )
            .await?;

        Ok(H256::from_slice(&result.transaction_hash.0))
    }

    // Generic method to subscribe to contract events
    pub async fn subscribe_to_events(&self, contract_type: &str) -> Result<()> {
        // Implementation depends on specific event subscription mechanism
        // This is a placeholder for actual implementation
        Ok(())
    }
}

// Public alias for the Ethereum service as the general blockchain service
pub type BlockchainService = EthereumService;

// Function to initialize blockchain service from settings
pub async fn init_blockchain_service(blockchain_uri: &str) -> Result<BlockchainService> {
    let service = EthereumService::new(blockchain_uri).await?;

    // Here you would typically load contract addresses from config
    // and set them on the service

    Ok(service)
}