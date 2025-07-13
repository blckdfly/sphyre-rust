use anyhow::{Context, Result};
use ethers::{
    prelude::{Http, Provider, SignerMiddleware},
    signers::{LocalWallet},
    types::{Address, H256},
};
use std::str::FromStr;
use std::sync::Arc;
use web3::{
    contract::{Contract},
    transports::Http as Web3Http,
    Web3,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use clap::builder::TypedValueParser;
use crate::blockchain::contracts::identity::IdentityContract;

// Ethereum blockchain service implementation
#[derive(Debug)]
pub struct EthereumService {
    pub web3: Web3<Web3Http>,
    pub(crate) provider: Arc<Provider<Http>>,
    pub identity_contract_address: Option<Address>,
    pub credential_contract_address: Option<Address>,
    pub access_control_contract_address: Option<Address>,
    client: Option<Arc<SignerMiddleware<Provider<Http>, LocalWallet>>>,
    wallet: Option<LocalWallet>
}

impl EthereumService {
    pub async fn new(blockchain_uri: &str) -> Result<Self> {
        // Initialize Web3 connection
        let transport = web3::transports::Http::new(blockchain_uri)?;
        let web3 = Web3::new(transport);

        let provider = Provider::<Http>::try_from(blockchain_uri)
            .context("Failed to initialize Ethereum provider")?;

        Ok(Self {
            web3,
            provider: Arc::new(provider),
            wallet: None,
            identity_contract_address: None,
            credential_contract_address: None,
            access_control_contract_address: None,
            client: None,
        })
    }

    // Set wallet for signing transactions
    pub fn with_wallet(mut self, private_key: &str) -> Result<Self> {
        let wallet = LocalWallet::from_str(private_key)
            .context("Invalid private key format")?;
        self.wallet = Some(wallet.clone());

        // Create a client with the wallet and provider
        let client = SignerMiddleware::new(
            self.provider.clone(),
            wallet
        );
        self.client = Some(Arc::new(client));

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

    pub fn get_identity_contract(&self) -> Result<Arc<IdentityContract<SignerMiddleware<Provider<Http>, LocalWallet>>>> {
        let address = self.identity_contract_address
            .ok_or_else(|| anyhow::anyhow!("Identity contract address not set"))?;

        // Use the address directly
        let contract_address: Address = address;

        // Get the client or return an error if not initialized
        let client = self.client.clone()
            .ok_or_else(|| anyhow::anyhow!("Client not initialized. Call with_wallet first."))?;

        // Create the contract instance
        let contract = IdentityContract::new(contract_address, client);

        Ok(Arc::new(contract))
    }

    pub fn get_credential_contract(&self) -> Result<Contract<Web3Http>> {
        let address = self.credential_contract_address
            .ok_or_else(|| anyhow::anyhow!("Credential contract address not set"))?;

        // Simple ABI for credential contract
        let contract_abi = r#"[
            {
                "inputs": [
                    {"name": "issuerDid", "type": "string"},
                    {"name": "subjectDid", "type": "string"},
                    {"name": "credentialHash", "type": "string"},
                    {"name": "metadata", "type": "string"}
                ],
                "name": "issueCredential",
                "outputs": [{"name": "", "type": "string"}],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]"#;

        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            contract_abi.as_bytes(),
        )?;

        Ok(contract)
    }

    pub fn get_access_control_contract(&self) -> Result<Contract<Web3Http>> {
        let address = self.access_control_contract_address
            .ok_or_else(|| anyhow::anyhow!("Access control contract address not set"))?;

        // Simple ABI for access control contract
        let contract_abi = r#"[
            {
                "inputs": [
                    {"name": "role", "type": "bytes32"},
                    {"name": "account", "type": "address"}
                ],
                "name": "hasRole",
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]"#;

        let contract = Contract::from_json(
            self.web3.eth(),
            address,
            contract_abi.as_bytes(),
        )?;

        Ok(contract)
    }

    // Generate a new DID
    pub async fn generate_did(&self, user_id: &str) -> Result<String> {
        // For now, generate a simple DID without blockchain interaction In production; this would interact with the smart contract
        let did = format!("did:ssi:ethereum:{}", user_id);
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
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(format!("{}{}{}{}", issuer_did, subject_did, credential_hash, metadata))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    // Verify a credential on the blockchain
    pub async fn verify_credential(&self, credential_id: &str) -> Result<bool> {
        // Simplified implementation - in production would query smart contract
        Ok(!credential_id.is_empty())
    }

    // Revoke a credential
    pub async fn revoke_credential(&self, credential_id: &str, revocation_reason: &str) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(format!("{}{}", credential_id, revocation_reason))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
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
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(format!("{}{}{}{}{}", owner_did, resource_id, accessor_did, permissions, expiration))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    // Update access policy
    pub async fn update_access_policy(
        &self,
        policy_id: &str,
        permissions: u32,
        expiration: u64,
    ) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(format!("{}{}{}", policy_id, permissions, expiration))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    // Revoke access policy
    pub async fn revoke_access_policy(&self, policy_id: &str) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(policy_id)
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    pub async fn create_consent(
        &self,
        user_did: &str,
        data_controller_did: &str,
        purpose: &str,
        data_categories: &str,
        expiration: u64,
    ) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(format!("{}{}{}{}{}", user_did, data_controller_did, purpose, data_categories, expiration))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    pub async fn update_consent(
        &self,
        consent_id: &str,
        purpose: &str,
        data_categories: &str,
        expiration: u64,
    ) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                               DefaultHasher::new()
                                    .hash_one(format!("{}{}{}{}", consent_id, purpose, data_categories, expiration))
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    // Revoke consent
    pub async fn revoke_consent(&self, consent_id: &str) -> Result<H256> {
        // Simplified implementation
        let mock_hash = format!("0x{:x}",
                                DefaultHasher::new()
                                    .hash_one(consent_id)
        );

        Ok(H256::from_str(&mock_hash).unwrap_or_default())
    }

    pub async fn subscribe_to_events(&self,) -> Result<()> {
        Ok(())
    }

    // Get the provider for use in other components
    pub fn get_provider(&self) -> &Provider<Http> {
        &self.provider
    }

    // Get a clone of the provider for use in other components
    pub fn get_provider_clone(&self) -> Arc<Provider<Http>> {
        self.provider.clone()
    }

    // Note: These methods are placeholders and will need to be properly implemented
    // when the wallet field is updated to the correct type

    // Get a clone of the wallet for use in other components
    pub fn get_wallet_clone(&self) -> LocalWallet {
        // This is a placeholder implementation
        LocalWallet::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    // Get a reference to the wallet for use in other components
    pub fn get_wallet(&self) -> &LocalWallet {
        // This is a placeholder implementation that will cause issues
        // It should be fixed by updating the wallet field type
        panic!("Wallet not properly initialized")
    }
}

pub type BlockchainService = EthereumService;

pub async fn init_blockchain_service(blockchain_uri: &str) -> Result<BlockchainService> {
    let service = EthereumService::new(blockchain_uri).await?;

    // Here you would typically load contract addresses from config
    // and set them on the service

    Ok(service)
}

trait HashOne {
    fn hash_one<T: Hash>(&mut self, value: T) -> u64;
}

impl HashOne for DefaultHasher {
    fn hash_one<T: Hash>(&mut self, value: T) -> u64 {
        value.hash(self);
        self.finish()
    }
}
