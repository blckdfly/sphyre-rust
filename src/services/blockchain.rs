use crate::models::did::{DIDDocument, DIDResolutionResult, DIDResolutionMetadata, DIDDocumentMetadata};
use crate::models::smart_contract::{BlockchainNetwork, BlockchainTransaction, ContractStatus, SmartContract};
use anyhow::{Context, Result};
use chrono::Utc;
use ethers::prelude::*;
use mongodb::{
    bson::{doc, to_document},
    Client as MongoClient,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use async_trait::async_trait;

pub struct BlockchainService {
    db: Arc<MongoClient>,
    provider: Arc<Provider<Http>>,
    wallet: LocalWallet,
    network: String,
    did_registry_address: String,
    pub client: Arc<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>>,
    pub identity_contract_address: Option<String>,
    pub credential_contract_address: Option<String>,
    pub access_control_contract_address: Option<String>,

}

impl BlockchainService {
    pub(crate) fn default() -> BlockchainService {
        todo!()
    }
}

#[async_trait::async_trait]
pub trait IBlockchainService: Send + Sync {
    async fn generate_did(&self, user_id: &str) -> Result<String>;
    async fn resolve_did(&self, did: &str) -> Result<DIDResolutionResult>;
    async fn update_did(&self, did: &str, document: DIDDocument) -> Result<()>;
    async fn get_transaction(&self, tx_hash: &str) -> Result<BlockchainTransaction>;
}

impl BlockchainService {
    //noinspection ALL
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        db: Arc<MongoClient>,
        network: String,
        did_registry_address: String,
    ) -> Result<Self> {
        // Create provider
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create provider")?;
        let provider = Arc::new(provider);

        let wallet = private_key.parse::<LocalWallet>()
            .context("Failed to parse private key")?;

        // Initialize client
        let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));

        Ok(Self {
            client,
            identity_contract_address: None,
            credential_contract_address: None,
            access_control_contract_address: None,
            db,
            provider,
            wallet,
            network,
            did_registry_address,
        })
    }

    pub fn set_identity_contract_address(&mut self, address: String) {
        self.identity_contract_address = Some(address);
    }

    pub fn set_credential_contract_address(&mut self, address: String) {
        self.credential_contract_address = Some(address);
    }

    pub fn set_access_control_contract_address(&mut self, address: String) {
        self.access_control_contract_address = Some(address);
    }

    pub fn get_provider(&self) -> &Arc<Provider<Http>> {
        &self.provider
    }

    pub fn get_wallet(&self) -> &LocalWallet {
        &self.wallet
    }

    pub fn get_provider_clone(&self) -> Arc<Provider<Http>> {
        self.provider.clone()
    }

    pub fn get_wallet_clone(&self) -> LocalWallet {
        self.wallet.clone()
    }

    // Generate a new DID for a user
    pub async fn generate_did(&self, user_id: &str) -> Result<String> {
        let address = self.wallet.address();
        let did = format!("did:ethr:{:x}", address);

        let now = Utc::now();

        let did_document = DIDDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: did.clone(),
            controller: did.clone(),
            verification_method: vec![],  // Would be populated with actual keys
            authentication: vec![],       // Would be populated with key references
            assertion_method: vec![],     // Would be populated with key references
            key_agreement: None,
            service: None,
            created: now,
            updated: now,
        };

        // Store DID document in the database
        let dids_collection = self.db.database("ssi_db").collection("dids");
        dids_collection
            .insert_one(to_document(&did_document)?, None)
            .await
            .context("Failed to insert DID document into database")?;

        // Register DID on the blockchain
        self.register_did_on_blockchain(&did, user_id).await?;

        Ok(did)
    }

    // Register a DID on the blockchain
    async fn register_did_on_blockchain(&self, did: &str, user_id: &str) -> Result<String> {
        // In a real implementation, this would interact with a smart contract
        // For now, we'll simulate the blockchain transaction

        let tx_hash = hex::encode(H256::random().as_bytes());

        // Store the transaction
        let transaction = BlockchainTransaction {
            id: Uuid::new_v4().to_string(),
            hash: tx_hash.clone(),
            contract_id: Some(self.did_registry_address.clone()),
            from_address: format!("{:x}", self.wallet.address()),
            to_address: Some(self.did_registry_address.clone()),
            value: "0".to_string(),
            gas_price: "20000000000".to_string(), // 20 Gwei
            gas_limit: "300000".to_string(),
            gas_used: Some("100000".to_string()),
            data: Some(format!("registerDID({},{})", did, user_id)),
            nonce: 0, // Would be actual nonce in real implementation
            status: crate::models::smart_contract::TransactionStatus::Confirmed,
            block_number: Some(12345678),
            block_hash: Some(hex::encode(H256::random().as_bytes())),
            timestamp: Some(Utc::now()),
            network: BlockchainNetwork::Custom(self.network.clone()),
        };

        let transactions_collection = self.db.database("ssi_db").collection("transactions");
        transactions_collection
            .insert_one(to_document(&transaction)?, None)
            .await
            .context("Failed to insert transaction into database")?;

        Ok(tx_hash)
    }

    // Resolve a DID document
    pub async fn resolve_did(&self, did: &str) -> Result<DIDResolutionResult> {
        let dids_collection = self.db.database("ssi_db").collection("dids");

        let result = dids_collection
            .find_one(doc! { "id": did }, None)
            .await?;

        match result {
            Some(doc) => {
                let did_document: DIDDocument = bson::from_document(doc)?;

                let resolution_result = DIDResolutionResult {
                    did_document_metadata: DIDDocumentMetadata {
                        created: did_document.created,
                        updated: did_document.updated,
                        deactivated: false,
                        version_id: "1".to_string(),
                    },
                    did_document,
                    did_resolution_metadata: DIDResolutionMetadata {
                        content_type: "application/did+json".to_string(),
                        error: None,
                    },
                };

                Ok(resolution_result)
            }
            None => {
                Err(anyhow::anyhow!("DID not found"))
            }
        }
    }

    // Update a DID document
    pub async fn update_did(&self, did: &str, document: DIDDocument) -> Result<()> {
        let dids_collection: mongodb::Collection<DIDDocument> = self.db.database("ssi_db").collection("dids");

        // Update in database
        let update_result = dids_collection
            .update_one(
                doc! { "id": did },
                doc! { "$set": to_document(&document)? },
                None,
            )
            .await?;

        if update_result.matched_count == 0 {
            return Err(anyhow::anyhow!("DID not found"));
        }

        // Register update on blockchain
        self.update_did_on_blockchain(did).await?;

        Ok(())
    }

    async fn update_did_on_blockchain(&self, did: &str) -> Result<String> {
        // In a real implementation, this would interact with a smart contract
        // For now, we'll simulate the blockchain transaction

        let tx_hash = hex::encode(H256::random().as_bytes());

        // Store the transaction
        let transaction = BlockchainTransaction {
            id: Uuid::new_v4().to_string(),
            hash: tx_hash.clone(),
            contract_id: Some(self.did_registry_address.clone()),
            from_address: format!("{:x}", self.wallet.address()),
            to_address: Some(self.did_registry_address.clone()),
            value: "0".to_string(),
            gas_price: "20000000000".to_string(), // 20 Gwei
            gas_limit: "300000".to_string(),
            gas_used: Some("100000".to_string()),
            data: Some(format!("updateDID({})", did)),
            nonce: 0, // Would be actual nonce in real implementation
            status: crate::models::smart_contract::TransactionStatus::Confirmed,
            block_number: Some(12345678),
            block_hash: Some(hex::encode(H256::random().as_bytes())),
            timestamp: Some(Utc::now()),
            network: BlockchainNetwork::Custom(self.network.clone()),
        };

        let transactions_collection = self.db.database("ssi_db").collection("transactions");
        transactions_collection
            .insert_one(to_document(&transaction)?, None)
            .await
            .context("Failed to insert transaction into database")?;

        Ok(tx_hash)
    }

    // Deploy a smart contract
    pub async fn deploy_contract(&self, name: &str, version: &str, abi: &str, bytecode: &str, creator: &str) -> Result<SmartContract> {
        // In a real implementation, we would deploy the contract to the blockchain
        // For now, we'll simulate the deployment

        let contract_address = format!("{:x}", H160::random());
        let contract_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let contract = SmartContract {
            id: contract_id.clone(),
            name: name.to_string(),
            version: version.to_string(),
            network: self.network.clone(),
            address: contract_address.clone(),
            abi: abi.to_string(),
            bytecode: Some(bytecode.to_string()),
            created_at: now,
            updated_at: now,
            status: ContractStatus::Deployed,
            creator: creator.to_string(),
            functions: vec![], // Would be parsed from ABI
            events: vec![],    // Would be parsed from ABI
            deployer: "".to_string(),
            deployment_transaction: "".to_string(),
            deployment_block: 0,
        };

        // Store contract in database
        let contracts_collection = self.db.database("ssi_db").collection("contracts");
        contracts_collection
            .insert_one(to_document(&contract)?, None)
            .await
            .context("Failed to insert contract into database")?;

        // Store deployment transaction
        let tx_hash = hex::encode(H256::random().as_bytes());
        let transaction = BlockchainTransaction {
            id: Uuid::new_v4().to_string(),
            hash: tx_hash,
            contract_id: Some(contract_id),
            from_address: format!("{:x}", self.wallet.address()),
            to_address: None, // Contract creation
            value: "0".to_string(),
            gas_price: "20000000000".to_string(), // 20 Gwei
            gas_limit: "1000000".to_string(),
            gas_used: Some("800000".to_string()),
            data: Some(bytecode.to_string()),
            nonce: 0, // Would be actual nonce in real implementation
            status: crate::models::smart_contract::TransactionStatus::Confirmed,
            block_number: Some(12345678),
            block_hash: Some(hex::encode(H256::random().as_bytes())),
            timestamp: Some(now),
            network: BlockchainNetwork::Custom(self.network.clone()),
        };

        let transactions_collection = self.db.database("ssi_db").collection("transactions");
        transactions_collection
            .insert_one(to_document(&transaction)?, None)
            .await
            .context("Failed to insert transaction into database")?;

        Ok(contract)
    }

    // Get blockchain transaction details
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<BlockchainTransaction> {
        let transactions_collection = self.db.database("ssi_db").collection("transactions");

        let result = transactions_collection
            .find_one(doc! { "hash": tx_hash }, None)
            .await?;

        match result {
            Some(doc) => {
                let transaction: BlockchainTransaction = bson::from_document(doc)?;
                Ok(transaction)
            }
            None => {
                Err(anyhow::anyhow!("Transaction not found"))
            }
        }
    }

    // Call a smart contract function
    pub async fn call_contract(&self, contract_id: &str, function: &str, params: Vec<String>) -> Result<serde_json::Value> {
        // In a real implementation, this would call the smart contract
        // For now, we'll simulate the call

        // Find contract
        let contracts_collection = self.db.database("ssi_db").collection("contracts");
        let result = contracts_collection
            .find_one(doc! { "id": contract_id }, None)
            .await?;

        let contract = match result {
            Some(doc) => {
                let contract: SmartContract = bson::from_document(doc)?;
                contract
            }
            None => {
                return Err(anyhow::anyhow!("Contract not found"));
            }
        };

        // Simulate contract call
        // In reality, this would use ethers-rs to make a call

        // For now, return a mock response
        Ok(json!({
            "success": true,
            "contract": contract.address,
            "function": function,
            "params": params,
            "result": "0x0000000000000000000000000000000000000000000000000000000000000001"
        }))
    }
}

#[async_trait::async_trait]
impl IBlockchainService for BlockchainService {
    async fn generate_did(&self, user_id: &str) -> Result<String> {
        self.generate_did(user_id).await
    }

    async fn resolve_did(&self, did: &str) -> Result<DIDResolutionResult> {
        self.resolve_did(did).await
    }

    async fn update_did(&self, did: &str, document: DIDDocument) -> Result<()> {
        self.update_did(did, document).await
    }

    async fn get_transaction(&self, tx_hash: &str) -> Result<BlockchainTransaction> {
        self.get_transaction(tx_hash).await
    }

    // Tambahkan method lainnya sesuai dengan kebutuhan create_new_consent()
}
