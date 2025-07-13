use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContract {
    pub id: String,
    pub name: String,
    pub version: String,
    pub address: String,
    pub abi: String,
    pub bytecode: Option<String>,
    pub network: String,
    pub status: ContractStatus,     
    pub creator: String,         
    pub functions: Vec<String>,      
    pub events: Vec<String>,       
    pub deployer: String,
    pub deployment_transaction: String,
    pub deployment_block: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainNetwork {
    #[serde(rename = "ethereum")]
    Ethereum,
    #[serde(rename = "polygon")]
    Polygon,
    #[serde(rename = "solana")]
    Solana,
    #[serde(rename = "avalanche")]
    Avalanche,
    #[serde(rename = "local")]
    Local,
    #[serde(rename = "custom")]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractStatus {
    #[serde(rename = "deployed")]
    Deployed,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "terminated")]
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractFunction {
    pub name: String,
    pub inputs: Vec<FunctionParameter>,
    pub outputs: Vec<FunctionParameter>,
    pub constant: bool,
    pub payable: bool,
    pub gas: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParameter {
    pub name: String,
    pub type_: String,
    pub components: Option<Vec<FunctionParameter>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEventDefinition {
    pub name: String,
    pub inputs: Vec<EventParameter>,
    pub anonymous: bool,

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractEvent {
    DIDCreated {
        did: String,
        block_number: u64,
    },
    CredentialIssued {
        credential_id: String,
        issuer: String,
        subject: String,
        block_number: u64,
    },
    CredentialRevoked {
        credential_id: String,
        block_number: u64,
    },
    AccessPolicyCreated {
        policy_id: String,
        resource_id: String,
        block_number: u64,
    },
    AccessPolicyRevoked {
        policy_id: String,
        block_number: u64,
    },
    ConsentGiven {
        consent_id: String,
        user: String,
        controller: String,
        block_number: u64,
    },
    ConsentRevoked {
        consent_id: String,
        block_number: u64,
    },
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventParameter {
    pub name: String,
    pub type_: String,
    pub indexed: bool,
    pub components: Option<Vec<EventParameter>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainTransaction {
    pub id: String,
    pub hash: String,
    pub contract_id: Option<String>,
    pub from_address: String,
    pub to_address: Option<String>,
    pub value: String,
    pub gas_price: String,
    pub gas_limit: String,
    pub gas_used: Option<String>,
    pub data: Option<String>,
    pub nonce: u64,
    pub status: TransactionStatus,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub network: BlockchainNetwork,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "failed")]
    Failed,
}