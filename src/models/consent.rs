use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    pub id: String,
    pub user_id: String,
    pub requester_id: String,
    pub requester_name: String,
    pub purpose: String,
    pub scope: Vec<ConsentScope>,
    pub expiration: Option<DateTime<Utc>>,
    pub status: ConsentStatus,
    pub evidence: Option<ConsentEvidence>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsentScope {
    #[serde(rename = "profile")]
    Profile,
    #[serde(rename = "identity")]
    Identity,
    #[serde(rename = "credential")]
    Credential(String), // Specific credential type
    #[serde(rename = "did")]
    DID,
    #[serde(rename = "personal_data")]
    PersonalData(String), // Specific data attribute
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsentStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "granted")]
    Granted,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "revoked")]
    Revoked,
    #[serde(rename = "expired")]
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentEvidence {
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub signature: Option<String>,
    pub blockchain_receipt: Option<ConsentBlockchainReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentBlockchainReceipt {
    pub transaction_id: String,
    pub chain_id: String,
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub requester_id: String,
    pub requester_name: String,
    pub purpose: String,
    pub scope: Vec<ConsentScope>,
    pub expiration: Option<DateTime<Utc>>,
}