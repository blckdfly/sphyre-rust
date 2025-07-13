use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    pub id: String,
    pub user_id: String,
    pub resource_id: String,
    pub resource_type: ResourceType,
    pub action: AccessAction,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    DID,
    Credential,
    Consent,
    Profile,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessAction {
    #[serde(rename = "create")]
    Create,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "share")]
    Share,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "login")]
    Login,
    Revoke,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessLogFilter {
    pub user_id: Option<String>,
    pub resource_type: Option<ResourceType>,
    pub action: Option<AccessAction>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub success: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessPolicy {
    pub id: String,
    pub user_id: String,
    pub resource_id: String,
    pub resource_type: String,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessPolicyInput {
    pub resource_id: String,
    pub resource_type: String,
    pub action: String,
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self) // or return a custom string representation
    }
}