use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    #[serde(rename = "did")]
    DID,
    #[serde(rename = "credential")]
    Credential,
    #[serde(rename = "consent")]
    Consent,
    #[serde(rename = "profile")]
    Profile,
    #[serde(rename = "other")]
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