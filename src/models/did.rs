use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: String,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Option<Vec<String>>,
    pub service: Option<Vec<Service>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub type_: String,
    pub controller: String,
    pub public_key_jwk: Option<JWK>,
    pub public_key_multibase: Option<String>,
    pub public_key_hex: ()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWK {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub type_: String,
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionResult {
    pub did_document: DIDDocument,
    pub did_resolution_metadata: DIDResolutionMetadata,
    pub did_document_metadata: DIDDocumentMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDResolutionMetadata {
    pub content_type: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocumentMetadata {
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deactivated: bool,
    pub version_id: String,
}