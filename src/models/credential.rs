use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub type_: Vec<String>,
    pub issuer: String,
    pub issuance_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub credential_subject: CredentialSubject,
    pub proof: CredentialProof,
    pub status: Option<CredentialStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    pub type_: String,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
    pub jws: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    pub type_: String,
    pub status_list_index: Option<String>,
    pub status_list_credential: Option<String>,
    pub revocation_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub type_: Vec<String>,
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub holder: String,
    pub proof: PresentationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationProof {
    pub type_: String,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub challenge: Option<String>,
    pub domain: Option<String>,
    pub proof_purpose: String,
    pub proof_value: String,
    pub jws: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub credential_type: String,
    pub subject_id: String,
    pub claims: HashMap<String, serde_json::Value>,
    pub expiration_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationRequest {
    pub id: String,
    pub requested_credentials: Vec<RequestedCredential>,
    pub challenge: String,
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestedCredential {
    pub type_: String,
    pub required_attributes: Option<Vec<String>>,
    pub predicates: Option<Vec<CredentialPredicate>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPredicate {
    pub attribute: String,
    pub predicate_type: PredicateType,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PredicateType {
    #[serde(rename = ">=")]
    GreaterThanOrEqual,
    #[serde(rename = "<=")]
    LessThanOrEqual,
    #[serde(rename = ">")]
    GreaterThan,
    #[serde(rename = "<")]
    LessThan,
    #[serde(rename = "==")]
    Equal,
}