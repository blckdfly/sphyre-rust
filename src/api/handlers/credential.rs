use winnow::Parser;
use crate::api::{ApiError, ApiResponse, ApiResult, AppState};
use crate::models::credential::{Credential, CredentialInput, CredentialVerification};
use crate::models::user::User;
use crate::services::credential::{
    issue_credential as issue_credential_fn,
    list_user_credentials,
    revoke_credential_by_id,
    verify_credential as verify_credential_fn,
    get_credential_by_id,
    list_all_credentials,
};
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use crate::blockchain::BlockchainService;
use crate::db::mongodb::MongoDBClient;
use anyhow::Result;

// List credentials for the authenticated user
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<Vec<Credential>> {
    let credentials = list_user_credentials(&state.db, &user.id).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(credentials, "Credentials retrieved successfully")))
}

// Get specific credential by ID
pub async fn get_credential(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(credential_id): Path<String>,
) -> ApiResult<Credential> {
    let credential = get_credential_by_id(&state.db, &credential_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Credential not found" => ApiError::NotFound(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(credential, "Credential retrieved successfully")))
}

// Issue a new credential
pub async fn issue_credential(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Json(credential_input): Json<CredentialInput>,
) -> ApiResult<Credential> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let credential = issue_credential_service(&state.db, blockchain, &user.id, credential_input).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(credential, "Credential issued successfully")))
}

async fn issue_credential_service(_p0: &MongoDBClient, _p1: &BlockchainService, _p2: &String, _p3: CredentialInput) -> Result<Credential, Box<dyn std::error::Error>> {
    todo!()
}

// Verify a credential
pub async fn verify_credential(
    State(state): State<Arc<AppState>>,
    _user: User, // Injected by auth middleware
    Json(verification_request): Json<CredentialVerification>,
) -> ApiResult<bool> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let is_valid = verify_credential_service(&state.db, blockchain, verification_request).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(is_valid, "Credential verification completed")))
}

async fn verify_credential_service(_p0: &MongoDBClient, _p1: &BlockchainService, _p2: CredentialVerification) -> Result<bool, Box<dyn std::error::Error>> {
    todo!()
}

// Revoke a credential
pub async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(credential_id): Path<String>,
) -> ApiResult<bool> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let revoked = revoke_credential_by_id(&state.db, blockchain, &credential_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Credential not found" => ApiError::NotFound(e.to_string()),
            "Not authorized to revoke this credential" => ApiError::AccessDenied(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(revoked, "Credential revoked successfully")))
}

// Admin endpoint to list all credentials in the system
pub async fn admin_list_credentials(
    State(state): State<Arc<AppState>>,
    _user: User, // Injected by auth middleware (admin check is done in middleware)
) -> ApiResult<Vec<Credential>> {
    let credentials = list_all_credentials(&state.db).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(credentials, "All credentials retrieved successfully")))
}
