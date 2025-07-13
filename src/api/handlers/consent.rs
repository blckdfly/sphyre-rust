use crate::api::{ApiError, ApiResponse, ApiResult, AppState};
use crate::models::consent::{Consent, ConsentInput};
use crate::models::user::User;
use crate::services::blockchain::{IBlockchainService};
use crate::services::consent::{
    create_new_consent, get_consent_by_id, list_user_consents,
    revoke_consent_by_id, update_consent_by_id,
};
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;

// List all consents for the authenticated user
pub async fn list_consents(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<Vec<Consent>> {
    let consents = list_user_consents(&state.db.client, &user.id).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(consents, "Consents retrieved successfully")))
}

// Get specific consent by ID
pub async fn get_consent(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(consent_id): Path<String>,
) -> ApiResult<Consent> {
    let consent = get_consent_by_id(&state.db.client, &consent_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Consent not found" => ApiError::NotFound(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(consent, "Consent retrieved successfully")))
}

// Create a new consent
pub async fn create_consent(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Json(consent_input): Json<ConsentInput>,
) -> ApiResult<Consent> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let consent = create_new_consent(
        &state.db.client,
        blockchain as &dyn IBlockchainService,
        &user.id,
        consent_input
    ).await.map_err(|e| ApiError::InternalError(e.to_string()))?;


    Ok(Json(ApiResponse::success(consent, "Consent created successfully")))
}

// Update an existing consent
pub async fn update_consent(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(consent_id): Path<String>,
    Json(consent_input): Json<ConsentInput>,
) -> ApiResult<Consent> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let updated_consent = update_consent_by_id(&state.db.client, blockchain, &consent_id, &user.id, consent_input).await
        .map_err(|e| match e.to_string().as_str() {
            "Consent not found" => ApiError::NotFound(e.to_string()),
            "Not authorized to update this consent" => ApiError::AccessDenied(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(updated_consent, "Consent updated successfully")))
}

// Revoke a consent
pub async fn revoke_consent(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(consent_id): Path<String>,
) -> ApiResult<bool> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let revoked = revoke_consent_by_id(&state.db.client, blockchain, &consent_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Consent not found" => ApiError::NotFound(e.to_string()),
            "Not authorized to revoke this consent" => ApiError::AccessDenied(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(revoked, "Consent revoked successfully")))
}
