use crate::api::{ApiError, ApiResponse, ApiResult, AppState};
use crate::models::access_log::{AccessPolicy, AccessPolicyInput};
use crate::models::user::User;
use crate::services::access_control::{
    create_access_policy as create_policy_service,
    get_policy_by_id, 
    list_user_policies,
    revoke_policy_by_id, 
    update_policy_by_id,
};
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;

// List all access policies for the authenticated user
pub async fn list_access_policies(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<Vec<AccessPolicy>> {
    let policies = list_user_policies(&state.db.client, &user.id).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(policies, "Access policies retrieved successfully")))
}

pub async fn get_access_policy(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(policy_id): Path<String>,
) -> ApiResult<AccessPolicy> {
    let policy = get_policy_by_id(&state.db.client, &policy_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Access policy not found" => ApiError::NotFound(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(policy, "Access policy retrieved successfully")))
}

// Create a new access policy
pub async fn create_access_policy(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Json(policy_input): Json<AccessPolicyInput>,
) -> ApiResult<AccessPolicy> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let policy = create_policy_service(&state.db.client, blockchain, &user.id, policy_input).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(policy, "Access policy created successfully")))
}

// Update an existing access policy
pub async fn update_access_policy(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(policy_id): Path<String>,
    Json(policy_input): Json<AccessPolicyInput>,
) -> ApiResult<AccessPolicy> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let updated_policy = update_policy_by_id(&state.db.client, blockchain, &policy_id, &user.id, policy_input).await
        .map_err(|e| match e.to_string().as_str() {
            "Access policy not found" => ApiError::NotFound(e.to_string()),
            "Not authorized to update this policy" => ApiError::AccessDenied(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(updated_policy, "Access policy updated successfully")))
}

// Revoke an access policy
pub async fn revoke_access_policy(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Path(policy_id): Path<String>,
) -> ApiResult<bool> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let revoked = revoke_policy_by_id(&state.db.client, blockchain, &policy_id, &user.id).await
        .map_err(|e| match e.to_string().as_str() {
            "Access policy not found" => ApiError::NotFound(e.to_string()),
            "Not authorized to revoke this policy" => ApiError::AccessDenied(e.to_string()),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(ApiResponse::success(revoked, "Access policy revoked successfully")))
}