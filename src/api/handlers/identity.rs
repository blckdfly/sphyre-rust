use crate::api::{ApiError, ApiResponse, ApiResult, AppState};
use crate::models::user::{AuthToken, User, UserCredentials, UserProfile};
use crate::services::identity::{authenticate_user, create_user_did, register_user, update_user_profile};
use axum::{
    extract::{State},
    Json,
};
use std::sync::Arc;

// Register a new user
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(user_data): Json<UserCredentials>,
) -> ApiResult<AuthToken> {
    let result = register_user(&state.db, user_data).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(result, "User registered successfully")))
}

// Login and receive auth token
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(credentials): Json<UserCredentials>,
) -> ApiResult<AuthToken> {
    let token = authenticate_user(&state.db, credentials).await
        .map_err(|e| ApiError::AuthError(e.to_string()))?;

    Ok(Json(ApiResponse::success(token, "Login successful")))
}

// Get user profile
pub async fn get_profile(
    State(_state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<UserProfile> {
    let profile = user.profile;
    Ok(Json(ApiResponse::success(profile, "Profile retrieved successfully")))
}

// Update user profile
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Json(profile): Json<UserProfile>,
) -> ApiResult<UserProfile> {
    let updated_profile = update_user_profile(&state.db, &user.id, profile).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(updated_profile, "Profile updated successfully")))
}

// Get user's DID (Decentralized Identifier)
pub async fn get_did(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<String> {
    let did = user.did.ok_or_else(|| ApiError::NotFound("DID not found".to_string()))?;
    Ok(Json(ApiResponse::success(did, "DID retrieved successfully")))
}

// Create a new DID for the user
pub async fn create_did(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
) -> ApiResult<String> {
    if user.did.is_some() {
        return Err(ApiError::BadRequest("User already has a DID".to_string()));
    }

    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let did = create_user_did(&state.db, blockchain, &user.id).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(did, "DID created successfully")))
}

// Admin endpoint to list all users
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _user: User, // Injected by auth middleware (admin check is done in middleware)
) -> ApiResult<Vec<UserProfile>> {
    use crate::services::identity::list_all_users;

    let users = list_all_users(&state.db).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(users, "Users retrieved successfully")))
}