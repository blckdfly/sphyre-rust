use crate::api::{ApiError, AppState};
use crate::models::user::User;
use crate::services::identity::validate_auth_token;
use axum::{
    body::Body,
    extract::State,
    http::{Request},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

// Authentication middleware
pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, ApiError> {
    let token = extract_token_from_header(&request)
        .ok_or_else(|| ApiError::AuthError("Missing or invalid authorization header".to_string()))?;

    // Validate token and get user data
    let user = validate_auth_token(&state.db, &token)
        .await
        .map_err(|e| ApiError::AuthError(e.to_string()))?;

    // Store user in request extensions
    request.extensions_mut().insert(user);

    // Continue with the request
    Ok(next.run(request).await)
}

// Admin authorization middleware (additional layer after authentication)
pub async fn authorize_admin(
    State(..): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, ApiError> {
    let user = request
        .extensions()
        .get::<User>()
        .cloned()
        .ok_or_else(|| ApiError::AuthError("User not authenticated".to_string()))?;

    if !user.is_admin {
        return Err(ApiError::AccessDenied("Admin access required".to_string()));
    }

    // Continue with the request
    Ok(next.run(request).await)
}

// Helper function to extract token from Authorization header
fn extract_token_from_header(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|value| {
            if value.starts_with("Bearer ") {
                Some(value[7..].to_string())
            } else {
                None
            }
        })
}