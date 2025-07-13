use crate::api::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    body::Body,
};
use hyper::Request;
use std::sync::Arc;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}

pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract the token
    let token = &auth_header[7..]; // Remove "Bearer " prefix

    // Decode and validate the JWT token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Fetch the user from the database
    let user = state
        .db
        .get_user_by_id(&token_data.claims.sub)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Insert the user into request extensions
    request.extensions_mut().insert(user);

    // Continue to the next middleware/handler
    Ok(next.run(request).await)
}

pub async fn authorize_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // First, authenticate the user
    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract the token
    let token = &auth_header[7..]; // Remove "Bearer " prefix

    // Decode and validate the JWT token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user = state
        .db
        .get_user_by_id(&token_data.claims.sub)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    // Insert the user into request extensions
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}
