use crate::utils::errors::WalletError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type Result<T> = std::result::Result<T, WalletError>;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// DID of the user
    pub did: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// JWT ID (unique identifier for this token)
    pub jti: String,
}

/// Create a new JWT token for a user
pub fn create_token(user_id: &str, did: &str, secret: &str, expiry_hours: i64) -> Result<String> {
    let now = Utc::now();
    let expiry = now + Duration::hours(expiry_hours);

    let claims = Claims {
        sub: user_id.to_string(),
        did: did.to_string(),
        iat: now.timestamp(),
        exp: expiry.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let header = Header::new(Algorithm::HS256);

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
        .map_err(|e| WalletError::JwtError(format!("Token creation failed: {}", e)))
}

/// Validate a JWT token and extract the claims
pub fn validate_token(token: &str, secret: &str) -> Result<Claims> {
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
        .map_err(|e| WalletError::JwtError(format!("Token validation failed: {}", e)))?;

    Ok(token_data.claims)
}

/// Extract JWT token from authorization header
pub fn extract_token_from_header(auth_header: &str) -> Result<&str> {
    if !auth_header.starts_with("Bearer ") {
        return Err(WalletError::JwtError("Invalid authorization header format".to_string()));
    }

    // Split at "Bearer " and take the second part (the token)
    Ok(auth_header.split_at(7).1)
}

/// Create a refresh token
pub fn create_refresh_token(user_id: &str, secret: &str) -> Result<String> {
    let now = Utc::now();
    // Refresh tokens typically have longer expiry times
    let expiry = now + Duration::days(30);

    let claims = Claims {
        sub: user_id.to_string(),
        did: "refresh".to_string(), // Marker to identify as refresh token
        iat: now.timestamp(),
        exp: expiry.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let header = Header::new(Algorithm::HS256);

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
        .map_err(|e| WalletError::JwtError(format!("Refresh token creation failed: {}", e)))
}

/// Validate a refresh token
pub fn validate_refresh_token(token: &str, secret: &str) -> Result<String> {
    let claims = validate_token(token, secret)?;

    // Verify this is a refresh token
    if claims.did != "refresh" {
        return Err(WalletError::JwtError("Invalid refresh token".to_string()));
    }

    Ok(claims.sub)
}