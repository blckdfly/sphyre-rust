use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use crate::api::AppState;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub profile: UserProfile,
    pub did: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub website: Option<String>,
    pub phone: Option<String>,
    pub preferences: UserPreferences,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub language: String,
    pub timezone: String,
    pub notifications: NotificationSettings,
    pub privacy: PrivacySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub email_notifications: bool,
    pub push_notifications: bool,
    pub sms_notifications: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    pub profile_visibility: String,
    pub allow_data_sharing: bool,
    pub track_activity: bool,
}

#[async_trait::async_trait]
impl<'a> FromRequestParts<Arc<AppState>> for User {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &'a mut Parts,
        state: &'a Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.strip_prefix("Bearer "));

        let token = auth_header
            .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid authorization header".to_string()))?;

        // Validate token and extract user
        match validate_token(token, state).await {
            Ok(user) => Ok(user),
            Err(_) => Err((StatusCode::UNAUTHORIZED, "Invalid token".to_string())),
        }
    }
}

// Implement your token validation logic
async fn validate_token(_token: &str, _state: &Arc<AppState>) -> Result<User, Box<dyn std::error::Error>> {
    // For example, using JWT:
    /*
    use jsonwebtoken::{decode, DecodingKey, Validation};

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret("your-secret".as_ref()),
        &Validation::default(),
    )?;

    // Look up user in database using claims
    let user = get_user_from_database(&claims.sub, &state.db).await?;
    Ok(user)
    */

    // Placeholder implementation
    Err("Token validation not implemented".into())
}
