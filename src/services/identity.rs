use crate::blockchain::BlockchainService;
use crate::models::user::{AuthToken, User, UserCredentials, UserProfile};
use crate::utils::crypto::{hash_password, verify_password};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use mongodb::{bson::{doc, to_bson, to_document, Document},  Collection};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;
use crate::db::mongodb::MongoDBClient;
use crate::models::{NotificationSettings, PrivacySettings, UserPreferences};

// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,       // Subject (user ID)
    exp: usize,        // Expiration time
    iat: usize,        // Issued at
    email: String,     // User email
}

pub async fn register_user(db: &MongoDBClient, credentials: UserCredentials) -> Result<AuthToken> {
    let users_collection = get_users_collection(db);

    if users_collection
        .find_one(doc! { "email": &credentials.email }, None)
        .await?
        .is_some()
    {
        anyhow::bail!("User with this email already exists");
    }

    // Hash the password
    let salt = b"default_salt"; // You should use a proper random salt
    let hashed_password = hash_password(&credentials.password, salt)?;

    // Create a new user
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let user = User {
        id: user_id.clone(),
        email: credentials.email.clone(),
        password_hash: hex::encode(hashed_password),
        profile: UserProfile {
            name: credentials.email.clone(),
            avatar_url: None,
            bio: None,
            location: None,
            website: None,
            phone: None,
            created_at: now,
            updated_at: now,
            preferences: UserPreferences {
                language: "".to_string(),
                timezone: "".to_string(),
                notifications: NotificationSettings {
                    email_notifications: false,
                    push_notifications: false,
                    sms_notifications: false,
                },
                privacy: PrivacySettings {
                    profile_visibility: "".to_string(),
                    allow_data_sharing: false,
                    track_activity: false,
                },
            },
        },
        did: None,
        is_admin: false,
        created_at: now,
        updated_at: now,
    };

    // Insert user into database
    users_collection
        .insert_one(to_document(&user)?, None)
        .await
        .context("Failed to insert user into database")?;

    // Generate auth token
    generate_auth_token(&user)
}

// Authenticate user and return token
pub async fn authenticate_user(db: &MongoDBClient, credentials: UserCredentials) -> Result<AuthToken> {
    let users_collection = get_users_collection(db);

    let user_doc = users_collection
        .find_one(doc! { "email": &credentials.email }, None)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let user: User = bson::from_document(user_doc)?;

    // Verify password
    let salt = b"default_salt"; // Should match the salt used during registration
    if !verify_password(&credentials.password, salt, &hex::decode(&user.password_hash).map_err(|_| anyhow::anyhow!("Invalid password hash"))?) {
        anyhow::bail!("Invalid password");
    }

    // Generate auth token
    generate_auth_token(&user)
}

// Validate auth token and return user
pub async fn validate_auth_token(db: &MongoDBClient, token: &str) -> Result<User> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // Decode and validate JWT token
    let token_data = jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    ).context("Invalid token")?;

    let users_collection = get_users_collection(db);

    // Find user by ID
    let user_doc = users_collection
        .find_one(doc! { "id": &token_data.claims.sub }, None)
        .await?
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let user: User = bson::from_document(user_doc)?;

    Ok(user)
}

// Update user profile
pub async fn update_user_profile(db: &MongoDBClient, user_id: &str, profile: UserProfile) -> Result<UserProfile> {
    let users_collection = get_users_collection(db);

    // Update profile fields
    let mut updated_profile = profile;
    updated_profile.updated_at = Utc::now();

    // Update in database
    let update_result = users_collection
        .update_one(
            doc! { "id": user_id },
            doc! { "$set": {
                "profile": to_bson(&updated_profile)?,
                "updated_at": Utc::now()
            }},
            None,
        )
        .await?;

    if update_result.matched_count == 0 {
        anyhow::bail!("User not found");
    }

    Ok(updated_profile)
}

// Create a DID for a user
pub async fn create_user_did(
    db: &MongoDBClient,
    blockchain: &BlockchainService,
    user_id: &str,
) -> Result<String> {
    let did = blockchain.generate_did(user_id).await?;

    // Update user with the new DID
    let users_collection = get_users_collection(db);
    let update_result = users_collection
        .update_one(
            doc! { "id": user_id },
            doc! { "$set": {
                "did": &did,
                "updated_at": Utc::now()
            }},
            None,
        )
        .await?;

    if update_result.matched_count == 0 {
        anyhow::bail!("User not found");
    }

    Ok(did)
}

// List all users (admin function)
pub async fn list_all_users(db: &MongoDBClient) -> Result<Vec<UserProfile>> {
    let users_collection = get_users_collection(db);

    let mut cursor = users_collection.find(None, None).await?;
    let mut users = Vec::new();

    while cursor.advance().await? {
        let user: User = bson::from_document(Document::try_from(cursor.current().clone())?)?;
        users.push(user.profile);
    }

    Ok(users)
}

fn get_users_collection(db: &MongoDBClient) -> Collection<Document> {
    db.client.database("ssi_db").collection("users")
}

// Helper function to generate JWT auth token
fn generate_auth_token(user: &User) -> Result<AuthToken> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let jwt_expiration = env::var("JWT_EXPIRATION")
        .unwrap_or_else(|_| "60".to_string())
        .parse::<i64>()
        .unwrap_or(60);

    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(jwt_expiration))
        .expect("Valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.clone(),
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
        email: user.email.clone(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )?;

    Ok(AuthToken {
        token,
        expires_at: expiration as u64,
    })
}
