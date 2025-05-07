use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub app_name: String,
    pub port: u16,
    pub environment: Environment,
    pub mongodb_uri: String,
    pub jwt_secret: String,
    pub jwt_expiration: u64, // in minutes
    pub blockchain_enabled: bool,
    pub blockchain_uri: String,
    pub ipfs_uri: Option<String>,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Environment {
    Development,
    Testing,
    Production,
}

impl Settings {
    pub fn is_development(&self) -> bool {
        self.environment == Environment::Development
    }

    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }
}

// Load configuration from environment variables or .env file
pub fn load_config() -> anyhow::Result<Settings> {
    // Load from .env file if present
    if Path::new(".env").exists() {
        dotenv::dotenv().ok();
    }

    // Parse environment (default to development)
    let environment = match env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()).to_lowercase().as_str() {
        "production" => Environment::Production,
        "testing" => Environment::Testing,
        _ => Environment::Development,
    };

    // Build settings from environment variables
    let settings = Settings {
        app_name: env::var("APP_NAME").unwrap_or_else(|_| "SSI Backend".to_string()),
        port: env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .unwrap_or(3000),
        environment,
        mongodb_uri: env::var("MONGODB_URI").expect("MONGODB_URI must be set"),
        jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        jwt_expiration: env::var("JWT_EXPIRATION")
            .unwrap_or_else(|_| "60".to_string()) // Default 60 minutes
            .parse::<u64>()
            .unwrap_or(60),
        blockchain_enabled: env::var("BLOCKCHAIN_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true),
        blockchain_uri: env::var("BLOCKCHAIN_URI")
            .unwrap_or_else(|_| "http://localhost:8545".to_string()),
        ipfs_uri: env::var("IPFS_URI").ok(),
        log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
    };

    Ok(settings)
}