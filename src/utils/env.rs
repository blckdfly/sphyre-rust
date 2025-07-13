use std::env;
use std::path::PathBuf;
use dotenv::dotenv;
use lazy_static::lazy_static;

// Define environment variables with default values
lazy_static! {
    /// Server host address
    pub static ref SERVER_HOST: String = env_or_default("SERVER_HOST", "127.0.0.1");

    /// Server port
    pub static ref SERVER_PORT: u16 = env_or_default("SERVER_PORT", "8080")
        .parse()
        .expect("SERVER_PORT must be a valid port number");

    /// Database URL
    pub static ref DATABASE_URL: String = env_or_default("DATABASE_URL", "postgresql://postgres:postgres@localhost/ssi_wallet");

    /// JWT secret key
    pub static ref JWT_SECRET: String = env_or_default("JWT_SECRET", "development_jwt_secret_key_change_in_production");

    /// JWT expiration time in seconds
    pub static ref JWT_EXPIRATION: i64 = env_or_default("JWT_EXPIRATION", "86400")
        .parse()
        .expect("JWT_EXPIRATION must be a valid number");

    /// IPFS API URL
    pub static ref IPFS_API_URL: String = env_or_default("IPFS_API_URL", "http://127.0.0.1:5001/api/v0");

    /// IPFS Gateway URL
    pub static ref IPFS_GATEWAY_URL: String = env_or_default("IPFS_GATEWAY_URL", "http://127.0.0.1:8080/ipfs");

    /// Ethereum RPC URL
    pub static ref ETH_RPC_URL: String = env_or_default("ETH_RPC_URL", "http://localhost:8545");

    /// Log level
    pub static ref LOG_LEVEL: String = env_or_default("LOG_LEVEL", "info");

    /// Keystore directory
    pub static ref KEYSTORE_DIR: PathBuf = PathBuf::from(env_or_default("KEYSTORE_DIR", ".wallet/keystore"));

    /// Credentials directory
    pub static ref CREDENTIALS_DIR: PathBuf = PathBuf::from(env_or_default("CREDENTIALS_DIR", ".wallet/credentials"));

    /// Chain ID
    pub static ref CHAIN_ID: u64 = env_or_default("CHAIN_ID", "1")
        .parse()
        .expect("CHAIN_ID must be a valid number");

    /// Enable CORS
    pub static ref ENABLE_CORS: bool = env_or_default("ENABLE_CORS", "true")
        .parse()
        .expect("ENABLE_CORS must be true or false");

    /// CORS allowed origins
    pub static ref CORS_ALLOWED_ORIGINS: String = env_or_default("CORS_ALLOWED_ORIGINS", "*");
}

/// Initialize environment variables from .env file
pub fn init() {
    dotenv().ok();
}

/// Get environment variable or return default value
fn env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Check if we're running in development mode
pub fn is_development() -> bool {
    env_or_default("ENVIRONMENT", "development") == "development"
}

/// Check if we're running in production mode
pub fn is_production() -> bool {
    env_or_default("ENVIRONMENT", "development") == "production"
}

/// Get application base directory
pub fn app_dir() -> PathBuf {
    let home_dir = dirs::home_dir()
        .expect("Failed to determine home directory");

    let app_dir = home_dir.join(".ssi_wallet");

    if !app_dir.exists() {
        std::fs::create_dir_all(&app_dir)
            .expect("Failed to create application directory");
    }

    app_dir
}