// Constants for SSI Wallet Application

// JWT related constants
pub const JWT_SECRET: &str = "your_jwt_secret_key_here"; // Change in production
pub const JWT_EXPIRATION: i64 = 24 * 60 * 60; // 24 hours in seconds

// IPFS related constants
pub const IPFS_API_URL: &str = "http://127.0.0.1:5001/api/v0";
pub const IPFS_GATEWAY_URL: &str = "http://127.0.0.1:8080/ipfs";

// Blockchain related constants
pub const DEFAULT_GAS_LIMIT: u64 = 6721975;
pub const DEFAULT_GAS_PRICE: u64 = 20000000000;
pub const CHAIN_ID: u64 = 1; // Ethereum mainnet; use appropriate value for your blockchain

// DID related constants
pub const DID_METHOD: &str = "did:ethr";
pub const DID_PREFIX: &str = "did:ethr:";

// Credential related constants
pub const CREDENTIAL_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const DEFAULT_CREDENTIAL_TYPE: &str = "VerifiableCredential";

// API endpoints
pub const API_VERSION: &str = "v1";
pub const API_PREFIX: &str = "/api";

// Security settings
pub const PASSWORD_HASH_ITERATIONS: u32 = 100_000;
pub const PASSWORD_HASH_LEN: usize = 32;
pub const PASSWORD_SALT_LEN: usize = 16;

// Storage paths
pub const DEFAULT_KEY_STORE_PATH: &str = ".wallet/keystore";
pub const DEFAULT_CREDENTIALS_PATH: &str = ".wallet/credentials";