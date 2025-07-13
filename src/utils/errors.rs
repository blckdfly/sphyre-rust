use std::fmt;
use std::error::Error;
use std::io;
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum WalletError {
    // General errors
    IoError(io::Error),
    SerializationError(String),
    DatabaseError(String),

    // Authentication/Authorization errors
    AuthenticationError(String),
    JwtError(String),
    Unauthorized(String),

    // Wallet specific errors
    WalletNotFound(String),
    CredentialNotFound(String),
    InvalidCredential(String),

    // Blockchain interaction errors
    BlockchainError(String),
    TransactionError(String),

    // Cryptographic errors
    EncryptionError(String),
    DecryptionError(String),
    InvalidKey(String),
    SigningError(String),

    // IPFS errors
    IpfsError(String),

    // DID related errors
    DidError(String),
    DidResolutionError(String),

    // Validation errors
    ValidationError(String),

    // Generic errors
    NotImplemented,
    InternalServerError(String),
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    code: u16,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::IoError(e) => write!(f, "IO Error: {}", e),
            WalletError::SerializationError(msg) => write!(f, "Serialization Error: {}", msg),
            WalletError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            WalletError::AuthenticationError(msg) => write!(f, "Authentication Error: {}", msg),
            WalletError::JwtError(msg) => write!(f, "JWT Error: {}", msg),
            WalletError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            WalletError::WalletNotFound(msg) => write!(f, "Wallet Not Found: {}", msg),
            WalletError::CredentialNotFound(msg) => write!(f, "Credential Not Found: {}", msg),
            WalletError::InvalidCredential(msg) => write!(f, "Invalid Credential: {}", msg),
            WalletError::BlockchainError(msg) => write!(f, "Blockchain Error: {}", msg),
            WalletError::TransactionError(msg) => write!(f, "Transaction Error: {}", msg),
            WalletError::EncryptionError(msg) => write!(f, "Encryption Error: {}", msg),
            WalletError::DecryptionError(msg) => write!(f, "Decryption Error: {}", msg),
            WalletError::InvalidKey(msg) => write!(f, "Invalid Key: {}", msg),
            WalletError::SigningError(msg) => write!(f, "Signing Error: {}", msg),
            WalletError::IpfsError(msg) => write!(f, "IPFS Error: {}", msg),
            WalletError::DidError(msg) => write!(f, "DID Error: {}", msg),
            WalletError::DidResolutionError(msg) => write!(f, "DID Resolution Error: {}", msg),
            WalletError::ValidationError(msg) => write!(f, "Validation Error: {}", msg),
            WalletError::NotImplemented => write!(f, "Functionality Not Implemented"),
            WalletError::InternalServerError(msg) => write!(f, "Internal Server Error: {}", msg),
        }
    }
}

impl Error for WalletError {}

impl From<io::Error> for WalletError {
    fn from(error: io::Error) -> Self {
        WalletError::IoError(error)
    }
}

impl From<serde_json::Error> for WalletError {
    fn from(error: serde_json::Error) -> Self {
        WalletError::SerializationError(error.to_string())
    }
}

impl From<mongodb::error::Error> for WalletError {
    fn from(error: mongodb::error::Error) -> Self {
        WalletError::DatabaseError(error.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for WalletError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        WalletError::JwtError(error.to_string())
    }
}

impl From<anyhow::Error> for WalletError {
    fn from(error: anyhow::Error) -> Self {
        WalletError::InternalServerError(error.to_string())
    }
}

// Implement IntoResponse for Axum compatibility
impl IntoResponse for WalletError {
    fn into_response(self) -> Response {
        let (status_code, error_type) = match self {
            WalletError::AuthenticationError(_) => (StatusCode::UNAUTHORIZED, "authentication_error"),
            WalletError::JwtError(_) => (StatusCode::UNAUTHORIZED, "jwt_error"),
            WalletError::Unauthorized(_) => (StatusCode::FORBIDDEN, "forbidden"),
            WalletError::WalletNotFound(_) | WalletError::CredentialNotFound(_) =>
                (StatusCode::NOT_FOUND, "not_found"),
            WalletError::ValidationError(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            WalletError::NotImplemented => (StatusCode::NOT_IMPLEMENTED, "not_implemented"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_server_error"),
        };

        let error_response = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            code: status_code.as_u16(),
        };

        (status_code, Json(error_response)).into_response()
    }
}

// Helper function for creating error responses
pub fn create_error_response(error: WalletError) -> Response {
    error.into_response()
}

// Helper macro for convenient error creation
#[macro_export]
macro_rules! wallet_err {
    ($err_type:ident, $msg:expr) => {
        crate::utils::errors::WalletError::$err_type($msg.to_string())
    };
}

// Result type alias for convenience
pub type WalletResult<T> = Result<T, WalletError>;