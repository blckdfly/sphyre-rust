pub mod handlers;
pub mod middleware;
pub mod routes;

use crate::blockchain::BlockchainService;
use crate::config::settings::Settings;
use crate::db::mongodb::MongoDBClient;

// Application state that will be shared across all routes
pub struct AppState {
    pub config: Settings,
    pub db: MongoDBClient,
    pub blockchain: Option<BlockchainService>,
}

// Response types
#[derive(serde::Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

// Custom error type for API errors
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Authorization error: {0}")]
    AccessDenied(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Blockchain error: {0}")]
    BlockchainError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),
}

// Implement conversion from various error types to ApiError
impl From<mongodb::error::Error> for ApiError {
    fn from(err: mongodb::error::Error) -> Self {
        ApiError::DatabaseError(err.to_string())
    }
}

impl From<web3::Error> for ApiError {
    fn from(err: web3::Error) -> Self {
        ApiError::BlockchainError(err.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("JSON parsing error: {}", err))
    }
}

// Convert ApiError to axum Response
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::AuthError(_) => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::AccessDenied(_) => (axum::http::StatusCode::FORBIDDEN, self.to_string()),
            ApiError::NotFound(_) => (axum::http::StatusCode::NOT_FOUND, self.to_string()),
            ApiError::BadRequest(_) => (axum::http::StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::BlockchainError(_) | ApiError::DatabaseError(_) | ApiError::InternalError(_) => {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };

        let body = ApiResponse::<()>::error(error_message);
        (status, axum::Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<axum::Json<ApiResponse<T>>, ApiError>;