use axum::{
    body::Body,
    http::{Request},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use tracing::{error, info};
use uuid::Uuid;

// Request logging middleware
pub async fn log_request(request: Request<Body>, next: Next<Body>) -> Response {
    let start_time = Utc::now();
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().clone();

    // Add request ID to extensions for potential use in handlers
    let mut request = request;
    request.extensions_mut().insert(request_id.clone());

    // Log the incoming request
    info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        "Incoming request"
    );

    // Process the request
    let response = next.run(request).await;

    // Calculate the time taken to process the request
    let duration = Utc::now() - start_time;
    let status = response.status();

    // Log the response
    if status.is_success() {
        info!(
            request_id = %request_id,
            status = %status.as_u16(),
            duration = %duration.num_milliseconds(),
            "Request completed successfully"
        );
    } else if status.is_client_error() || status.is_server_error() {
        error!(
            request_id = %request_id,
            status = %status.as_u16(),
            duration = %duration.num_milliseconds(),
            "Request failed"
        );
    } else {
        info!(
            request_id = %request_id,
            status = %status.as_u16(),
            duration = %duration.num_milliseconds(),
            "Request completed with non-standard status"
        );
    }

    response
}