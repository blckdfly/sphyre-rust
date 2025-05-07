use crate::api::handlers::{
    access_control, consent, credential, identity,
};
use crate::api::middleware::{auth, logger};
use crate::api::AppState;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

pub fn create_routes(state: Arc<AppState>) -> Router {
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/identity/register", post(identity::register))
        .route("/api/v1/identity/login", post(identity::login));

    let identity_routes = Router::new()
        .route("/api/v1/identity/profile", get(identity::get_profile))
        .route("/api/v1/identity/profile", post(identity::update_profile))
        .route("/api/v1/identity/did", get(identity::get_did))
        .route("/api/v1/identity/did", post(identity::create_did))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    let credential_routes = Router::new()
        .route("/api/v1/credential", get(credential::list_credentials))
        .route("/api/v1/credential/:id", get(credential::get_credential))
        .route("/api/v1/credential", post(credential::issue_credential))
        .route("/api/v1/credential/verify", post(credential::verify_credential))
        .route(
            "/api/v1/credential/:id/revoke",
            post(credential::revoke_credential),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    let consent_routes = Router::new()
        .route("/api/v1/consent", get(consent::list_consents))
        .route("/api/v1/consent/:id", get(consent::get_consent))
        .route("/api/v1/consent", post(consent::create_consent))
        .route("/api/v1/consent/:id", post(consent::update_consent))
        .route("/api/v1/consent/:id/revoke", post(consent::revoke_consent))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    let access_control_routes = Router::new()
        .route(
            "/api/v1/access",
            get(access_control::list_access_policies),
        )
        .route(
            "/api/v1/access/:id",
            get(access_control::get_access_policy),
        )
        .route(
            "/api/v1/access",
            post(access_control::create_access_policy),
        )
        .route(
            "/api/v1/access/:id",
            post(access_control::update_access_policy),
        )
        .route(
            "/api/v1/access/:id/revoke",
            post(access_control::revoke_access_policy),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));

    // Admin routes for elevated access
    let admin_routes = Router::new()
        .route("/api/v1/admin/users", get(identity::list_users))
        .route(
            "/api/v1/admin/credentials",
            get(credential::admin_list_credentials),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authorize_admin,
        ));

    // Combine all routes
    Router::new()
        .merge(public_routes)
        .merge(identity_routes)
        .merge(credential_routes)
        .merge(consent_routes)
        .merge(access_control_routes)
        .merge(admin_routes)
        .layer(middleware::from_fn(logger::log_request))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// Health check endpoint
async fn health_check() -> &'static str {
    "SSI Backend Service - OK"
}