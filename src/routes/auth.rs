use axum::{Router, routing::get};
use mongodb::Database;

pub fn auth_routes(_db: Database) -> Router {
    Router::new().route("/auth/ping", get(ping))
}

async fn ping() -> &'static str {
    "Auth pong"
}
