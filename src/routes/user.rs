use axum::{Router, routing::get};
use mongodb::Database;

pub fn user_routes(_db: Database) -> Router {
    Router::new().route("/user/ping", get(ping))
}

async fn ping() -> &'static str {
    "User pong"
}
