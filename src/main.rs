mod api;
mod blockchain;
mod config;
pub mod db;
mod models;
mod services;
mod utils;
mod routes;
mod constant;

use crate::api::routes::create_routes;

use crate::db::mongodb::init_database as connect_database;
use axum::Server;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    // Load configuration
    let config = config::settings::load_config()?;
    info!("Configuration loaded successfully");

    // Connect to MongoDB
    let db_client = connect_database(&config.mongodb_uri).await?;
    info!("Connected to MongoDB");

    // Initialize blockchain connection if enabled
    let blockchain_service = if config.blockchain_enabled {
        Some(blockchain::init_blockchain_service(&config.blockchain_uri).await?)
    } else {
        None
    };

    // Create app state
    let state = Arc::new(api::AppState {
        config: config.clone(),
        db: db_client,
        blockchain: blockchain_service,
    });

    // Create application with routes
    let app = create_routes(state);

    // Run the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Server listening on {}", addr);
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}