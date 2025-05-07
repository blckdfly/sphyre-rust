use mongodb::{Client, Database};
use std::env;

pub async fn init_db() -> mongodb::error::Result<Database> {
    let uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let client = Client::with_uri_str(uri).await?;
    Ok(client.database("sphyre"))
}
