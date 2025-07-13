mod ethereum;
pub(crate) mod contracts;
mod events;

pub use ethereum::{BlockchainService, init_blockchain_service};