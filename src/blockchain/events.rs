use crate::blockchain::ethereum::BlockchainService;
use crate::models::smart_contract::ContractEvent;
use anyhow::{Result};
use ethers::types::{Filter, Log, BlockNumber, H160, H256, U64};
use ethers::providers::{Middleware, StreamExt};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;

// Event listener for blockchain events
pub struct EventListener {
    blockchain: Arc<BlockchainService>,
    event_sender: mpsc::Sender<ContractEvent>,
}

impl EventListener {
    pub fn new(blockchain: Arc<BlockchainService>, sender: mpsc::Sender<ContractEvent>) -> Self {
        Self {
            blockchain,
            event_sender: sender,
        }
    }

    // Start the event listener in a separate task
    pub async fn start(&self) -> Result<task::JoinHandle<()>> {
        let blockchain = self.blockchain.clone();
        let sender = self.event_sender.clone();

        // Spawn a task to listen for events
        let handle = task::spawn(async move {
            if let Err(e) = Self::listen_events(blockchain, sender).await {
                eprintln!("Event listener error: {}", e);
            }
        });

        Ok(handle)
    }

    // Listen for blockchain events
    async fn listen_events(
        blockchain: Arc<BlockchainService>,
        sender: mpsc::Sender<ContractEvent>,
    ) -> Result<()> {
        // Get provider from blockchain service
        let provider = blockchain.get_provider();

        // Parse contract addresses
        let mut addresses = Vec::new();
        
        // Add identity contract address if available
        if let Ok(addr_str) = std::env::var("IDENTITY_CONTRACT_ADDRESS") {
            if let Ok(addr) = addr_str.parse::<H160>() {
                addresses.push(addr);
            }
        }

        if let Ok(addr_str) = std::env::var("CREDENTIAL_CONTRACT_ADDRESS") {
            if let Ok(addr) = addr_str.parse::<H160>() {
                addresses.push(addr);
            }
        }

        if let Ok(addr_str) = std::env::var("ACCESS_CONTROL_CONTRACT_ADDRESS") {
            if let Ok(addr) = addr_str.parse::<H160>() {
                addresses.push(addr);
            }
        }

        let filter = Filter::new()
            .from_block(BlockNumber::Latest)
            .address(addresses);

        // Create a stream of logs
        let mut stream = provider.watch(&filter).await?;

        // Listen for new logs
        while let Some(log) = stream.next().await {
            // Process each log
            if let Some(event) = process_log(log).await? {
                if sender.send(event).await.is_err() {
                    eprintln!("Failed to send event, channel might be closed");
                    break;
                }
            }
        }

        Ok(())
    }
}

// Process a log entry from the blockchain
async fn process_log(log: Log) -> Result<Option<ContractEvent>> {
    // Extract topics
    let topics = log.topics;
    if topics.is_empty() {
        return Ok(None);
    }
    
    let event_sig = topics[0];

    // Define event signatures (these should match your contract's event signatures)
    // In a real implementation, you would use the ABI to decode events properly
    let did_created_sig = H256::from_slice(&keccak256(b"DIDCreated(string,address,uint256)"));
    let credential_issued_sig = H256::from_slice(&keccak256(b"CredentialIssued(bytes32,address,address,uint256)"));
    let credential_revoked_sig = H256::from_slice(&keccak256(b"CredentialRevoked(bytes32,uint256)"));
    let access_policy_created_sig = H256::from_slice(&keccak256(b"AccessPolicyCreated(bytes32,bytes32,uint256)"));
    let access_policy_revoked_sig = H256::from_slice(&keccak256(b"AccessPolicyRevoked(bytes32,uint256)"));
    let consent_given_sig = H256::from_slice(&keccak256(b"ConsentGiven(bytes32,address,address,uint256)"));
    let consent_revoked_sig = H256::from_slice(&keccak256(b"ConsentRevoked(bytes32,uint256)"));

    // Match events based on signature
    let event = match event_sig {
        sig if sig == did_created_sig => {
            // Extract DID from log data (this is a simplified example)
            let did = format!("did:eth:{:x}", log.address);
            ContractEvent::DIDCreated {
                did,
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == credential_issued_sig => {
            ContractEvent::CredentialIssued {
                credential_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                issuer: format!("{:x}", topics.get(2).unwrap_or(&H256::zero())),
                subject: format!("{:x}", topics.get(3).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == credential_revoked_sig => {
            ContractEvent::CredentialRevoked {
                credential_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == access_policy_created_sig => {
            ContractEvent::AccessPolicyCreated {
                policy_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                resource_id: format!("{:x}", topics.get(2).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == access_policy_revoked_sig => {
            ContractEvent::AccessPolicyRevoked {
                policy_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == consent_given_sig => {
            ContractEvent::ConsentGiven {
                consent_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                user: format!("{:x}", topics.get(2).unwrap_or(&H256::zero())),
                controller: format!("{:x}", topics.get(3).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        sig if sig == consent_revoked_sig => {
            ContractEvent::ConsentRevoked {
                consent_id: format!("{:x}", topics.get(1).unwrap_or(&H256::zero())),
                block_number: log.block_number.unwrap_or(U64::zero()).as_u64(),
            }
        }

        // Unknown event
        _ => {
            return Ok(None);
        }
    };

    Ok(Some(event))
}

pub async fn create_event_listener(
    blockchain: Arc<BlockchainService>,
) -> Result<(mpsc::Receiver<ContractEvent>, task::JoinHandle<()>)> {
    let (sender, receiver) = mpsc::channel(100);
    
    let listener = EventListener::new(blockchain, sender);
    let handle = listener.start().await?;

    Ok((receiver, handle))
}

// Helper function to compute keccak256 hash
fn keccak256(input: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}