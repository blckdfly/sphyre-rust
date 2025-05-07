use crate::blockchain::ethereum::BlockchainService;
use crate::models::smart_contract::ContractEvent;
use anyhow::{Context, Result};
use ethers::prelude::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use web3::types::{BlockNumber, FilterBuilder, Log};

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
        // Get web3 instance
        let web3 = &blockchain.web3;

        // Create filter for contract events
        // This is a simplified example that would need adjustment for real events
        let filter = FilterBuilder::default()
            .from_block(BlockNumber::Latest)
            .address(vec![
                // Add contract addresses to listen for
                blockchain.identity_contract_address.unwrap_or_default(),
                blockchain.credential_contract_address.unwrap_or_default(),
                blockchain.access_control_contract_address.unwrap_or_default(),
            ])
            .build();

        // Create filter
        let filter_id = web3.eth().filter(filter).await?;

        // Listen for new logs
        loop {
            // Get new logs since last poll
            let logs = web3.eth().get_filter_changes(filter_id.clone()).await?;

            for log in logs {
                // Process each log
                if let Some(event) = process_log(log).await? {
                    // Send event to event channel
                    if sender.send(event).await.is_err() {
                        eprintln!("Failed to send event, channel might be closed");
                        break;
                    }
                }
            }

            // Wait before next poll
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

// Process a log entry from the blockchain
async fn process_log(log: Log) -> Result<Option<ContractEvent>> {
    // This would need to be implemented based on your contract's event structure
    // Here we're providing a simplified implementation

    // Extract topics
    let topics = log.topics;
    if topics.is_empty() {
        return Ok(None);
    }

    // First topic is the event signature
    let event_sig = topics[0];

    // Simplified event matching based on signature
    // In real implementation, you would decode the log data based on ABI
    let event = match event_sig.as_bytes() {
        // Match DID created event
        b if b.starts_with(b"DIDCreated") => {
            let did = String::from_utf8_lossy(&log.data.0).to_string();
            ContractEvent::DIDCreated {
                did,
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match Credential issued event
        b if b.starts_with(b"CredentialIssued") => {
            ContractEvent::CredentialIssued {
                credential_id: format!("0x{:x}", topics[1]),
                issuer: format!("0x{:x}", topics[2]),
                subject: format!("0x{:x}", topics[3]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match Credential revoked event
        b if b.starts_with(b"CredentialRevoked") => {
            ContractEvent::CredentialRevoked {
                credential_id: format!("0x{:x}", topics[1]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match AccessPolicy created event
        b if b.starts_with(b"AccessPolicyCreated") => {
            ContractEvent::AccessPolicyCreated {
                policy_id: format!("0x{:x}", topics[1]),
                resource_id: format!("0x{:x}", topics[2]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match AccessPolicy revoked event
        b if b.starts_with(b"AccessPolicyRevoked") => {
            ContractEvent::AccessPolicyRevoked {
                policy_id: format!("0x{:x}", topics[1]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match Consent given event
        b if b.starts_with(b"ConsentGiven") => {
            ContractEvent::ConsentGiven {
                consent_id: format!("0x{:x}", topics[1]),
                user: format!("0x{:x}", topics[2]),
                controller: format!("0x{:x}", topics[3]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Match Consent revoked event
        b if b.starts_with(b"ConsentRevoked") => {
            ContractEvent::ConsentRevoked {
                consent_id: format!("0x{:x}", topics[1]),
                block_number: log.block_number.unwrap_or_default().as_u64()
            }
        }

        // Unknown event
        _ => {
            return Ok(None);
        }
    };

    Ok(Some(event))
}

// Create event listener
pub async fn create_event_listener(
    blockchain: Arc<BlockchainService>,
) -> Result<(mpsc::Receiver<ContractEvent>, task::JoinHandle<()>)> {
    // Create channel for events
    let (sender, receiver) = mpsc::channel(100);

    // Create and start listener
    let listener = EventListener::new(blockchain, sender);
    let handle = listener.start().await?;

    Ok((receiver, handle))
}