use anyhow::{Context, Result};
use ethers::prelude::{abigen, SignerMiddleware, Provider};
use ethers::types::{Address, H256, U256};
use ethers::providers::Http;
use ethers::signers::LocalWallet;
use std::str::FromStr;
use std::sync::Arc;

// Add these imports for the missing types
use axum::{extract::State, Json};
use uuid::Uuid;
use chrono::Utc;

use crate::api::{ApiResult, ApiResponse, ApiError};
use crate::models::access_log::{AccessPolicyInput, AccessPolicy};
use crate::models::user::User;
use crate::api::AppState;
use crate::db::mongodb::MongoDBClient;

// Generate type-safe contract bindings
abigen!(
    AccessControlContract,
    r#"[
        function hasRole(bytes32 role, address account) external view returns (bool)
        function grantRole(bytes32 role, address account) external
        function revokeRole(bytes32 role, address account) external
        function getRoleMember(bytes32 role, uint256 index) external view returns (address)
        function getRoleMemberCount(bytes32 role) external view returns (uint256)
        event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
        event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
    ]"#,
);

// Re-export the generated contract type
pub use self::AccessControlContract;


pub struct AccessControlContractClient {
    contract: AccessControlContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl AccessControlContractClient {
    pub fn new(
        client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
        contract_address: &str,
    ) -> Result<Self> {
        let address = Address::from_str(contract_address)
            .context("Failed to parse contract address")?;

        let contract = AccessControlContract::new(address, client);

        Ok(Self { contract })
    }

    // Common roles as bytes32 constants
    pub fn admin_role() -> [u8; 32] {
        // keccak256("ADMIN_ROLE")
        [
            0xdf, 0x8b, 0x4c, 0x52, 0x0f, 0xb9, 0x32, 0x78,
            0xea, 0x3d, 0x77, 0xbb, 0x9c, 0xd5, 0x70, 0x98,
            0xc5, 0x6b, 0x85, 0x28, 0x5e, 0x26, 0xc0, 0x26,
            0xbd, 0xf7, 0x1f, 0xfa, 0xc9, 0x08, 0xeb, 0xed
        ]
    }

    pub fn issuer_role() -> [u8; 32] {
        // keccak256("ISSUER_ROLE")
        [
            0x95, 0x8e, 0x56, 0xb2, 0xcc, 0x1a, 0x25, 0x61,
            0xe7, 0x9a, 0x1b, 0x5d, 0xc0, 0xe2, 0x2b, 0x85,
            0xf2, 0xed, 0x4e, 0x41, 0xb7, 0xef, 0x9d, 0x22,
            0xf5, 0x3f, 0x1b, 0x0d, 0x1d, 0xed, 0x71, 0x66
        ]
    }

    pub fn verifier_role() -> [u8; 32] {
        // keccak256("VERIFIER_ROLE")
        [
            0x76, 0xe1, 0x0a, 0x1e, 0xed, 0xed, 0x62, 0x64,
            0xa7, 0x3a, 0x2b, 0x62, 0xf5, 0x7e, 0x29, 0x15,
            0x36, 0x15, 0xce, 0x1c, 0x47, 0x33, 0xbe, 0xbb,
            0xb3, 0xd5, 0xf5, 0x3e, 0x85, 0xd6, 0x10, 0x9d
        ]
    }

    // Check if an account has a specific role
    pub async fn has_role(&self, role: [u8; 32], account: Address) -> Result<bool> {
        let has_role = self.contract
            .has_role(role, account)
            .call()
            .await?;

        Ok(has_role)
    }

    // Grant a role to an account
    pub async fn grant_role(&self, role: [u8; 32], account: Address) -> Result<H256> {
        let grant_role_call = self.contract.grant_role(role, account);
        let pending_tx = grant_role_call.send().await?;
        let receipt = pending_tx.await?.context("Transaction failed")?;
        Ok(receipt.transaction_hash)
    }

    // Revoke a role from an account
    pub async fn revoke_role(&self, role: [u8; 32], account: Address) -> Result<H256> {
        let revoke_role_call = self.contract.revoke_role(role, account);
        let pending_tx = revoke_role_call.send().await?;
        let receipt = pending_tx.await?.context("Transaction failed")?;
        Ok(receipt.transaction_hash)
    }

    // Get role member by index
    pub async fn get_role_member(&self, role: [u8; 32], index: U256) -> Result<Address> {
        let member = self.contract
            .get_role_member(role, index)
            .call()
            .await?;

        Ok(member)
    }

    pub async fn get_role_member_count(&self, role: [u8; 32]) -> Result<U256> {
        let count = self.contract
            .get_role_member_count(role)
            .call()
            .await?;

        Ok(count)
    }

    // Get all members with a role
    pub async fn get_all_role_members(&self, role: [u8; 32]) -> Result<Vec<Address>> {
        let count = self.get_role_member_count(role).await?;
        let mut members = Vec::new();

        for i in 0..count.as_u64() {
            let member = self.get_role_member(role, U256::from(i)).await?;
            members.push(member);
        }

        Ok(members)
    }
}

// HTTP handler for creating access policy
pub async fn create_access_policy_handler(
    State(state): State<Arc<AppState>>,
    user: User, // Injected by auth middleware
    Json(policy_input): Json<AccessPolicyInput>,
) -> ApiResult<AccessPolicy> {
    let blockchain = state.blockchain.as_ref()
        .ok_or_else(|| ApiError::InternalError("Blockchain service not available".to_string()))?;

    let policy = create_access_policy_service(&state.db, blockchain, &user.id, policy_input).await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(ApiResponse::success(policy, "Access policy created successfully")))
}

// Service function for creating access policy
pub async fn create_access_policy_service(
    db: &MongoDBClient,
    _blockchain: &impl std::fmt::Debug,
    user_id: &str,
    input: AccessPolicyInput,
) -> Result<AccessPolicy> {
    let new_policy = AccessPolicy {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        resource_id: input.resource_id,
        resource_type: input.resource_type,
        action: input.action,
        created_at: Utc::now(),
    };

    let collection = db.client.database("ssi_db").collection("access_policies");
    collection
        .insert_one(new_policy.clone(), None)
        .await?;

    Ok(new_policy)
}
