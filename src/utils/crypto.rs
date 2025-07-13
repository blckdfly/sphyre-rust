use crate::constant::{PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LEN, PASSWORD_SALT_LEN};
use rand::{rngs::OsRng, RngCore};
use ring::{digest, pbkdf2};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
use std::num::NonZeroU32;
use hex;
use crate::utils::errors::WalletError;

pub type Result<T> = std::result::Result<T, WalletError>;

pub fn generate_private_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng::new().fill_bytes(&mut key);
    Ok(key)
}

pub fn public_key_to_eth_address(public_key: &PublicKey) -> String {
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_bytes = &public_key_bytes[1..];

    // Keccak-256 hash
    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();

    format!("0x{}", hex::encode(&hash[12..32]))
}

pub fn derive_public_key(private_key: &[u8; 32]) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|_| WalletError::InvalidKey("Failed to create secret key".to_string()))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key)
}

/// Generate a DID from an Ethereum address
pub fn generate_did(address: &str) -> String {
    format!("did:ethr:{}", address.trim_start_matches("0x"))
}

/// Hash password with salt using PBKDF2
pub fn hash_password(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0u8; PASSWORD_HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_HASH_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut output,
    );
    Ok(output)
}

/// Verify password against stored hash
pub fn verify_password(password: &str, salt: &[u8], hash: &[u8]) -> bool {
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_HASH_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        hash,
    ).is_ok()
}

/// Generate random salt
pub fn generate_salt() -> [u8; PASSWORD_SALT_LEN] {
    let mut salt = [0u8; PASSWORD_SALT_LEN];
    OsRng::new().fill_bytes(&mut salt);
    salt
}

pub fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    // Generate a random salt and nonce
    let salt = generate_salt();
    let mut nonce_bytes = [0u8; 12];
    OsRng::new().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let key = hash_password(password, &salt)?;
    let key = key.as_slice().try_into()
        .map_err(|_| WalletError::EncryptionError("Invalid key length".to_string()))?;

    // Encrypt the data
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

    let payload = Payload {
        msg: data,
        aad: b"".as_ref(),
    };

    let ciphertext = cipher.encrypt(nonce, payload)
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

    // Format as salt + nonce + ciphertext
    let mut result = Vec::with_capacity(salt.len() + nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data encrypted with encrypt_data
pub fn decrypt_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    // Split the encrypted data into salt, nonce, and ciphertext
    if encrypted_data.len() < PASSWORD_SALT_LEN + 12 {
        return Err(WalletError::DecryptionError("Invalid encrypted data".to_string()));
    }

    let salt = &encrypted_data[0..PASSWORD_SALT_LEN];
    let nonce_bytes = &encrypted_data[PASSWORD_SALT_LEN..PASSWORD_SALT_LEN + 12];
    let ciphertext = &encrypted_data[PASSWORD_SALT_LEN + 12..];

    let nonce = Nonce::from_slice(nonce_bytes);

    let key = hash_password(password, salt)?;
    let key = key.as_slice().try_into()
        .map_err(|_| WalletError::DecryptionError("Invalid key length".to_string()))?;

    // Decrypt the data
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WalletError::DecryptionError(e.to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: b"".as_ref(),
    };

    let plaintext = cipher.decrypt(nonce, payload)
        .map_err(|_| WalletError::DecryptionError("Decryption failed".to_string()))?;

    Ok(plaintext)
}

/// Sign data with a private key
pub fn sign_data(data: &[u8], private_key: &[u8; 32]) -> Result<Vec<u8>> {
    use secp256k1::{Message, Secp256k1};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|_| WalletError::SigningError("Invalid private key".to_string()))?;

    // Hash the data first (typically needed for signing)
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Create a message from the hash
    let message = Message::from_digest_slice(hash.as_slice())
        .map_err(|_| WalletError::SigningError("Invalid message hash".to_string()))?;

    // Sign the message
    let signature = secp.sign_ecdsa(&message, &secret_key);

    // Serialize the signature
    Ok(signature.serialize_compact().to_vec())
}

/// Verify a signature
pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
    use secp256k1::{Message, Secp256k1, ecdsa::Signature};

    let secp = Secp256k1::new();

    // Hash the data
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Create a message from the hash
    let message = Message::from_digest_slice(hash.as_slice())
        .map_err(|_| WalletError::SigningError("Invalid message hash".to_string()))?;

    // Parse the signature
    let sig = Signature::from_compact(signature)
        .map_err(|_| WalletError::SigningError("Invalid signature format".to_string()))?;

    // Verify
    match secp.verify_ecdsa(&message, &sig, public_key) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Calculate SHA-256 hash of data
pub fn generate_signature(data: &[u8]) -> Vec<u8> {
    let hash = digest::digest(&digest::SHA256, data);
    hash.as_ref().to_vec()
}

/// Calculate SHA-256 hash of data
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let hash = digest::digest(&digest::SHA256, data);
    hash.as_ref().to_vec()
}
