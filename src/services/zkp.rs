use core::fmt;
use std::error::Error;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{OsRng};
use serde::{Deserialize, Serialize};

/// Error types for ZKP operations
#[derive(Debug)]
pub enum ZkpError {
    ProofGenerationError(String),
    ProofVerificationError(String),
    SerializationError(String),
    InvalidInputError(String),
}

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkpError::ProofGenerationError(msg) => write!(f, "Proof generation error: {}", msg),
            ZkpError::ProofVerificationError(msg) => write!(f, "Proof verification error: {}", msg),
            ZkpError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ZkpError::InvalidInputError(msg) => write!(f, "Invalid input error: {}", msg),
        }
    }
}

impl Error for ZkpError {}

/// Represents a serializable range proof
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableRangeProof {
    proof_bytes: Vec<u8>,
    commitment_bytes: Vec<u8>,
}

/// ZKP Service handles zero-knowledge proof operations
pub struct ZkpService {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

impl Default for ZkpService {
    fn default() -> Self {
        ZkpService::new(64, 128)
    }
}

impl ZkpService {
    pub fn new(range_bit_size: usize, party_capacity: usize) -> Self {
        ZkpService {
            bp_gens: BulletproofGens::new(range_bit_size, party_capacity),
            pc_gens: PedersenGens::default(),
        }
    }

    pub fn generate_range_proof(
        &self,
        value: u64,
        bit_size: usize,
        blinding: Option<Scalar>,
    ) -> Result<SerializableRangeProof, ZkpError> {
        if bit_size > 64 {
            return Err(ZkpError::InvalidInputError(
                "Bit size must be less than or equal to 64".to_string(),
            ));
        }
        let blinding_factor = blinding.unwrap_or_else(|| Scalar::random(&mut OsRng));

        let mut transcript = Transcript::new(b"ssi_range_proof");

        let (proof, committed_value) = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            value,
            &blinding_factor,
            bit_size,
        )
            .map_err(|_| ZkpError::ProofGenerationError("Failed to generate range proof".to_string()))?;

        Ok(SerializableRangeProof {
            proof_bytes: proof.to_bytes(),
            commitment_bytes: committed_value.to_bytes().to_vec(),
        })
    }

    pub fn verify_range_proof(
        &self,
        proof: &SerializableRangeProof,
        bit_size: usize,
    ) -> Result<bool, ZkpError> {
        let mut transcript = Transcript::new(b"ssi_range_proof");

        let range_proof = RangeProof::from_bytes(&proof.proof_bytes).map_err(|_| {
            ZkpError::SerializationError("Failed to deserialize range proof".to_string())
        })?;

        let commitment = CompressedRistretto::from_slice(&proof.commitment_bytes)
            .map_err(|_| ZkpError::SerializationError("Invalid commitment bytes".to_string()))?;

        match range_proof.verify_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            &commitment,
            bit_size,
        ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn generate_credential_proof(
        &self,
        credential_values: &[u64],
        blinding_factors: Option<Vec<Scalar>>,
    ) -> Result<Vec<SerializableRangeProof>, ZkpError> {
        if credential_values.is_empty() {
            return Err(ZkpError::InvalidInputError(
                "Credential values cannot be empty".to_string(),
            ));
        }

        let mut rng = OsRng;
        let blindings = match blinding_factors {
            Some(factors) => {
                if factors.len() != credential_values.len() {
                    return Err(ZkpError::InvalidInputError(
                        "Number of blinding factors must match number of credential values".to_string(),
                    ));
                }
                factors
            }
            None => credential_values
                .iter()
                .map(|_| Scalar::random(&mut rng))
                .collect(),
        };

        let mut proofs = Vec::with_capacity(credential_values.len());

        for (i, &value) in credential_values.iter().enumerate() {
            match self.generate_range_proof(value, 32, Some(blindings[i])) {
                Ok(proof) => proofs.push(proof),
                Err(e) => return Err(e),
            }
        }

        Ok(proofs)
    }

    pub fn verify_credential_proof(
        &self,
        proofs: &[SerializableRangeProof],
    ) -> Result<bool, ZkpError> {
        if proofs.is_empty() {
            return Err(ZkpError::InvalidInputError("Proofs cannot be empty".to_string()));
        }

        for proof in proofs {
            if !self.verify_range_proof(proof, 32)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn generate_selective_disclosure(
        &self,
        credential_values: &[u64],
        reveal_indices: &[usize],
        blinding_factors: Option<Vec<Scalar>>,
    ) -> Result<(Vec<SerializableRangeProof>, Vec<u64>), ZkpError> {
        if credential_values.is_empty() {
            return Err(ZkpError::InvalidInputError(
                "Credential values cannot be empty".to_string(),
            ));
        }

        for &idx in reveal_indices {
            if idx >= credential_values.len() {
                return Err(ZkpError::InvalidInputError(format!(
                    "Invalid reveal index: {}",
                    idx
                )));
            }
        }

        let proofs = self.generate_credential_proof(credential_values, blinding_factors)?;

        let revealed_values: Vec<u64> = reveal_indices
            .iter()
            .map(|&idx| credential_values[idx])
            .collect();

        Ok((proofs, revealed_values))
    }

    pub fn verify_selective_disclosure(
        &self,
        proofs: &[SerializableRangeProof],
        revealed_values: &[u64],
        reveal_indices: &[usize],
    ) -> Result<bool, ZkpError> {
        if !self.verify_credential_proof(proofs)? {
            return Ok(false);
        }

        if revealed_values.len() != reveal_indices.len() {
            return Err(ZkpError::InvalidInputError(
                "Number of revealed values must match number of reveal indices".to_string(),
            ));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof() {
        let zkp_service = ZkpService::default();
        let proof = zkp_service.generate_range_proof(42, 32, None).unwrap();
        let verification = zkp_service.verify_range_proof(&proof, 32).unwrap();
        assert!(verification);
    }

    #[test]
    fn test_invalid_range_proof() {
        let zkp_service = ZkpService::default();
        let mut proof = zkp_service.generate_range_proof(42, 32, None).unwrap();
        proof.proof_bytes[0] = proof.proof_bytes[0].wrapping_add(1);
        let verification = zkp_service.verify_range_proof(&proof, 32).unwrap();
        assert!(!verification);
    }

    #[test]
    fn test_credential_proof() {
        let zkp_service = ZkpService::default();
        let credential_values = vec![25, 42, 1337];
        let proofs = zkp_service.generate_credential_proof(&credential_values, None).unwrap();
        let verification = zkp_service.verify_credential_proof(&proofs).unwrap();
        assert!(verification);
    }

    #[test]
    fn test_selective_disclosure() {
        let zkp_service = ZkpService::default();
        let credential_values = vec![25, 42, 1337, 8000];
        let reveal_indices = vec![1, 3];
        let (proofs, revealed) = zkp_service
            .generate_selective_disclosure(&credential_values, &reveal_indices, None)
            .unwrap();
        assert_eq!(revealed, vec![42, 8000]);
        let verification = zkp_service
            .verify_selective_disclosure(&proofs, &revealed, &reveal_indices)
            .unwrap();
        assert!(verification);
    }
}
