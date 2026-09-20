//! pqbit-core — post-quantum Bitcoin core primitives (Hartwell Labs)
//!
//! Quantum-resistant transaction model built on NIST-standardized ML-DSA-44
//! (FIPS 204) and SLH-DSA-SHA2-128s (FIPS 205), following the direction of
//! Bitcoin BIP-360 (P2MR, merged into the BIPs repo February 2026).
//! Lightweight UTXO model, fair-launch design.

use bitcoinpqc::{Algorithm, KeyPair, PublicKey, SecretKey, Signature};
use std::fmt;

/// Signature algorithms supported at genesis. Both are NIST FIPS standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    /// ML-DSA-44 (FIPS 204) — compact signatures, fast verification.
    MlDsa44,
    /// SLH-DSA-SHA2-128s (FIPS 205) — larger signatures, conservative hash-based security.
    SlhDsaSha2_128s,
}

impl SigAlgo {
    pub fn algorithm(self) -> Algorithm {
        match self {
            SigAlgo::MlDsa44 => Algorithm::ML_DSA_44,
            SigAlgo::SlhDsaSha2_128s => Algorithm::SLH_DSA_SHA2_128S,
        }
    }
}

/// A quantum-resistant UTXO.
#[derive(Debug, Clone)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// Serialized post-quantum verifying key committing this output.
    pub pubkey: Vec<u8>,
}

/// Input spending a previous quantum-resistant output.
#[derive(Debug, Clone)]
pub struct TxIn {
    /// Reference to the UTXO being spent.
    pub prev_txid: [u8; 32],
    /// Index of the output in the previous transaction.
    pub vout: u32,
    /// Serialized ML-DSA or SLH-DSA signature over the sighash.
    pub signature: Vec<u8>,
}

/// A quantum-resistant transaction.
#[derive(Debug, Clone, Default)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    /// Canonical pre-signature serialization (sighash basis).
    pub fn sighash_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.inputs.len() * 44 + self.outputs.len() * 40 + 4);
        buf.extend_from_slice(&self.version.to_le_bytes());
        for txin in &self.inputs {
            buf.extend_from_slice(&txin.prev_txid);
            buf.extend_from_slice(&txin.vout.to_le_bytes());
        }
        for txout in &self.outputs {
            buf.extend_from_slice(&txout.value.to_le_bytes());
            buf.extend_from_slice(&(txout.pubkey.len() as u32).to_le_bytes());
            buf.extend_from_slice(&txout.pubkey);
        }
        buf.extend_from_slice(&self.locktime.to_le_bytes());
        buf
    }

    /// Sighash (double SHA-256 of the preimage).
    pub fn sighash(&self) -> [u8; 32] {
        use bitcoin::hashes::{sha256d::Hash, Hash as _};
        let h = Hash::hash(&self.sighash_preimage());
        *h.as_byte_array()
    }
}

/// Errors surfaced by the PQ layer.
#[derive(Debug, PartialEq)]
pub enum PqBitError {
    SignatureRejected,
    UnsupportedAlgorithm,
    MalformedTransaction,
}

impl fmt::Display for PqBitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqBitError::SignatureRejected => write!(f, "PQ signature rejected"),
            PqBitError::UnsupportedAlgorithm => write!(f, "unsupported signature algorithm"),
            PqBitError::MalformedTransaction => write!(f, "malformed transaction"),
        }
    }
}

impl std::error::Error for PqBitError {}

/// Verify one PQ signature against a message and verifying key.
pub fn verify_pq(
    algo: SigAlgo,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, PqBitError> {
    let pk =
        PublicKey::try_from_slice(algo.algorithm(), pubkey).map_err(|_| PqBitError::MalformedTransaction)?;
    let sig =
        Signature::try_from_slice(algo.algorithm(), signature).map_err(|_| PqBitError::MalformedTransaction)?;
    match bitcoinpqc::verify(&pk, message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Sign a message with a PQ secret key; returns the serialized signature.
pub fn sign_pq(algo: SigAlgo, secret: &[u8], message: &[u8]) -> Result<Vec<u8>, PqBitError> {
    let sk =
        SecretKey::try_from_slice(algo.algorithm(), secret).map_err(|_| PqBitError::MalformedTransaction)?;
    bitcoinpqc::sign(&sk, message)
        .map(|s| s.bytes)
        .map_err(|_| PqBitError::SignatureRejected)
}

/// Generate a quantum-resistant keypair (wallet primitive).
pub fn generate_pq_keypair(algo: SigAlgo) -> Result<KeyPair, PqBitError> {
    use rand::RngCore;
    let mut entropy = [0u8; 128];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    bitcoinpqc::generate_keypair(algo.algorithm(), &entropy)
        .map_err(|_| PqBitError::UnsupportedAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_keygen_sign_verify_roundtrip() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let msg = b"pqbit genesis";
        let sig = sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, msg).expect("sign");
        let ok = verify_pq(SigAlgo::MlDsa44, &kp.public_key.bytes, msg, &sig).expect("verify");
        assert!(ok, "ML-DSA roundtrip must verify");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let sig = sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, b"real message").expect("sign");
        let ok = verify_pq(
            SigAlgo::MlDsa44,
            &kp.public_key.bytes,
            b"tampered message",
            &sig,
        )
        .expect("verify runs");
        assert!(!ok, "tampered message must not verify");
    }

    #[test]
    fn public_key_size_matches_crate_spec() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        assert_eq!(
            kp.public_key.bytes.len(),
            bitcoinpqc::public_key_size(Algorithm::ML_DSA_44)
        );
    }

    #[test]
    fn sighash_is_deterministic() {
        let mut tx = Transaction::default();
        tx.inputs.push(TxIn {
            prev_txid: [7u8; 32],
            vout: 0,
            signature: vec![],
        });
        tx.outputs.push(TxOut {
            value: 100_000_000,
            pubkey: vec![1u8; 1312],
        });
        assert_eq!(tx.sighash(), tx.sighash(), "sighash must be deterministic");
    }
}
