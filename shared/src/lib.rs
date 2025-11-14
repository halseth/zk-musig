use serde::{Deserialize, Serialize};

/// Journal output from the guest program
///
/// All data is wrapped in this single structure for atomic commitment.
/// This ensures that all values are committed to together in the zero-knowledge proof,
/// preventing selective disclosure or manipulation of individual fields.
///
/// All cryptographic values are hex-encoded strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalOutput {
    /// The signer's public key (hex-encoded, 33 bytes compressed format)
    pub pubkey: String,

    /// The signer's public nonce (hex-encoded, 66 bytes)
    pub pubnonce: String,

    /// Parity bit for the challenge (0 or 1)
    /// Used to determine sign adjustments in the signature
    pub challenge_parity: u8,

    /// Parity bit for the signing nonce (0 or 1)
    /// Indicates whether the signing nonce has even Y coordinate
    pub nonce_parity: u8,

    /// Blinded nonce coefficient b' = b + gamma (hex-encoded scalar, 32 bytes)
    /// This is the nonce coefficient with the blinding factor applied
    pub b: String,

    /// Blinded challenge e' (hex-encoded scalar, 32 bytes)
    /// This is the challenge with key coefficient and blinding applied
    pub e: String,

    /// Message commitment SHA256(message || message_salt) (hex-encoded, 32 bytes)
    /// Used to bind the proof to a specific transaction without revealing the message
    pub message_commitment: String,
}
