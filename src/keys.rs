use signature::Signer;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, Signature};

use crate::error::Result;

/// Compute the SHA-256 fingerprint string for public key data.
///
/// Returns a string like `"SHA256:abcdef..."` matching the format
/// used by `ssh-keygen -l` and stored in our keyring attributes.
pub fn fingerprint(key_data: &KeyData) -> String {
    key_data.fingerprint(HashAlg::Sha256).to_string()
}

/// Parse an OpenSSH private key from raw bytes (PEM format).
pub fn parse_private_key(openssh_bytes: &[u8]) -> Result<PrivateKey> {
    Ok(PrivateKey::from_openssh(openssh_bytes)?)
}

/// Extract public key data from a private key for use in agent `Identity` responses.
pub fn public_key_data(privkey: &PrivateKey) -> KeyData {
    privkey.public_key().key_data().clone()
}

/// Get the human-readable algorithm name for keyring attribute storage.
pub fn algorithm_name(key_data: &KeyData) -> &'static str {
    match key_data {
        KeyData::Ed25519(_) => "ed25519",
        KeyData::Ecdsa(k) => match k.curve() {
            ssh_key::EcdsaCurve::NistP256 => "ecdsa-p256",
            ssh_key::EcdsaCurve::NistP384 => "ecdsa-p384",
            ssh_key::EcdsaCurve::NistP521 => "ecdsa-p521",
        },
        KeyData::Rsa(_) => "rsa",
        _ => "unknown",
    }
}

/// Sign data with a private key.
///
/// Uses `ssh_key`'s `Signer<Signature>` trait, which handles ed25519 and ECDSA
/// correctly. For RSA, this always produces SHA-512 signatures regardless of
/// `flags` — proper flag-based RSA hash selection is a Milestone 2 item.
pub fn sign(privkey: &PrivateKey, data: &[u8]) -> Result<Signature> {
    Ok(privkey.try_sign(data)?)
}
