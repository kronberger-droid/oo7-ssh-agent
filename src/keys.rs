use signature::{SignatureEncoding, Signer};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

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

/// Sign data with a private key, respecting SSH agent protocol flags.
///
/// For ed25519 and ECDSA, flags are irrelevant — there's only one
/// signing algorithm per key type. For RSA, flags select the hash:
/// - `RSA_SHA2_512` (0x04) → rsa-sha2-512
/// - `RSA_SHA2_256` (0x02) → rsa-sha2-256
/// - neither → legacy ssh-rsa (SHA-1)
pub fn sign(privkey: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature> {
    match privkey.key_data() {
        KeypairData::Rsa(rsa_keypair) => sign_rsa(rsa_keypair, data, flags),
        _ => Ok(privkey.try_sign(data)?),
    }
}

/// RSA signing with hash algorithm selected by SSH agent flags.
fn sign_rsa(
    key: &ssh_key::private::RsaKeypair,
    data: &[u8],
    flags: u32,
) -> Result<Signature> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::RsaPrivateKey;
    use ssh_agent_lib::proto::signature;

    let private_key = RsaPrivateKey::from_components(
        rsa::BigUint::try_from(&key.public.n)?,
        rsa::BigUint::try_from(&key.public.e)?,
        rsa::BigUint::try_from(&key.private.d)?,
        vec![
            rsa::BigUint::try_from(&key.private.p)?,
            rsa::BigUint::try_from(&key.private.q)?,
        ],
    )?;

    let (algorithm, sig_bytes) = if flags & signature::RSA_SHA2_512 != 0 {
        let sig = SigningKey::<sha2::Sha512>::new(private_key).sign(data);
        ("rsa-sha2-512", sig.to_vec())
    } else if flags & signature::RSA_SHA2_256 != 0 {
        let sig = SigningKey::<sha2::Sha256>::new(private_key).sign(data);
        ("rsa-sha2-256", sig.to_vec())
    } else {
        let sig = SigningKey::<sha1::Sha1>::new_unprefixed(private_key).sign(data);
        ("ssh-rsa", sig.to_vec())
    };

    Ok(Signature::new(Algorithm::new(algorithm)?, sig_bytes)?)
}
