//! Debug signing key material (RSA-2048).

use super::{KeystoreMaterial, SignError, SignResult};

/// Embedded Android Debug RSA key (pure-Rust, no `rcgen`/`ring`, no `$HOME/.cache`).
const EMBEDDED_DEBUG_KEY: &[u8] = include_bytes!("embedded_debug.key");

/// Return the embedded Android debug keystore without `rcgen`/`ring` or filesystem cache access.
pub fn generate_debug_keystore() -> SignResult<KeystoreMaterial> {
    deserialize_keystore(EMBEDDED_DEBUG_KEY)
}

/// Return the embedded Android debug keystore without touching the filesystem.
pub fn generate_debug_keystore_ephemeral() -> SignResult<KeystoreMaterial> {
    deserialize_keystore(EMBEDDED_DEBUG_KEY)
}

/// Serialize keystore for external caches.
pub fn serialize_debug_keystore(mat: &KeystoreMaterial) -> Vec<u8> {
    serialize_keystore(mat)
}

/// Deserialize keystore from [`serialize_debug_keystore`].
pub fn deserialize_debug_keystore(bytes: &[u8]) -> SignResult<KeystoreMaterial> {
    deserialize_keystore(bytes)
}

fn serialize_keystore(mat: &KeystoreMaterial) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(mat.private_key_der.len() as u32).to_le_bytes());
    out.extend_from_slice(&mat.private_key_der);
    out.extend_from_slice(&(mat.certificate_der.len() as u32).to_le_bytes());
    out.extend_from_slice(&mat.certificate_der);
    out.push(u8::from(mat.is_ec));
    out
}

fn deserialize_keystore(bytes: &[u8]) -> SignResult<KeystoreMaterial> {
    if bytes.len() < 9 {
        return Err(SignError::Signing("cached keystore too short".into()));
    }
    let mut o = 0usize;
    let pk_len = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + pk_len + 4 > bytes.len() {
        return Err(SignError::Signing("cached keystore truncated".into()));
    }
    let private_key_der = bytes[o..o + pk_len].to_vec();
    o += pk_len;
    let cert_len = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + cert_len + 1 > bytes.len() {
        return Err(SignError::Signing("cached keystore cert truncated".into()));
    }
    let certificate_der = bytes[o..o + cert_len].to_vec();
    o += cert_len;
    let is_ec = bytes[o] != 0;
    Ok(KeystoreMaterial {
        private_key_der,
        certificate_der,
        is_ec,
    })
}
