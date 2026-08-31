//! Package signing — bind a manifest to its `.cwasm` so they cannot be recombined
//! (RFC-0015 §"The signed package").
//!
//! The package is `{ manifest_bytes, cwasm_bytes }`. What is Ed25519-signed is
//! `BLAKE3(manifest_bytes) ‖ BLAKE3(cwasm_bytes)` — a 64-byte value. Signing the two
//! hashes rather than one blob lets `lantern-runtime` verify the `.cwasm` it is about to
//! `deserialize` without holding the manifest, and lets `lantern-shell` verify the
//! manifest it is about to render without pulling the whole `.cwasm`.

use lantern_crypto::hash::{self, HASH_LEN};
use lantern_crypto::signing::{self, SigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// The signed value: `BLAKE3(manifest) ‖ BLAKE3(cwasm)`.
pub const DIGEST_LEN: usize = 2 * HASH_LEN;

/// `BLAKE3(manifest_bytes) ‖ BLAKE3(cwasm_bytes)`.
pub fn package_digest(manifest_bytes: &[u8], cwasm_bytes: &[u8]) -> [u8; DIGEST_LEN] {
    digest_from_hashes(
        hash::hash(manifest_bytes).as_bytes(),
        hash::hash(cwasm_bytes).as_bytes(),
    )
}

/// The digest when the manifest half is already hashed — the shape `lantern-runtime`
/// uses to verify a `.cwasm` without the manifest in hand.
pub fn digest_from_hashes(
    manifest_hash: &[u8; HASH_LEN],
    cwasm_hash: &[u8; HASH_LEN],
) -> [u8; DIGEST_LEN] {
    let mut d = [0u8; DIGEST_LEN];
    d[..HASH_LEN].copy_from_slice(manifest_hash);
    d[HASH_LEN..].copy_from_slice(cwasm_hash);
    d
}

/// Signs a package: `Ed25519_sign(package_digest(manifest, cwasm))`.
pub fn sign_package(
    manifest_bytes: &[u8],
    cwasm_bytes: &[u8],
    key: &SigningKey,
) -> [u8; SIGNATURE_LEN] {
    key.sign(&package_digest(manifest_bytes, cwasm_bytes))
}

/// Verifies a package signature against both halves.
pub fn verify_package(
    manifest_bytes: &[u8],
    cwasm_bytes: &[u8],
    public_key: &[u8; PUBLIC_KEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), PackageError> {
    let digest = package_digest(manifest_bytes, cwasm_bytes);
    signing::verify(public_key, &digest, signature).map_err(|_| PackageError::BadSignature)
}

/// Verifies a package signature given only the `.cwasm` and the manifest's BLAKE3 hash —
/// what `lantern-runtime` does before `deserialize`, without ever seeing the manifest.
pub fn verify_cwasm(
    manifest_hash: &[u8; HASH_LEN],
    cwasm_bytes: &[u8],
    public_key: &[u8; PUBLIC_KEY_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), PackageError> {
    let digest = digest_from_hashes(manifest_hash, hash::hash(cwasm_bytes).as_bytes());
    signing::verify(public_key, &digest, signature).map_err(|_| PackageError::BadSignature)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PackageError {
    /// The signature does not verify — the manifest, the `.cwasm`, or the pairing between
    /// them was tampered with, or it was signed under a different key.
    BadSignature,
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "package signature does not verify"),
        }
    }
}

impl std::error::Error for PackageError {}
