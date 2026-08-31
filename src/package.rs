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

// -------------------------------------------------------------------------------------
// The on-disk package container
// -------------------------------------------------------------------------------------

/// `LPK1` + u32-LE `len(manifest)` + manifest + u32-LE `len(cwasm)` + cwasm + 64-byte sig.
/// A single distributable file holding both halves and the signature over their digest.
const MAGIC: &[u8; 4] = b"LPK1";

/// Serialises `{ manifest, cwasm, signature }` into one `.lpkg` blob.
pub fn encode_package(
    manifest_bytes: &[u8],
    cwasm_bytes: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + manifest_bytes.len() + 4 + cwasm_bytes.len() + SIGNATURE_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(manifest_bytes);
    out.extend_from_slice(&(cwasm_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(cwasm_bytes);
    out.extend_from_slice(signature);
    out
}

/// The three parts of a `.lpkg` blob. **Does not verify the signature** — call
/// [`verify_package`] with the caller's trusted public key.
pub struct Package {
    pub manifest_bytes: Vec<u8>,
    pub cwasm_bytes: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Parses a `.lpkg` blob. Structural only — the signature still needs verifying.
pub fn decode_package(bytes: &[u8]) -> Result<Package, PackageError> {
    let mut r = bytes;
    let take = |r: &mut &[u8], n: usize| -> Result<Vec<u8>, PackageError> {
        if r.len() < n {
            return Err(PackageError::Malformed);
        }
        let (head, tail) = r.split_at(n);
        *r = tail;
        Ok(head.to_vec())
    };
    if take(&mut r, 4)? != MAGIC {
        return Err(PackageError::Malformed);
    }
    let mlen = u32::from_le_bytes(take(&mut r, 4)?.try_into().unwrap()) as usize;
    let manifest_bytes = take(&mut r, mlen)?;
    let clen = u32::from_le_bytes(take(&mut r, 4)?.try_into().unwrap()) as usize;
    let cwasm_bytes = take(&mut r, clen)?;
    let signature: [u8; SIGNATURE_LEN] = take(&mut r, SIGNATURE_LEN)?.try_into().unwrap();
    if !r.is_empty() {
        return Err(PackageError::Malformed);
    }
    Ok(Package { manifest_bytes, cwasm_bytes, signature })
}

#[derive(Debug, PartialEq, Eq)]
pub enum PackageError {
    /// The signature does not verify — the manifest, the `.cwasm`, or the pairing between
    /// them was tampered with, or it was signed under a different key.
    BadSignature,
    /// The `.lpkg` container is truncated or has a bad magic / length header.
    Malformed,
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "package signature does not verify"),
            Self::Malformed => write!(f, "malformed .lpkg container"),
        }
    }
}

impl std::error::Error for PackageError {}
