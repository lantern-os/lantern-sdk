//! Model packages ([RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md)): a model, signed by
//! its publisher, checked the way an app package is.
//!
//! `LMD1` + u32-LE `len(manifest)` + manifest + u32-LE `len(model)` + model + 64-byte signature. The signature is the app
//! package's ([`crate::package::sign_package`]): Ed25519 over `BLAKE3(manifest) ‖ BLAKE3(model)`.
//!
//! - **The manifest** is text: the line `lantern-model 1`, then `name=` and the model's name, then newlines up to
//!   [`MANIFEST_LEN`] bytes, so the model starts on a 512-byte boundary. It can't parse as an app manifest, and an app
//!   manifest can't pass for one, so neither kind of package can be presented as the other.
//! - **The model** starts at offset [`MODEL_OFFSET`]: a sector of the disk, and aligned for the engine, which reads its
//!   weights in place.
//!
//! Reading and checking allocate nothing, for the inference service. Writing one ([`encode_model`]) needs `alloc`.

use alloc::vec::Vec;

use lantern_crypto::signing::{SigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::package::{sign_package, verify_package, PackageError};

pub const MAGIC: &[u8; 4] = b"LMD1";
/// The manifest's first line.
pub const HEADER: &[u8] = b"lantern-model 1\n";
/// Where the model starts: a sector, so the engine's data is aligned and the disk reads it whole.
pub const MODEL_OFFSET: usize = 512;
/// The manifest's length, padding included: whatever puts the model at [`MODEL_OFFSET`].
pub const MANIFEST_LEN: usize = MODEL_OFFSET - 4 - 4 - 4;
/// The longest name that fits.
pub const NAME_MAX: usize = 64;

/// A model package, borrowed from its bytes. **Not yet verified**: [`ModelPackage::verify`] does that.
#[derive(Debug)]
pub struct ModelPackage<'a> {
    pub manifest: &'a [u8],
    pub model: &'a [u8],
    pub signature: &'a [u8; SIGNATURE_LEN],
}

impl<'a> ModelPackage<'a> {
    /// Whether `publisher` signed this manifest and this model, together.
    pub fn verify(&self, publisher: &[u8; PUBLIC_KEY_LEN]) -> Result<(), PackageError> {
        verify_package(self.manifest, self.model, publisher, self.signature)
    }

    /// The model's name, from the manifest.
    pub fn name(&self) -> Option<&'a str> {
        let rest = self.manifest.strip_prefix(HEADER)?.strip_prefix(b"name=")?;
        let end = rest.iter().position(|&b| b == b'\n')?;
        core::str::from_utf8(&rest[..end]).ok()
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// A package's whole length, from its first [`MODEL_OFFSET`] bytes: how much to read before [`decode_model`].
pub fn package_len(first: &[u8]) -> Result<usize, PackageError> {
    if first.get(..4) != Some(MAGIC.as_slice()) || u32_at(first, 4) != Some(MANIFEST_LEN) {
        return Err(PackageError::Malformed);
    }
    let model_len = u32_at(first, 8 + MANIFEST_LEN).ok_or(PackageError::Malformed)?;
    MODEL_OFFSET.checked_add(model_len).and_then(|n| n.checked_add(SIGNATURE_LEN)).ok_or(PackageError::Malformed)
}

/// Parses a model package in place: exactly [`package_len`] bytes, the model at [`MODEL_OFFSET`], and a manifest that
/// says it's a model. Structural only: the signature still needs [`ModelPackage::verify`].
pub fn decode_model(bytes: &[u8]) -> Result<ModelPackage<'_>, PackageError> {
    let len = package_len(bytes)?;
    if bytes.len() != len {
        return Err(PackageError::Malformed);
    }
    let manifest = &bytes[8..8 + MANIFEST_LEN];
    let model = &bytes[MODEL_OFFSET..len - SIGNATURE_LEN];
    let signature = bytes[len - SIGNATURE_LEN..].try_into().map_err(|_| PackageError::Malformed)?;
    let package = ModelPackage { manifest, model, signature };
    package.name().ok_or(PackageError::Malformed)?;
    Ok(package)
}

/// Builds and signs a model package. `None` for a name that's empty, too long, or has a newline in it, or a model over
/// 4 GiB.
pub fn encode_model(name: &str, model: &[u8], key: &SigningKey) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > NAME_MAX || name.contains('\n') {
        return None;
    }
    let model_len = u32::try_from(model.len()).ok()?;
    let mut manifest = Vec::with_capacity(MANIFEST_LEN);
    manifest.extend_from_slice(HEADER);
    manifest.extend_from_slice(b"name=");
    manifest.extend_from_slice(name.as_bytes());
    manifest.resize(MANIFEST_LEN, b'\n');
    let signature = sign_package(&manifest, model, key);
    let mut out = Vec::with_capacity(MODEL_OFFSET + model.len() + SIGNATURE_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(MANIFEST_LEN as u32).to_le_bytes());
    out.extend_from_slice(&manifest);
    out.extend_from_slice(&model_len.to_le_bytes());
    out.extend_from_slice(model);
    out.extend_from_slice(&signature);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_random_bytes([seed; 32])
    }

    #[test]
    fn a_package_round_trips_verifies_and_puts_the_model_on_a_sector() {
        let model = b"LMODEL01 and its weights".repeat(40);
        let bytes = encode_model("stories15M", &model, &key(0x4c)).unwrap();
        assert_eq!(package_len(&bytes[..MODEL_OFFSET]), Ok(bytes.len()));
        let package = decode_model(&bytes).unwrap();
        assert_eq!(package.name(), Some("stories15M"));
        assert_eq!(package.model, model.as_slice());
        assert_eq!(package.model.as_ptr() as usize - bytes.as_ptr() as usize, MODEL_OFFSET);
        assert_eq!(package.verify(&key(0x4c).verifying_key()), Ok(()));
        assert_eq!(package.verify(&key(0x4d).verifying_key()), Err(PackageError::BadSignature), "another publisher");
    }

    #[test]
    fn any_changed_byte_is_refused() {
        let bytes = encode_model("m", &[7u8; 600], &key(0x4c)).unwrap();
        let publisher = key(0x4c).verifying_key();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            let ok = decode_model(&bad).is_ok_and(|p| p.verify(&publisher).is_ok());
            assert!(!ok, "byte {i} changed, and it still verified");
        }
    }

    #[test]
    fn an_app_package_is_not_a_model_package() {
        let (manifest, wasm): (&[u8], &[u8]) = (b"[app]\nname = \"x\"\n", b"wasm");
        let app = crate::package::encode_package(manifest, wasm, &sign_package(manifest, wasm, &key(0x4c)));
        assert_eq!(decode_model(&app).map(|_| ()), Err(PackageError::Malformed));
        let model = encode_model("m", b"weights", &key(0x4c)).unwrap();
        assert!(crate::package::decode_package_ref(&model).is_err());
    }

    #[test]
    fn bad_names_and_truncations_are_refused() {
        assert!(encode_model("", b"x", &key(1)).is_none());
        assert!(encode_model("a\nb", b"x", &key(1)).is_none());
        assert!(encode_model(&"n".repeat(NAME_MAX + 1), b"x", &key(1)).is_none());
        let bytes = encode_model("m", b"weights", &key(1)).unwrap();
        assert!(decode_model(&bytes[..bytes.len() - 1]).is_err());
        assert!(package_len(&bytes[..10]).is_err());
    }
}
