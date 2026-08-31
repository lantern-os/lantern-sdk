//! `lantern-sdk build` — turn a component + its manifest into a signed `.lpkg` package
//! (feature `build`).
//!
//! Steps (RFC-0015 §"Then `lantern-sdk build`"):
//!   1. parse + validate the manifest;
//!   2. check the component imports **exactly** the `lantern:host/*` interfaces the
//!      manifest declares — no more (the "imports ≤ declarations" guarantee);
//!   3. AOT-compile the component and sign `BLAKE3(manifest) ‖ BLAKE3(cwasm)`;
//!   4. emit the `{ manifest, cwasm, signature }` `.lpkg` blob.

use lantern_crypto::signing::SigningKey;
use lantern_runtime::compiler::{compiler_engine, component_import_names, precompile_and_sign};

use crate::manifest::{self, Manifest};
use crate::{package, wit};

/// A built, signed package plus the metadata a publisher wants alongside it.
#[derive(Debug)]
pub struct Built {
    /// The `.lpkg` blob — write this to disk / distribute it.
    pub lpkg: Vec<u8>,
    /// The Ed25519 public key the package was signed under. A verifier needs this.
    pub verifying_key: [u8; 32],
    pub manifest: Manifest,
}

/// Builds and signs a package. `component_wasm` is a `wasm32-wasip2` **component** (what
/// `cargo build --target wasm32-wasip2` emits), not a core module.
pub fn build(
    manifest_toml: &str,
    component_wasm: &[u8],
    signing_key: &SigningKey,
) -> Result<Built, BuildError> {
    let manifest = manifest::parse(manifest_toml).map_err(BuildError::Manifest)?;

    let engine = compiler_engine();
    let imports = component_import_names(&engine, component_wasm)
        .map_err(|e| BuildError::Component(format!("{e:?}")))?;
    check_imports(&manifest, &imports)?;

    // AOT-compile. The `.cwasm`'s own Ed25519 signature (`precompile_and_sign`) is the
    // RFC-0013 artifact check; the package signature below additionally binds the manifest.
    let (cwasm, _cwasm_sig) = precompile_and_sign(&engine, component_wasm, signing_key)
        .map_err(|e| BuildError::Component(format!("{e:?}")))?;

    let sig = package::sign_package(manifest_toml.as_bytes(), &cwasm, signing_key);
    let lpkg = package::encode_package(manifest_toml.as_bytes(), &cwasm, &sig);

    Ok(Built { lpkg, verifying_key: signing_key.verifying_key(), manifest })
}

/// The component's `lantern:host/*` imports must be exactly the manifest's declared set.
/// Non-`lantern:host` imports (the `wasi:*` a `std` toolchain adds) are ignored here —
/// the runtime traps them; a future stricter mode may reject them.
fn check_imports(manifest: &Manifest, component_imports: &[String]) -> Result<(), BuildError> {
    let declared: Vec<&str> = wit::declared_imports(manifest);

    let host_imports: Vec<&str> = component_imports
        .iter()
        .map(String::as_str)
        .filter(|i| i.starts_with("lantern:host/"))
        .collect();

    let undeclared: Vec<String> = host_imports
        .iter()
        .filter(|i| !declared.contains(i))
        .map(|s| s.to_string())
        .collect();
    if !undeclared.is_empty() {
        return Err(BuildError::UndeclaredImports(undeclared));
    }

    let unused: Vec<String> = declared
        .iter()
        .filter(|d| !host_imports.contains(d))
        .map(|s| s.to_string())
        .collect();
    if !unused.is_empty() {
        return Err(BuildError::DeclaredButNotImported(unused));
    }
    Ok(())
}

#[derive(Debug)]
pub enum BuildError {
    Manifest(crate::manifest::ManifestError),
    Component(String),
    /// The component imports `lantern:host/*` interfaces its manifest does not declare.
    UndeclaredImports(Vec<String>),
    /// The manifest declares interfaces the component never imports — a manifest that
    /// over-asks. (Downgrade to a warning if this proves too strict for real apps.)
    DeclaredButNotImported(Vec<String>),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manifest(e) => write!(f, "manifest: {e}"),
            Self::Component(e) => write!(f, "component: {e}"),
            Self::UndeclaredImports(v) => {
                write!(f, "component imports interfaces the manifest does not declare: {v:?}")
            }
            Self::DeclaredButNotImported(v) => {
                write!(f, "manifest declares interfaces the component never imports: {v:?}")
            }
        }
    }
}

impl std::error::Error for BuildError {}
