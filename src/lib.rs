//! `lantern-sdk` — the LanternOS developer SDK, v0
//! ([RFC-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0015-capability-manifest-format.md)/
//! [ADR-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0020-capability-manifest-format.md)).
//!
//! What an app ships is a Wasm component plus a **`lantern.capabilities.toml`** declaring,
//! per imported host interface, exactly what authority it needs. This crate is the
//! canonical tooling for that file:
//!
//! - [`manifest`] — the model and the [`parse`] + validation entry point.
//! - [`registry`] — the interface registry: which interfaces exist, their declaration
//!   shape, and their legal `ops`. Kept in lockstep with `lantern-runtime/wit/`.
//! - [`wit`] — generate the component's WIT `world` from the manifest, and the checkable
//!   [`wit::declared_imports`] list (imports can never exceed the manifest).
//! - [`plan`] — the ordered [`plan::GrantPlan`] a launch binder walks.
//! - [`package`] — the combined-digest (`BLAKE3(manifest) ‖ BLAKE3(cwasm)`, Ed25519)
//!   package signing that binds a manifest to its `.cwasm`, and the `.lpkg` container.
//! - [`bind`] (feature `bind`) — turn a `GrantPlan` + a binder's decisions into a
//!   `lantern_runtime::GrantManifest`.
//! - [`build`] (feature `build`) + the `lantern-sdk` CLI — validate, import-check,
//!   AOT-compile, sign, and emit a `.lpkg` package.
//!
//! Only [`package`] is available without the default `std` feature: that build is
//! `no_std` + `alloc`, for a confined `lantern-runtime` process that verifies the `.lpkg`
//! its launcher hands it ([RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)).
//!
//! **Not in this crate:** the launch-time binder and consent UX (`lantern-shell`'s job —
//! this crate fixes only the validated manifest it consumes and the `GrantPlan` /
//! `GrantManifest` it produces), and any manifest-evolution / upgrade story.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod manifest;
pub mod package;
#[cfg(feature = "std")]
pub mod plan;
#[cfg(feature = "std")]
pub mod registry;
#[cfg(feature = "std")]
pub mod wit;

#[cfg(feature = "bind")]
pub mod bind;

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "std")]
pub use manifest::{parse, Manifest, ManifestError};
#[cfg(feature = "std")]
pub use plan::GrantPlan;

#[cfg(all(test, feature = "std"))]
mod tests;
