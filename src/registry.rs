//! The interface registry — which host interfaces a manifest may declare, their
//! declaration shape, and their legal `ops`. RFC-0015/ADR-0020: this is **not**
//! open-ended; a manifest naming an interface or `ops` value not here fails validation,
//! because a developer cannot request a facility `lantern-runtime` cannot satisfy.
//!
//! Kept in lockstep with `lantern-runtime/wit/host.wit`. Adding an interface is a
//! coordinated `lantern-runtime` + `lantern-sdk` change.

/// A registered host interface.
pub struct Interface {
    /// The key it appears under in the manifest, i.e. its WIT interface-local name:
    /// `keystore`, `filesystem`, `monotonic-clock`.
    pub name: &'static str,
    /// The fully-qualified WIT interface identifier the generated `world` imports.
    pub wit_import: &'static str,
    pub shape: Shape,
}

/// The two mapping shapes from RFC-0014.
pub enum Shape {
    /// Resource-scoped: `[[<name>.<resource>]]` array-of-tables, each entry a `role` +
    /// `ops` + `justification`. `ops` values must be a subset of `ops`.
    Resource {
        resource: &'static str,
        ops: &'static [&'static str],
    },
    /// Link-scoped: `[<name>]` table, presence = request, `justification` the only key.
    Link,
}

/// The Phase 2 registry — the three interfaces `lantern-runtime` implements today
/// (RFC-0014's `keystore` + `monotonic-clock`, RFC-0016's `filesystem`).
pub const REGISTRY: &[Interface] = &[
    Interface {
        name: "keystore",
        wit_import: "lantern:host/keystore@0.1.0",
        shape: Shape::Resource { resource: "key", ops: &["encrypt", "decrypt", "sign"] },
    },
    Interface {
        name: "filesystem",
        wit_import: "lantern:host/filesystem@0.1.0",
        shape: Shape::Resource { resource: "file", ops: &["read", "write"] },
    },
    Interface {
        name: "monotonic-clock",
        wit_import: "lantern:host/monotonic-clock@0.1.0",
        shape: Shape::Link,
    },
];

/// Looks up a registered interface by its manifest key / WIT interface-local name.
pub fn lookup(name: &str) -> Option<&'static Interface> {
    REGISTRY.iter().find(|i| i.name == name)
}
