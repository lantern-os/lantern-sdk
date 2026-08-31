//! Turn a [`GrantPlan`] plus a binder's per-request decisions into a
//! `lantern_runtime::GrantManifest` (feature `bind`).
//!
//! This crate does **not** implement the binder — resolving a `role` to a concrete
//! object, minting the badge, and (eventually) asking the user for consent is
//! `lantern-shell`'s job (RFC-0015). This helper only owns the ordering: it walks the
//! plan in declaration order and assembles the sparse `GrantManifest` from whatever the
//! caller's closures return, so a caller cannot get the `open(slot)` indices wrong.

use lantern_runtime::{GrantManifest, HostCapability, HostFile, MonotonicClock};

use crate::plan::{GrantPlan, LinkRequest, ResourceRequest};

/// A binder's decision for one resource-scoped request.
pub enum Bound<T> {
    /// The role was bound to a concrete object; `T` is the minted host handle record.
    Granted(T),
    /// The role was declined (or is not yet bound). `open(slot)` will return `none`.
    Declined,
}

/// Assembles a `GrantManifest` from `plan` and the caller's binding decisions.
///
/// - `key` / `file` are called once per resource request, in declaration order, and
///   return the minted [`HostCapability`] / [`HostFile`] or [`Bound::Declined`].
/// - `clock` is called iff the plan requests `monotonic-clock`; returning `None` refuses
///   it (the component will then fail to instantiate — RFC-0014's link-scoped rule).
pub fn bind(
    plan: &GrantPlan,
    mut key: impl FnMut(&ResourceRequest) -> Bound<HostCapability>,
    mut file: impl FnMut(&ResourceRequest) -> Bound<HostFile>,
    clock: impl FnOnce(&LinkRequest) -> Option<MonotonicClock>,
) -> GrantManifest {
    GrantManifest {
        keystore_keys: plan.keystore.iter().map(|r| into_opt(key(r))).collect(),
        filesystem_files: plan.filesystem.iter().map(|r| into_opt(file(r))).collect(),
        monotonic_clock: plan.monotonic_clock.as_ref().and_then(clock),
    }
}

fn into_opt<T>(b: Bound<T>) -> Option<T> {
    match b {
        Bound::Granted(t) => Some(t),
        Bound::Declined => None,
    }
}
