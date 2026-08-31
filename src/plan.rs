//! The `GrantPlan` — the ordered, structured view of a manifest that a launch binder
//! (`lantern-shell`, or a host runner) walks to obtain concrete capabilities and build a
//! `lantern_runtime::GrantManifest` (RFC-0015 §"Compilation to `GrantManifest`").

use crate::manifest::{AppInfo, Manifest, ResourceDecl};

/// One resource-scoped request the binder must resolve to a concrete object (or decline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    /// The permanent `open(slot)` wire index — this request's position in its
    /// declaration array. Stable regardless of later declines.
    pub slot: u32,
    pub role: String,
    pub ops: Vec<String>,
    pub justification: String,
}

/// One link-scoped request — granted or refused whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    pub justification: String,
}

/// Everything a manifest requests, ordered for a binder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPlan {
    pub app: AppInfo,
    /// `keystore.open(i)` requests, `i` = index here.
    pub keystore: Vec<ResourceRequest>,
    /// `filesystem.open(i)` requests.
    pub filesystem: Vec<ResourceRequest>,
    pub monotonic_clock: Option<LinkRequest>,
}

impl Manifest {
    /// The launch-time plan for this manifest.
    pub fn plan(&self) -> GrantPlan {
        GrantPlan {
            app: self.app.clone(),
            keystore: requests(&self.keystore),
            filesystem: requests(&self.filesystem),
            monotonic_clock: self
                .monotonic_clock
                .as_ref()
                .map(|d| LinkRequest { justification: d.justification.clone() }),
        }
    }
}

fn requests(decls: &[ResourceDecl]) -> Vec<ResourceRequest> {
    decls
        .iter()
        .enumerate()
        .map(|(i, d)| ResourceRequest {
            slot: i as u32,
            role: d.role.clone(),
            ops: d.ops.clone(),
            justification: d.justification.clone(),
        })
        .collect()
}
