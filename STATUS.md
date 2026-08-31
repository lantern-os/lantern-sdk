# lantern-sdk — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). First prototype code now exists — see "Done".

## Done
- SDK responsibilities and least-privilege-by-default stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed.
- **The capability manifest format is accepted and first-implemented** —
  [RFC-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0015-capability-manifest-format.md)/[ADR-0020](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0020-capability-manifest-format.md)
  (Accepted). `src/`:
  - **`manifest`** — the model + [`parse`] + full RFC-0015 validation (known interfaces,
    legal `ops` per the registry, unique roles, non-empty ≤ 280-char justifications,
    identifier charset, shape/extra-key checks). Errors point at the offending declaration.
  - **`registry`** — the interface registry, one entry per interface `lantern-runtime`
    implements (`keystore`, `filesystem`, `monotonic-clock`), each with its declaration
    shape, WIT import identifier, and legal `ops`. A manifest naming anything else fails.
  - **`wit`** — `declared_imports` (the checkable "imports ≤ declarations" list) and
    `generate_world`.
  - **`plan`** — `GrantPlan`: the ordered `ResourceRequest`s (with permanent `slot`
    indices) a launch binder walks.
  - **`package`** — combined-digest signing: `BLAKE3(manifest) ‖ BLAKE3(cwasm)`,
    Ed25519-signed; `verify_package` and `verify_cwasm` (the manifest-less path
    `lantern-runtime` uses).
  - **`bind`** (feature `bind`) — assemble a `lantern_runtime::GrantManifest` from a
    `GrantPlan` + a binder's per-request `Bound::{Granted, Declined}` decisions, in
    declaration order.
  - 21 tests (20 without `bind`). `cargo clippy --all-targets -D warnings` clean with and
    without `--features bind`.
- **`lantern-example-signer` is now manifest-driven** — its runner parses the app's
  `lantern.capabilities.toml` via this crate, plans it, and binds the plan; the manifest
  is the authority, not hard-coded Rust. (Its own repo — see
  `lantern-runtime/STATUS.md`.)
- **Not in this crate** (RFC-0015 scope): the launch binder + consent UX
  (`lantern-shell`'s — this crate produces the `GrantPlan` it consumes); per-language
  binding ergonomics; installed-app manifest evolution.

## Next
- The build/package CLI (`lantern-sdk build`): compile a component for `wasm32-wasip2`,
  check its imports against `wit::declared_imports`, and emit the signed
  `{ manifest, cwasm, signature }` package. Today the `lantern-example-signer` runner
  does the compile+sign inline via `lantern-runtime::compiler`.
- `lantern-sdk manifest explain` — render a manifest exactly as `lantern-shell` will
  (RFC-0015 "Future possibilities").
- TypeScript bindings (ADR-0001) — follows from WIT, later.
- WIT `world` composition so the generated import world and the app's export world merge
  without the app author re-declaring imports.

## Blocked on
- ~~Stable WIT interfaces from [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime).~~ Lifted (RFC-0014/
  RFC-0016). ~~The manifest format.~~ Accepted (RFC-0015/ADR-0020).
- The build CLI's confined-run loop wants `lantern-runtime` running in a real confined
  process (`lantern-runtime/STATUS.md`) — the host-target stand-in is fine for v0.
