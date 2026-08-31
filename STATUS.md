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
    Ed25519-signed; `verify_package` / `verify_cwasm` (the manifest-less path
    `lantern-runtime` uses); and the `.lpkg` container
    (`encode_package` / `decode_package`) — one distributable file holding the manifest,
    the `.cwasm`, and the signature.
  - **`bind`** (feature `bind`) — assemble a `lantern_runtime::GrantManifest` from a
    `GrantPlan` + a binder's per-request `Bound::{Granted, Declined}` decisions, in
    declaration order.
  - **`build`** (feature `build`) + the **`lantern-sdk` CLI** — `lantern-sdk build
    --manifest <toml> --component <wasm> --out <lpkg> [--seed <hex> | --ephemeral]`:
    validates the manifest, checks the component imports **exactly** the `lantern:host/*`
    interfaces the manifest declares (rejects undeclared imports *and* a manifest that
    over-asks), AOT-compiles + signs (via `lantern-runtime/compiler`), and emits the
    `.lpkg` + a `.pub` key file.
  - 28 tests (`--features build`) / 22 (`bind`) / 21 (default). `cargo clippy
    --all-targets -D warnings` clean in all three configs.
- **`lantern-example-signer` runs a signed `.lpkg`** — `make` builds the component, runs
  `lantern-sdk build` on it, and the runner (runtime-role only now — no `compiler`)
  decodes + verifies the package, deserializes the `.cwasm`, and binds the manifest's
  plan. The manifest is the authority end to end. (Its own repo — see
  `lantern-runtime/STATUS.md`.)
- **Not in this crate** (RFC-0015 scope): the launch binder + consent UX
  (`lantern-shell`'s — this crate produces the `GrantPlan` it consumes); per-language
  binding ergonomics; installed-app manifest evolution.

## Next
- `lantern-sdk build` should also *drive* `cargo build --target wasm32-wasip2` (today it
  takes a pre-built component path), and generate the component's WIT import `world` from
  the manifest so the app author does not re-declare imports (WIT `world` composition).
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
