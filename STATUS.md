# lantern-sdk — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). The hard blocker is lifted — see "Blocked on".

## Done
- SDK responsibilities and least-privilege-by-default stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed.

## Next
- **Design the capability manifest format** — now unblocked. [RFC-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0014-wit-handle-capability-mapping.md)/[ADR-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0018-wit-handle-capability-mapping.md)
  fix the *runtime-side contract* this must satisfy: one badge per resource-scoped grant
  (e.g. a `lantern:crypto/keystore` `key`), one yes/no per link-scoped facility (e.g.
  `monotonic-clock`). The file format a developer authors, and how it compiles to the
  `GrantManifest` [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime) consumes, is this crate's to design —
  likely its own RFC.
- Phase 2: SDK v0 — build a confined Wasm app, declare capabilities in a manifest, run it
  against `lantern-runtime`'s `build_linker`. `lantern-runtime`'s `wit/host.wit` is the first
  interface set to bind against.

## Blocked on
- ~~Stable WIT interfaces from [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime).~~ Lifted —
  `lantern-runtime`'s `wit/host.wit` exists (`monotonic-clock` link-scoped,
  `lantern:crypto/keystore` resource-scoped) and the two mapping shapes are fixed by
  RFC-0014/ADR-0018. The surface is still small and unversioned — pinning it as a governed
  public ABI is a later-phase concern (`lantern-runtime`'s `ARCHITECTURE.md` open questions) —
  but it is no longer absent.
