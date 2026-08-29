# lantern-sdk — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). The hard blocker is lifted — see "Blocked on".

## Done
- SDK responsibilities and least-privilege-by-default stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed.

## Next
- **The capability manifest format is drafted** — [RFC-0015](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0015-capability-manifest-format.md)
  (Draft): a TOML `lantern.capabilities.toml` keyed by WIT interface, two declaration
  shapes mirroring RFC-0014's two mapping shapes (resource-scoped = ordered role list with
  `ops` + mandatory `justification`; link-scoped = present-or-absent + `justification`),
  abstract roles bound to concrete objects at launch, declaration order as the
  `keystore.open(slot)` index, the WIT `world` generated *from* the manifest, and a
  combined-digest signature binding manifest to `.cwasm`. Awaiting review/acceptance
  before implementation.
- After acceptance: the `lantern-sdk` manifest parser/validator + WIT-`world` generator,
  then SDK v0 — build a confined Wasm app, declare capabilities in a manifest, run it
  against `lantern-runtime`'s `build_linker`. `lantern-runtime`'s `wit/host.wit` is the
  first interface set to bind against.
- The launch-time *binder* and consent UX (resolve a manifest `role` to a concrete object)
  are `lantern-shell`'s, not this crate's (RFC-0015 scope).

## Blocked on
- ~~Stable WIT interfaces from [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime).~~ Lifted —
  `lantern-runtime`'s `wit/host.wit` exists (`monotonic-clock` link-scoped,
  `lantern:crypto/keystore` resource-scoped) and the two mapping shapes are fixed by
  RFC-0014/ADR-0018. The surface is still small and unversioned — pinning it as a governed
  public ABI is a later-phase concern (`lantern-runtime`'s `ARCHITECTURE.md` open questions) —
  but it is no longer absent.
