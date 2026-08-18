# lantern-sdk — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). Still fully blocked — see "Blocked on".

## Done
- SDK responsibilities and least-privilege-by-default stance drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Threat model drafted and reviewed.

## Next
- Design the capability manifest format.
- Phase 2: SDK v0 — build a confined Wasm app, declare capabilities, run against the runtime.

## Blocked on
- Stable WIT interfaces from [`lantern-runtime`](https://github.com/lantern-os/lantern-runtime).
