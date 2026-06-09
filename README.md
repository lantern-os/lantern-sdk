# lantern-sdk

The developer **SDK** for LanternOS: capability-aware APIs, WIT-based bindings, and tooling to
build, package, and run confined Wasm apps and agents.

- **Layer:** tooling (cross-cutting).
- **Language:** Rust for the core; TypeScript for web/tooling bindings ([ADR-0001](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0001-rust-as-primary-language.md)).
- **System context:** [wiki/Runtime](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Runtime.md), [wiki/Security](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Security.md).

> ⚠️ **Phase 0.** Design only; no code. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Goal
Make the **safe path the easy path**. Capability handling should be ergonomic so developers
request least privilege by default, and the SDK should make ambient-authority patterns hard to
even express.
