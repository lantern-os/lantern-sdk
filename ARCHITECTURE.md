# lantern-sdk — Architecture

Companion to [wiki/Runtime](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Runtime.md).

## What the SDK provides
- **Capability-aware APIs** — types that make capabilities first-class: you receive, attenuate,
  and pass them explicitly. The type system discourages hoarding authority.
- **WIT bindings** — generate language bindings from the Component Model interfaces
  ([ADR-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0003-wasm-as-portable-app-abi.md)) the runtime exposes.
- **Build & package tooling** — compile to Wasm components, declare required capabilities in a
  **manifest**, sign and content-address the artefact ([`lantern-filesystem`](https://github.com/lantern-os/lantern-filesystem)).
- **Local run/dev loop** — run a component confined against the runtime, granting only the
  declared capabilities, with the audit log visible.

## Design principles
- **Least privilege by default** — the manifest declares the *minimum* capabilities; the
  developer must justify each. Broad requests are friction by design.
- **Safe path = easy path** — idiomatic SDK usage is the secure usage; ambient-authority
  patterns are hard to express.
- **Honest manifests** — a component's declared capabilities are exactly what it can be
  granted; the user/shell sees them before consenting.

## Languages
Core in Rust; TypeScript bindings for web/tooling. Additional language bindings follow from
WIT, not from bespoke per-language work.

## Open questions
- Manifest format and how it maps to grantable capabilities and consent UX.
- Ergonomics of attenuation in each target language.
- Reproducible, signed packaging and a distribution model (Phase 5).
