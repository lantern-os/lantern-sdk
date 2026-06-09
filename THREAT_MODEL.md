# lantern-sdk — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The SDK is tooling,
not a runtime trust boundary — but it shapes whether developers build least-privilege software,
and tooling is a supply-chain target (system threat T10).

## Assets
- Integrity of generated artefacts and bindings.
- Honesty of capability manifests.
- Integrity of the SDK toolchain itself.

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| S1 | Developer ships over-privileged apps | Least-privilege defaults; per-capability justification; friction on broad requests. |
| S2 | Dishonest/over-broad manifest | Manifest = exactly the grantable caps; user sees it before consent; runtime enforces it. |
| S3 | Compromised SDK toolchain (supply chain) | Reproducible builds; signed releases; minimal dependencies; provenance. |
| S4 | Tampered packaged artefact | Content-addressed + signed packaging. |

## Non-goals
- The SDK is not a runtime enforcement boundary — enforcement is the runtime's and kernel's
  job; the SDK's role is to make safe defaults easy and manifests honest.
