# Project instructions

## Product and evidence

- This is a commercial, cross-platform download manager targeting a complete launch. Internal experiments are not a public MVP.
- Read `README.md` and `docs/execution-status.md` before changing the project. Requirements and scope live in `docs/product-requirements.md` and `docs/delivery-backlog.md`.
- Record material decisions, implementation status, verification results, and unresolved risks in Markdown. Distinguish proposed controls from implemented and tested controls.
- Default user-facing communication and product documentation to Arabic; code identifiers may use English.

## Engineering and security ownership

- The user explicitly requests Engineering and Security agents. Delegate independent, bounded review work to those agents for changes to production architecture or trust boundaries; implementation and review should not be performed solely by the same agent when independent review is available.
- Engineering reviews module boundaries, error handling, cancellation, concurrency, resource limits, maintainability, and meaningful tests.
- Security reviews licensing, activation, authorization, cryptography, updates, secrets, native IPC, filesystem boundaries, untrusted inputs, and dependency additions affecting these areas.
- Use `docs/engineering-standards.md` and `docs/licensing-and-tamper-resistance.md` for the detailed standards once available. Resolve conflicting recommendations explicitly and record the decision.
- Review comments are work to resolve, not an automatic request for user permission. Escalate only unresolved business decisions, costs, credentials, or permissions actually needed.

## Implementation invariants

- Keep authoritative download state out of React. Separate the download engine, application command authorization, presentation, and commercial services.
- Do not implement custom cryptographic algorithms or put production signing secrets/shared license-minting secrets in desktop, extension, test fixtures, or the repository.
- A local paid/unlocked flag is not authority. Server resources must authorize requests on the server. Native application checks reduce accidental/UI bypass but cannot guarantee resistance to a modified client.
- Offline licensing and revocation have explicit tradeoffs; never claim unbreakable protection or instantaneous offline revocation.
- License errors or suspected tampering must not delete user files, corrupt partial downloads, disable OS protections, or terminate unrelated processes.
- Do not silently append resumed bytes when the representation cannot be validated, overwrite unrelated files, or log credentials and signed URLs.
- Pin production toolchains/dependencies when introduced, review their licenses/security posture, and maintain reproducible build inputs. Do not claim CI, signing, or audit is active before it is implemented.
- Run relevant tests after behavioral changes; record what was tested and on which environment. Do not add tests merely to mirror code.

## Current verification

- `npm.cmd test` on PowerShell (or `npm test` where supported) runs the HTTP lab tests using Node's built-in test framework without a child test process.
- `npm run lab:serve` starts a loopback-only synthetic fixture server. It is a development tool, not the product backend or download engine.
- Rust pure domain crates exist under `crates/`: download-core and resume-policy. Follow `docs/development.md` for the pinned local toolchain and test/fmt/clippy commands.
- The network transfer engine, durable storage, desktop app, browser extensions, and production licensing are not yet implemented; consult the current execution record rather than inferring their existence.
