# Changelog

What changed in Chronos, in the words of the people who use it. Every entry
here is something you can observe from outside: a new capability, a changed
behaviour, a fixed defect, a security change.

> **Chronos is an unstable alpha.** Every release is tagged with a prerelease
> marker — `-alpha.1` and onward. Anything may change between releases,
> including behaviour you depend on, and there is no upgrade path guarantee
> until a release ships without that marker. Do not run this in production.

Versions follow [semantic versioning](https://semver.org). The wire contract is
versioned separately and independently, as `chronos.<domain>.v1` — see
[docs/VERSIONING.md](docs/VERSIONING.md).


## v0.1.0-alpha.1 — 2026-08-27

### Fixed
- **compliance** — Your data export and erasure confirmation now state that invoice records are retained only when your organizations were actually invoiced, instead of saying so for everyone.
