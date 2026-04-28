# philharmonic-api

Part of the Philharmonic workspace: https://github.com/metastable-void/philharmonic-workspace

`philharmonic-api` is the public HTTP API layer for Philharmonic. It
exposes a builder that accepts deployment-supplied trait implementations
such as `RequestScopeResolver` and returns a ready-to-serve `axum::Router`.
The current 0.0.0 crate implements scope resolution, correlation IDs,
structured error envelopes, real authentication (long-lived `pht_`
token lookup and ephemeral COSE_Sign1 verification), placeholder
authorization, and meta smoke endpoints; substantive v1 handlers
land in later Phase 8 sub-phases.

## Contributing

This crate is developed as a submodule of the Philharmonic
workspace. Workspace-wide development conventions — git workflow,
script wrappers, Rust code rules, versioning, terminology — live
in the workspace meta-repo at
[metastable-void/philharmonic-workspace](https://github.com/metastable-void/philharmonic-workspace),
authoritatively in its
[`CONTRIBUTING.md`](https://github.com/metastable-void/philharmonic-workspace/blob/main/CONTRIBUTING.md).

SPDX-License-Identifier: Apache-2.0 OR MPL-2.0
