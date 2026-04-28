# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial functional release. Implements Phase 8 of the Philharmonic
roadmap: the complete public HTTP API.

- **Skeleton (A)**: axum builder, `RequestScopeResolver` trait +
  middleware, request context, structured error envelope, correlation
  ID propagation, structured request logging, meta smoke endpoints
  (`/v1/_meta/version`, `/v1/_meta/health`).
- **Authentication (B)**: long-lived `pht_` token lookup via substrate
  `find_by_content`, ephemeral COSE_Sign1 verification via
  `philharmonic-policy` B0 primitives, `AuthContext` enum (Principal |
  Ephemeral), authority-tenant binding, authority-epoch enforcement,
  generic external 401 collapsing.
- **Authorization (C)**: `RequiredPermission` per-route extension,
  role-based permission evaluation for Principal (via
  `evaluate_permission`), claim-list check for Ephemeral, tenant-scope
  enforcement, instance-scope enforcement infrastructure.
- **Workflow endpoints (D)**: 13 handlers — template CRUD (create, list,
  read, update, retire) + instance lifecycle (create, list, read,
  history, steps, execute, complete, cancel). Cursor-based pagination.
  `WorkflowEngine` integration with pluggable executor + lowerer.
- **Endpoint-config management (E)**: 6 handlers — create (SCK
  encrypt), list, read metadata, read decrypted (SCK decrypt), rotate,
  retire. No plaintext/ciphertext in logs or metadata reads.
- **Identity CRUD (F)**: 16 handlers — principal (create + list +
  rotate + retire), role (create + list + modify + retire), membership
  (assign + remove), minting authority (create + list + rotate +
  bump-epoch + retire + modify). `pht_` token returned once via
  `Zeroizing` borrow.
- **Token minting (G)**: `POST /v1/tokens/mint` — permission clipping
  against authority envelope, 4 KiB injected-claims cap, lifetime
  validation, instance-scope validation, builder validates kid+issuer
  against verifying-key registry, post-serialization `MAX_TOKEN_BYTES`
  guard.
- **Audit + rate limit + admin (H)**: tenant settings read/update,
  audit-event list (paginated + filterable), in-memory token-bucket
  rate limiting per tenant per endpoint family (429 + Retry-After),
  operator tenant create/suspend/unsuspend.

## [0.0.0]

Name reservation on crates.io. No functional content yet.
