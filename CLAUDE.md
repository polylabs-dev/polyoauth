# Poly OAuth

Post-quantum biometric OAuth/OIDC identity provider built on eStream v0.8.3 and PolyKit v0.3.0.

## Overview

Poly OAuth extends eStream's SPARK Auth into a standards-compliant OAuth 2.0 / OpenID Connect / SAML 2.0 identity provider with PQ biometric authentication — no passwords, no TOTP, no SMS codes. Tokens are ML-DSA-87 signed assertions (not classical JWTs). Sessions are scatter-stored, and ESLM anomaly detection flags suspicious authentication patterns in real time. First PQ biometric OAuth provider. Once an enterprise integrates Poly OAuth SSO, the switching cost is enormous.

## Key Patterns

- **Zero-linkage**: HKDF context `poly-oauth-v1`, lex `esn/global/org/polylabs/oauth`, isolated StreamSight + metering + billing
- **Graph model**: `graph identity_federation` (OrganizationNode, ApplicationNode, UserSessionNode, ServiceProviderNode) with CSR tiered storage
- **DAG model**: `dag token_chain` (TokenNode with ML-DSA-87 signatures, RefreshEdge, RevocationEdge) — acyclic enforcement, tokens are PQ-signed assertions not shared secrets
- **State machine**: `session_lifecycle` (INITIATED → CHALLENGED → AUTHENTICATED → ACTIVE → EXPIRED → REVOKED)
- **Overlays**: session_count, active_users, last_auth_ns, risk_score (identity_federation); validity_status, usage_count (token_chain)
- **ai_feed**: auth_anomaly on identity_federation (unusual login patterns, geo-velocity, device fingerprint drift)
- **Build**: FastLang `.fl` → ESCIR → Rust/WASM → `.escd`
- **RBAC**: eStream `rbac.fl` composed via PolyKit profiles

## Architecture

See `docs/ARCHITECTURE.md` for full specification including graph/DAG constructs, FastLang circuits, standards compliance, ESLM anomaly detection, and enterprise integration design.

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Identity Graph | `circuits/fl/graphs/polyoauth_identity_graph.fl` | Org/app/user/SP federation as typed graph |
| Token DAG | `circuits/fl/graphs/polyoauth_token_dag.fl` | PQ-signed token chain with acyclic enforcement |
| Auth Circuit | `circuits/fl/polyoauth_auth.fl` | SPARK challenge-response, ML-DSA-87 verification |
| Token Circuit | `circuits/fl/polyoauth_token.fl` | PQ-JWT issuance, refresh, revocation |
| Session Circuit | `circuits/fl/polyoauth_session.fl` | Session lifecycle management |
| Risk Circuit | `circuits/fl/polyoauth_risk.fl` | ESLM risk scoring, anomaly evaluation |
| SAML Bridge | `crates/saml-bridge/` | SAML 2.0 for legacy enterprise apps |
| SCIM Provider | `crates/scim/` | User provisioning/deprovisioning |
| OAuth Server | `crates/poly-oauth-server/` | OAuth 2.0 / OIDC / SAML provider |
| Admin Console | `apps/admin/` | Organization and policy management |
| Login UI | `apps/login/` | SPARK biometric login interface |
| SDK | `packages/poly-oauth-sdk/` | Client integration library |

## No REST API (Internal)

Internal management uses eStream Wire Protocol. External OAuth/OIDC/SAML endpoints follow their respective standards (HTTP-based by specification) as the interop layer for third-party applications. SCIM endpoints are also HTTP (required by spec).

## Pricing

| Tier | Users | Price |
|------|-------|-------|
| Self-Service | Up to 100 | $2/user/mo |
| Business | Up to 1000 (+ SAML, SCIM, conditional access) | $5/user/mo |
| Enterprise | Unlimited (+ ESLM anomaly, PQ CA, multi-org) | Contract |

## Platform

- eStream v0.8.3
- PolyKit v0.3.0
- ML-KEM-1024, ML-DSA-87, SHA3-256
- 8-Dimension metering
- Blinded billing tokens
- Compatible with: OAuth 2.0, OIDC, SAML 2.0, SCIM 2.0, FIDO2/WebAuthn

## Cross-Repo Coordination

This repo is part of the [polylabs-dev](https://github.com/polylabs-dev) organization, coordinated through the **AI Toolkit hub** at `toddrooke/ai-toolkit/`.

For cross-repo context, strategic priorities, and the master work queue:
- `toddrooke/ai-toolkit/CLAUDE-CONTEXT.md` — org map and priorities
- `toddrooke/ai-toolkit/scratch/BACKLOG.md` — master backlog
- `toddrooke/ai-toolkit/repos/polylabs-dev.md` — this org's status summary
