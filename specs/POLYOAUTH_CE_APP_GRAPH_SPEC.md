# PolyOAuth Cognitive Engine + App Graph Integration Specification

| Field | Value |
|-------|-------|
| **Version** | v0.1.0 |
| **Status** | Draft |
| **Product** | Poly OAuth |
| **Lex Namespace** | `polylabs/polyoauth` |
| **App Graph** | `circuits/fl/polyoauth_app_graph.fl` |
| **CE Meaning** | `circuits/fl/polyoauth_meaning.fl` |
| **Upstream Dependency** | PolyKit v0.12.0+, eStream v0.22.0+ (CE Phase 1+) |
| **New Circuits** | 2 (`polyoauth_app_graph.fl`, `polyoauth_meaning.fl`) |
| **Total Circuits** | 14 (12 existing + 2 new) |

---

## 1. Overview

### Purpose

This specification defines how Poly OAuth integrates with the eStream Cognitive Engine and registers its circuit topology as an App Graph. PolyOAuth composes 12 FL circuits (10 modules + 2 graphs) into a Stratum module graph with CE meaning domains tuned for PQ biometric SSO with ML-DSA-87 signed token workloads.

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **100% FastLang** | Both new circuits are `.fl` source, compiled via FLIR codegen |
| **Zero-Linkage Compliant** | CE state isolated via HKDF context `poly-oauth-ce-v1` |
| **Composable** | Composes PolyKit CE adapter circuits via `EDGE_BRIDGE_TO` |
| **Lex-Isolated** | All CE observations stay within `polylabs/polyoauth/*` lex namespaces |

---

## 2. App Graph

### Module Inventory (12 modules)

| Module | Circuit File | Partition | SLA |
|--------|-------------|-----------|-----|
| `polyoauth_auth` | `polyoauth_auth.fl` | Backend | Premium |
| `polyoauth_token` | `polyoauth_token.fl` | Backend | Premium |
| `polyoauth_session` | `polyoauth_session.fl` | Backend | Premium |
| `polyoauth_oidc` | `polyoauth_oidc.fl` | Backend | Premium |
| `polyoauth_webauthn` | `polyoauth_webauthn.fl` | Backend | Premium |
| `polyoauth_risk` | `polyoauth_risk.fl` | Backend | Standard |
| `polyoauth_admin` | `polyoauth_admin.fl` | Backend | Standard |
| `polyoauth_metering` | `polyoauth_metering.fl` | Shared | Standard |
| `polyoauth_platform_health` | `polyoauth_platform_health.fl` | Shared | Standard |
| `polyoauth_rbac` | `polyoauth_rbac.fl` | Shared | Standard |
| `polyoauth_identity_graph` | `graphs/polyoauth_identity_graph.fl` | Backend | Premium |
| `polyoauth_token_dag` | `graphs/polyoauth_token_dag.fl` | Backend | Standard |

### Intra-Graph Edges

- `polyoauth_auth` → `polyoauth_session` (session creation on successful auth)
- `polyoauth_auth` → `polyoauth_risk` (risk evaluation before granting access)
- `polyoauth_auth` → `polyoauth_webauthn` (biometric credential verification)
- `polyoauth_token` → `polyoauth_session` (token bound to session lifecycle)
- `polyoauth_token` → `polyoauth_token_dag` (token lineage tracking)
- `polyoauth_oidc` → `polyoauth_token` (ID token issuance after OIDC flow)
- `polyoauth_oidc` → `polyoauth_identity_graph` (federated identity resolution)
- `polyoauth_risk` → `polyoauth_rbac` (policy-gated risk score enforcement)
- `polyoauth_admin` → `polyoauth_rbac` (admin operations require RBAC check)
- `polyoauth_metering` → `polyoauth_token` (token issuance accounting)
- `polyoauth_platform_health` → `polyoauth_session` (session health overlay reads)

---

## 3. CE Meaning Domains

### 3.1 `identity/auth_patterns`

Tracks authentication dynamics to surface login anomalies and risk scoring insights.

| Signal | Description | Crystallization Threshold |
|--------|-------------|--------------------------|
| Login frequency distribution | Median, p95, p99 login latency per user cohort | 75 |
| Risk score trends | Step-up auth trigger rate, adaptive risk calibration drift | 75 |
| Credential rotation health | SPARK key rotation cadence, stale credential detection | 70 |

### 3.2 `identity/session_health`

Monitors session lifecycle and timeout patterns for security posture.

| Signal | Description | Crystallization Threshold |
|--------|-------------|--------------------------|
| Session duration distribution | Active vs idle ratio, premature expiry rate, max lifetime compliance | 80 |
| Timeout pattern anomalies | Unusual session extension requests, concurrent session spikes | 85 |
| Token refresh cadence | Refresh-to-access ratio, silent refresh success rate, token reuse detection | 80 |

### 3.3 `identity/federation_coverage`

Aggregate OIDC provider usage and token exchange metrics for federation health.

| Signal | Description | Crystallization Threshold |
|--------|-------------|--------------------------|
| Provider usage distribution | Active IdP breakdown, provider failure rates, discovery endpoint health | 65 |
| Token exchange volume | Cross-product SSO handoff rate, federation grant success ratio | 65 |
| WebAuthn adoption | Passkey registration rate, biometric vs PIN fallback ratio | 60 |

---

## 4. Noise Filter

### Suppression Rules

| Suppressed Event | Reason |
|-----------------|--------|
| Token refresh cycles | High-frequency, expected lifecycle event (silent refresh every 5-15min) |
| Session keepalives | Heartbeat pings, no CE value |
| OIDC discovery re-fetches | Cached config revalidation, not user activity |
| CORS preflight probes | Infrastructure handshake, not authentication events |

### Signal Amplification

| Amplified Event | Reason |
|----------------|--------|
| Auth failures | Immediate security concern — brute force, credential stuffing, SPARK verification failure |
| Risk score spikes | Adaptive risk engine detected anomalous login context (geo, device, velocity) |
| Token revocation bursts | Mass revocation indicates compromise or admin emergency action |
| Session hijack indicators | Token reuse from different origin, concurrent conflicting sessions |

### Configuration

- Dedup window: 500ms (production), 0ms (development)
- Rate limit: 50 observations/s per circuit (production)
- Min signal confidence: 60%

---

## 5. SME Panels

### 5.1 Identity Security Posture Panel

| Field | Value |
|-------|-------|
| Panel ID | `polyoauth_identity_security_posture` |
| Domain Scope | `identity/auth_patterns`, `identity/session_health` |
| Min Panelists | 3 |
| Specializations | `biometric_auth`, `risk_scoring`, `session_management`, `credential_lifecycle` |
| Calibration Floor | 80% (8000 bps) |
| Review Timeout | 24h |

Advisory triggers: auth failure rate > 5% in 5min window, risk score p99 > 850, session hijack indicator count > 0, SPARK verification failure rate > 0.1%.

### 5.2 Federation Health Panel

| Field | Value |
|-------|-------|
| Panel ID | `polyoauth_federation_health` |
| Domain Scope | `identity/federation_coverage` |
| Min Panelists | 3 |
| Specializations | `oidc_protocol`, `token_exchange`, `provider_integration`, `webauthn_ceremony` |
| Calibration Floor | 75% (7500 bps) |
| Review Timeout | 12h |

Advisory triggers: IdP failure rate > 2% per provider, token exchange rejection > 5%, discovery endpoint unreachable > 60s, WebAuthn ceremony timeout > 30s.

---

## 6. Bridge Edges

### Cross-Product Bridges

| Bridge | Source Module | Target | Shared Fields |
|--------|-------------|--------|---------------|
| PolyPass credential sync | `polyoauth_auth` | `polypass/polypass_vault` | `credential_ref`, `rotation_policy`, `breach_status` |
| PolyAuthenticator MFA | `polyoauth_webauthn` | `polyauthenticator/polyauth_ceremony` | `attestation_format`, `credential_id`, `challenge_response` |
| SSO consumer (all products) | `polyoauth_oidc` | `polykit/polykit_sso_consumer` | `id_token`, `session_handle`, `scope_grants` |

---

## 7. Strategic Grant Config

| Grant | Scope |
|-------|-------|
| eStream Platform | CE primitives (SSM hidden state, observation ingestion, cortex advisors), Stratum graph storage, FLIR codegen |
| Paragon Bridge | Future bridge to Paragon compliance framework for regulated identity and authentication use cases |

---

## 8. Circuit Inventory

### New CE Circuits (2)

| Circuit | File | Description |
|---------|------|-------------|
| `polyoauth_app_graph` | `circuits/fl/polyoauth_app_graph.fl` | 12-module app graph, edges, bridges, golden tests |
| `polyoauth_meaning` | `circuits/fl/polyoauth_meaning.fl` | 3 CE domains, noise filter, 2 SME panels, golden tests |

### Existing Circuits (12)

| Group | Circuits | Count |
|-------|----------|-------|
| **auth** | `polyoauth_auth`, `polyoauth_webauthn` | 2 |
| **token** | `polyoauth_token`, `polyoauth_oidc` | 2 |
| **session** | `polyoauth_session`, `polyoauth_risk` | 2 |
| **admin** | `polyoauth_admin` | 1 |
| **ops** | `polyoauth_metering`, `polyoauth_platform_health`, `polyoauth_rbac` | 3 |
| **graphs** | `polyoauth_identity_graph`, `polyoauth_token_dag` | 2 |

### Total: 14 Circuits

| Category | Count |
|----------|-------|
| Existing (pre-CE) | 12 |
| New CE circuits | 2 |
| **Total** | **14** |

---

## 9. Dependencies

| Dependency | Version | Usage |
|------------|---------|-------|
| eStream CE | v0.22.0+ Phase 1+ | SSM hidden state, observation ingestion, cortex advisors |
| PolyKit CE | v0.12.0+ | `polykit_cognitive`, `polykit_noise_filter`, `polykit_sme`, `polykit_app_graph` |
| `polykit_sso_consumer` | existing | Bridge target for cross-product SSO handoff |
| `polykit_identity` | existing | SPARK identity for HKDF derivation |
| `polykit_metering` | existing | Per-invocation metering with differential privacy |
| `polypass_vault` | existing | Bridge target for credential sync |
| `polyauth_ceremony` | existing | Bridge target for WebAuthn/FIDO2 MFA |
