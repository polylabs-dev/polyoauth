# PolyOAuth Cognitive Engine + App Graph Integration Specification

| Field | Value |
|-------|-------|
| **Version** | v0.1.0 |
| **Status** | Draft |
| **Product** | Q OAuth |
| **Lex Namespace** | `polyqlabs/qoauth` |
| **App Graph** | `circuits/fl/qoauth_app_graph.fl` |
| **CE Meaning** | `circuits/fl/qoauth_meaning.fl` |
| **Upstream Dependency** | QKit v0.12.0+, eStream v0.22.0+ (CE Phase 1+) |
| **New Circuits** | 2 (`qoauth_app_graph.fl`, `qoauth_meaning.fl`) |
| **Total Circuits** | 14 (12 existing + 2 new) |

---

## 1. Overview

### Purpose

This specification defines how Q OAuth integrates with the eStream Cognitive Engine and registers its circuit topology as an App Graph. PolyOAuth composes 12 FL circuits (10 modules + 2 graphs) into a Stratum module graph with CE meaning domains tuned for PQ biometric SSO with ML-DSA-87 signed token workloads.

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **100% FastLang** | Both new circuits are `.fl` source, compiled via FLIR codegen |
| **Zero-Linkage Compliant** | CE state isolated via HKDF context `poly-oauth-ce-v1` |
| **Composable** | Composes QKit CE adapter circuits via `EDGE_BRIDGE_TO` |
| **Lex-Isolated** | All CE observations stay within `polyqlabs/qoauth/*` lex namespaces |

---

## 2. App Graph

### Module Inventory (12 modules)

| Module | Circuit File | Partition | SLA |
|--------|-------------|-----------|-----|
| `qoauth_auth` | `qoauth_auth.fl` | Backend | Premium |
| `qoauth_token` | `qoauth_token.fl` | Backend | Premium |
| `qoauth_session` | `qoauth_session.fl` | Backend | Premium |
| `qoauth_oidc` | `qoauth_oidc.fl` | Backend | Premium |
| `qoauth_webauthn` | `qoauth_webauthn.fl` | Backend | Premium |
| `qoauth_risk` | `qoauth_risk.fl` | Backend | Standard |
| `qoauth_admin` | `qoauth_admin.fl` | Backend | Standard |
| `qoauth_metering` | `qoauth_metering.fl` | Shared | Standard |
| `qoauth_platform_health` | `qoauth_platform_health.fl` | Shared | Standard |
| `qoauth_rbac` | `qoauth_rbac.fl` | Shared | Standard |
| `qoauth_identity_graph` | `graphs/qoauth_identity_graph.fl` | Backend | Premium |
| `qoauth_token_dag` | `graphs/qoauth_token_dag.fl` | Backend | Standard |

### Intra-Graph Edges

- `qoauth_auth` → `qoauth_session` (session creation on successful auth)
- `qoauth_auth` → `qoauth_risk` (risk evaluation before granting access)
- `qoauth_auth` → `qoauth_webauthn` (biometric credential verification)
- `qoauth_token` → `qoauth_session` (token bound to session lifecycle)
- `qoauth_token` → `qoauth_token_dag` (token lineage tracking)
- `qoauth_oidc` → `qoauth_token` (ID token issuance after OIDC flow)
- `qoauth_oidc` → `qoauth_identity_graph` (federated identity resolution)
- `qoauth_risk` → `qoauth_rbac` (policy-gated risk score enforcement)
- `qoauth_admin` → `qoauth_rbac` (admin operations require RBAC check)
- `qoauth_metering` → `qoauth_token` (token issuance accounting)
- `qoauth_platform_health` → `qoauth_session` (session health overlay reads)

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
| Panel ID | `qoauth_identity_security_posture` |
| Domain Scope | `identity/auth_patterns`, `identity/session_health` |
| Min Panelists | 3 |
| Specializations | `biometric_auth`, `risk_scoring`, `session_management`, `credential_lifecycle` |
| Calibration Floor | 80% (8000 bps) |
| Review Timeout | 24h |

Advisory triggers: auth failure rate > 5% in 5min window, risk score p99 > 850, session hijack indicator count > 0, SPARK verification failure rate > 0.1%.

### 5.2 Federation Health Panel

| Field | Value |
|-------|-------|
| Panel ID | `qoauth_federation_health` |
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
| PolyPass credential sync | `qoauth_auth` | `qpass/qpass_vault` | `credential_ref`, `rotation_policy`, `breach_status` |
| PolyAuthenticator MFA | `qoauth_webauthn` | `qauthenticator/qauth_ceremony` | `attestation_format`, `credential_id`, `challenge_response` |
| SSO consumer (all products) | `qoauth_oidc` | `qkit/qkit_sso_consumer` | `id_token`, `session_handle`, `scope_grants` |

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
| `qoauth_app_graph` | `circuits/fl/qoauth_app_graph.fl` | 12-module app graph, edges, bridges, golden tests |
| `qoauth_meaning` | `circuits/fl/qoauth_meaning.fl` | 3 CE domains, noise filter, 2 SME panels, golden tests |

### Existing Circuits (12)

| Group | Circuits | Count |
|-------|----------|-------|
| **auth** | `qoauth_auth`, `qoauth_webauthn` | 2 |
| **token** | `qoauth_token`, `qoauth_oidc` | 2 |
| **session** | `qoauth_session`, `qoauth_risk` | 2 |
| **admin** | `qoauth_admin` | 1 |
| **ops** | `qoauth_metering`, `qoauth_platform_health`, `qoauth_rbac` | 3 |
| **graphs** | `qoauth_identity_graph`, `qoauth_token_dag` | 2 |

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
| QKit CE | v0.12.0+ | `qkit_cognitive`, `qkit_noise_filter`, `qkit_sme`, `qkit_app_graph` |
| `qkit_sso_consumer` | existing | Bridge target for cross-product SSO handoff |
| `qkit_identity` | existing | SPARK identity for HKDF derivation |
| `qkit_metering` | existing | Per-invocation metering with differential privacy |
| `qpass_vault` | existing | Bridge target for credential sync |
| `qauth_ceremony` | existing | Bridge target for WebAuthn/FIDO2 MFA |
