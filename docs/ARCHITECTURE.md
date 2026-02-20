# Poly OAuth Architecture

**Version**: 3.0
**Date**: February 2026
**Platform**: eStream v0.8.3
**Upstream**: PolyKit v0.3.0, eStream scatter-cas, graph/DAG constructs
**Build Pipeline**: FastLang (.fl) → ESCIR → Rust/WASM codegen → .escd

---

## Overview

Poly OAuth is the first post-quantum biometric OAuth/OIDC identity provider. It extends eStream's SPARK Auth into a standards-compliant OAuth 2.0 / OpenID Connect / SAML 2.0 identity provider with PQ biometric authentication — no passwords, no TOTP, no SMS codes. Tokens are ML-DSA-87 signed assertions (not classical JWTs), sessions are scatter-stored, and anomaly detection runs via ESLM. Once an enterprise integrates Poly OAuth for SSO, the switching cost is enormous.

### What Changed in v3.0

| Area | v2.0 | v3.0 |
|------|------|------|
| Identity model | Flat user/org store | `graph identity_federation` with typed overlays |
| Token model | ESCIR-signed blob | `dag token_chain` with acyclic enforcement + ML-DSA-87 signing |
| Session state | Implicit | `state_machine session_lifecycle` (INITIATED → REVOKED) |
| Circuit format | ESCIR YAML (`circuit.escir.yaml`) | FastLang `.fl` with PolyKit profiles |
| RBAC | Per-circuit annotations | eStream `rbac.fl` composed via PolyKit |
| Platform | eStream v0.8.1 | eStream v0.8.3 |

---

## Zero-Linkage Privacy

Poly OAuth operates under the Poly Labs zero-linkage privacy architecture:

- **HKDF context**: `poly-oauth-v1` — produces `user_id`, signing key, and encryption key that cannot be correlated with any other Poly product
- **Lex namespace**: `esn/global/org/polylabs/oauth` — completely isolated from other product namespaces
- **StreamSight**: Telemetry stays within `polylabs.oauth.*` lex paths
- **Metering**: Own `metering_graph` instance under `polylabs.oauth.metering` lex
- **Billing**: Tier checked via blinded token status, not cross-product identity

---

## Identity & Authentication

### SPARK Derivation Context

```
SPARK biometric → Secure Enclave/TEE → master_seed (in WASM, never exposed to JS)
                                            │
                                            ▼
                                   HKDF-SHA3-256(master_seed, "poly-oauth-v1")
                                            │
                                            ├── ML-DSA-87 signing key pair
                                            │   (token signing, session management, audit entries)
                                            │
                                            └── ML-KEM-1024 encryption key pair
                                                (session key wrapping, cross-org federation)
```

### User Identity

```
user_id = SHA3-256(spark_ml_dsa_87_public_key)[0..16]   # 16-byte truncated hash
```

All stream topics, organization membership, and session state reference this SPARK-derived `user_id`. There are no usernames, emails, or phone numbers at the identity layer. This `user_id` is unique to Poly OAuth and cannot be linked to identities in other Poly products.

### No Passwords

| Traditional OAuth/IdP | Poly OAuth |
|-----------------------|-----------|
| Password + TOTP → session token | SPARK biometric → Secure Enclave → ML-DSA-87 challenge-response |
| Phishable (password to steal) | Cannot be phished (biometric, not typed) |
| Keyloggable (typed input) | Cannot be keylogged (hardware biometric) |
| SIM-swappable (SMS 2FA) | Device-bound (no SMS, no TOTP) |
| Brute-forceable (entropy-limited) | Hardware-enforced rate limiting |

---

## Core Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Enterprise Applications                             │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐        │
│  │ SaaS │  │ Web  │  │ API  │  │Legacy│  │Mobile│  │ CLI  │        │
│  │ App  │  │ App  │  │ Svc  │  │ App  │  │ App  │  │ Tool │        │
│  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘        │
│     │         │         │         │         │         │              │
│     └─────────┴─────┬───┴─────────┴─────────┴─────────┘              │
│                      │                                                │
│        OAuth 2.0 / OIDC / SAML 2.0 / SCIM / FIDO2                   │
└──────────────────────┼────────────────────────────────────────────────┘
                       │
┌──────────────────────┼────────────────────────────────────────────────┐
│               Poly OAuth Server                                        │
│                      │                                                 │
│  ┌───────────────────┴──────────────────────────────────────────────┐ │
│  │  FastLang Circuits (WASM via .escd)                                │ │
│  │                                                                    │ │
│  │  polyoauth_auth.fl │ polyoauth_token.fl │ polyoauth_session.fl    │ │
│  │  polyoauth_saml.fl │ polyoauth_scim.fl  │ polyoauth_metering.fl   │ │
│  │  (all ML-DSA-87 signed .escd packages, StreamSight-annotated)     │ │
│  └──────────────────────────┬───────────────────────────────────────┘ │
│                              │                                         │
│  ┌──────────────────────────┴───────────────────────────────────────┐ │
│  │  Graph/DAG Layer (WASM, backed by scatter-cas)                     │ │
│  │                                                                    │ │
│  │  graph identity_federation — org/app/user/SP as federated graph   │ │
│  │  dag   token_chain         — PQ-signed token DAG (not JWT)        │ │
│  │  graph metering_graph      — per-app 8D usage (from PolyKit)      │ │
│  │  graph user_graph          — per-product identity (from PolyKit)   │ │
│  └──────────────────────────┬───────────────────────────────────────┘ │
│                              │                                         │
│  ┌──────────────────────────┴───────────────────────────────────────┐ │
│  │  ESLM Anomaly Detection Engine                                     │ │
│  │  Login patterns │ Geo-velocity │ Device fingerprint │ Risk score  │ │
│  └──────────────────────────┬───────────────────────────────────────┘ │
│                              │                                         │
│  ┌──────────────────────────┴───────────────────────────────────────┐ │
│  │  eStream SDK (lattice-hosted)                                      │ │
│  │  Wire protocol only: UDP :5000 / WebTransport :4433               │ │
│  └──────────────────────────┬───────────────────────────────────────┘ │
└──────────────────────────────┼────────────────────────────────────────┘
                               │
                        eStream Wire Protocol (QUIC/UDP)
                               │
┌──────────────────────────────┼────────────────────────────────────────┐
│                        eStream Network                                 │
│                               │                                        │
│  ┌────────────────────────────┴─────────────────────────────────────┐ │
│  │  Lattice-Hosted Circuits                                           │ │
│  │                                                                    │ │
│  │  polyoauth_session_sync.fl │ polyoauth_federation_relay.fl        │ │
│  │  polyoauth_metering.fl     │ scatter-cas runtime                  │ │
│  └────┬───────────┬──────────────┬──────────────────────────────────┘ │
│       │           │              │                                     │
│  ┌────┴──────────────────────────────────────────────────────────┐   │
│  │              Scatter Storage Layer (via scatter-cas)              │   │
│  │  AWS │ GCP │ Azure │ Cloudflare │ Hetzner │ Self-host           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         User's Device                                   │
│                                                                         │
│  SPARK Biometric → Secure Enclave → ML-DSA-87 Key Pair                │
│                                                                         │
│  (Private key NEVER leaves device)                                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Authentication Flow

### OAuth 2.0 Authorization Code Flow (with SPARK)

```
1. App redirects user to Poly OAuth /authorize
2. Poly OAuth displays QR code (or pushes to known device)
3. User's device: SPARK biometric prompt (face/fingerprint)
4. Device signs challenge with ML-DSA-87 private key
5. Poly OAuth verifies ML-DSA-87 signature
6. ESLM evaluates risk (new device? unusual location? geo-velocity?)
7. If risk acceptable: issue authorization code
8. App exchanges code for tokens at /token
9. Tokens are PQ-signed assertions (ML-DSA-87), not shared secrets
```

### Key Difference from Classical OAuth

| Step | Classical | Poly OAuth |
|------|-----------|-----------|
| Authentication | Password + TOTP | **SPARK biometric** (no password) |
| Token format | RSA/ECDSA-signed JWT | **ML-DSA-87 signed PQ-JWT** (quantum-safe assertion) |
| Token nature | Shared secret (bearer) | **PQ-signed assertion** (verifiable, not a secret) |
| Session storage | Server database | **Scatter-stored** (no single server) |
| MFA | SMS/TOTP (phishable) | **Device-bound** (unphishable) |
| Anomaly detection | Rule-based | **ESLM** (AI-powered) |

---

## Standards Compliance

### OAuth 2.0
- Authorization Code flow (with PKCE)
- Client Credentials flow
- Device Authorization flow (for IoT/CLI)
- Refresh token rotation

### OpenID Connect (OIDC)
- ID tokens (ML-DSA-87 signed)
- UserInfo endpoint
- Discovery (.well-known/openid-configuration)
- Dynamic client registration

### SAML 2.0
- SP-initiated SSO
- IdP-initiated SSO
- Assertion signing (ML-DSA-87)
- Single Logout (SLO)

### SCIM 2.0
- User provisioning/deprovisioning
- Group management
- Bulk operations
- Event notifications (push)

### FIDO2/WebAuthn Bridge
- Poly OAuth accepts FIDO2/WebAuthn as a secondary auth method
- SPARK biometric is primary; hardware keys as backup
- Bridges SPARK to WebAuthn for apps that already support it

---

## Graph/DAG Constructs

### Identity Federation Graph (`polyoauth_identity_graph.fl`)

The identity model is a typed graph. Organizations, applications, user sessions, and service providers are nodes; authorization relationships, membership, and sessions are edges. Overlays provide real-time federation state (session counts, active users, risk scores) without mutating the base graph.

```fastlang
type OrganizationNode = struct {
    org_id: bytes(16),
    name: bytes(256),
    domain: bytes(256),
    tier: u8,
    saml_metadata_hash: bytes(32),
    scim_endpoint_hash: bytes(32),
    created_at: u64,
    updated_at: u64,
}

type ApplicationNode = struct {
    app_id: bytes(16),
    org_id: bytes(16),
    name: bytes(256),
    redirect_uris_hash: bytes(32),
    grant_types: u16,
    client_type: u8,
    tags: bytes(128),
    created_at: u64,
}

type UserSessionNode = struct {
    session_id: bytes(16),
    user_id: bytes(16),
    device_fingerprint_hash: bytes(32),
    geo_hash: bytes(8),
    auth_method: u8,
    risk_score_at_auth: u16,
    created_at: u64,
    expires_at: u64,
}

type ServiceProviderNode = struct {
    sp_id: bytes(16),
    org_id: bytes(16),
    protocol: u8,
    metadata_hash: bytes(32),
    assertion_consumer_url_hash: bytes(32),
    created_at: u64,
}

type AuthorizesEdge = struct {
    scope: bytes(256),
    granted_at: u64,
    granted_by: bytes(16),
    expires_at: u64,
    conditional_policy_hash: bytes(32),
}

type BelongsToEdge = struct {
    role: u8,
    joined_at: u64,
    provisioned_via: u8,
}

type SessionEdge = struct {
    auth_timestamp_ns: u64,
    device_id: bytes(16),
    ip_hash: bytes(32),
    user_agent_hash: bytes(32),
}

graph identity_federation {
    node OrganizationNode
    node ApplicationNode
    node UserSessionNode
    node ServiceProviderNode
    edge AuthorizesEdge
    edge BelongsToEdge
    edge SessionEdge

    overlay session_count: u64 bitmask delta_curate
    overlay active_users: u64 bitmask delta_curate
    overlay last_auth_ns: u64 bitmask delta_curate
    overlay risk_score: u16 curate delta_curate

    storage csr {
        hot @bram,
        warm @ddr,
        cold @nvme,
    }

    ai_feed auth_anomaly

    observe identity_federation: [session_count, active_users, risk_score] threshold: {
        anomaly_score 0.85
        baseline_window 120
    }
}

series identity_series: identity_federation
    merkle_chain true
    lattice_imprint true
    witness_attest true
```

The `ai_feed auth_anomaly` drives ESLM-powered detection of unusual login patterns, geo-velocity violations (impossible travel), and device fingerprint drift. Risk scores are computed per-session and attached as overlays.

Key circuits: `create_org`, `register_app`, `create_session`, `register_sp`, `authorize_app`, `provision_user`, `evaluate_risk`.

### Token Chain DAG (`polyoauth_token_dag.fl`)

Tokens are modeled as a DAG, not as opaque blobs. Each token is an ML-DSA-87 signed assertion (not a shared secret). Refresh and revocation are explicit edges. The DAG enforces acyclicity — a revoked token cannot be un-revoked, and refresh chains are strictly forward.

```fastlang
type TokenNode = struct {
    token_id: bytes(16),
    session_id: bytes(16),
    user_id: bytes(16),
    app_id: bytes(16),
    token_type: u8,
    scope: bytes(256),
    issued_at: u64,
    expires_at: u64,
    signature: bytes(4627),
    signing_key_id: bytes(32),
}

type RefreshEdge = struct {
    refreshed_at: u64,
    new_token_id: bytes(16),
    rotation_count: u32,
}

type RevocationEdge = struct {
    revoked_at: u64,
    revoked_by: bytes(16),
    reason: u8,
}

dag token_chain {
    node TokenNode
    edge RefreshEdge
    edge RevocationEdge

    enforce acyclic
    sign ml_dsa_87

    overlay validity_status: u8 curate delta_curate
    overlay usage_count: u64 bitmask delta_curate

    storage csr {
        hot @bram,
        warm @ddr,
        cold @nvme,
    }

    observe token_chain: [validity_status, usage_count] threshold: {
        anomaly_score 0.9
        baseline_window 60
    }
}

series token_series: token_chain
    merkle_chain true
    lattice_imprint true
    witness_attest true
```

Key circuits: `issue_token`, `refresh_token`, `revoke_token`, `verify_token`, `introspect_token`.

### Session Lifecycle State Machine (`polyoauth_session_lifecycle.fl`)

Every authentication session follows a strict lifecycle with anomaly detection on state transitions.

```fastlang
state_machine session_lifecycle {
    initial INITIATED
    persistence wal
    terminal [EXPIRED, REVOKED]
    li_anomaly_detection true

    INITIATED -> CHALLENGED when challenge_issued guard device_registered
    CHALLENGED -> AUTHENTICATED when spark_verified guard signature_valid
    CHALLENGED -> INITIATED when challenge_timeout
    AUTHENTICATED -> ACTIVE when risk_acceptable guard risk_below_threshold
    AUTHENTICATED -> CHALLENGED when risk_step_up guard risk_above_threshold
    AUTHENTICATED -> REVOKED when risk_blocked guard risk_critical
    ACTIVE -> ACTIVE when token_refreshed guard refresh_valid
    ACTIVE -> EXPIRED when session_timeout
    ACTIVE -> REVOKED when user_logout
    ACTIVE -> REVOKED when admin_revoked
}
```

State transitions update the `session_count`, `active_users`, and `risk_score` overlays on `identity_federation`. The `observe` block flags anomalies (e.g., mass session creation, unusual geo-velocity patterns, simultaneous sessions from incompatible locations).

---

## PQ Token Format

### ML-DSA-87 Signed Token (PQ-JWT)

```json
{
  "header": {
    "alg": "ML-DSA-87",
    "typ": "PQ-JWT",
    "kid": "spark:did:polyoauth:signing-key-2026"
  },
  "payload": {
    "iss": "https://auth.polylabs.dev",
    "sub": "spark:did:alice",
    "aud": "client-app-id",
    "exp": 1740000000,
    "iat": 1739996400,
    "auth_method": "spark_biometric",
    "device_id": "spark:device:alice-iphone",
    "risk_score": 0.02,
    "roles": ["admin", "developer"],
    "org": "spark:org:acme-corp"
  },
  "signature": "<ML-DSA-87 signature (4627 bytes)>"
}
```

The token is a PQ-signed assertion — it proves the issuer attested the claims. It is not a shared secret. Apps verify tokens using Poly OAuth's published ML-DSA-87 public key (available at the JWKS endpoint with PQ algorithm negotiation).

---

## Conditional Access Policies

```yaml
policies:
  - name: "High-security apps"
    conditions:
      app_tags: [financial, hr, admin]
    require:
      auth_method: spark_biometric
      device_compliance: managed
      risk_score_max: 0.1
      location: [office_ips, vpn]

  - name: "Standard apps"
    conditions:
      app_tags: [productivity, communication]
    require:
      auth_method: spark_biometric
      risk_score_max: 0.5

  - name: "Block on anomaly"
    conditions:
      risk_score_min: 0.8
    action: block_and_notify_admin
```

---

## ESLM Anomaly Detection

The `ai_feed auth_anomaly` on `identity_federation` drives real-time risk assessment:

| Signal | What It Detects |
|--------|----------------|
| Device fingerprint | New/unknown device, fingerprint drift from baseline |
| Location | Unusual geographic location for user |
| Geo-velocity | Impossible travel (login from distant locations in short time) |
| Time pattern | Login at unusual time for user's baseline |
| Behavior | Unusual app access pattern, scope escalation |
| Network | Connection from high-risk network, TOR, known proxy |

Risk score (0.0–1.0) attached to every authentication via the `risk_score` overlay. Apps can enforce minimum risk thresholds via conditional access policies.

---

## scatter-cas Integration

Poly OAuth builds on eStream's `scatter-cas` runtime for session and token storage. Classification-driven k-of-n erasure coding distributes encrypted state across providers.

### Storage Layers

```
scatter-cas ObjectStore
  ├── PackStore      (local ESLite, offline cache)
  └── ScatterStore   (distributed k-of-n erasure coded)
        ├── k-of-n scatter per data classification:
        │   SESSION:       3-of-5, 2+ jurisdictions
        │   TOKEN:         3-of-5, 2+ jurisdictions
        │   AUDIT_LOG:     5-of-7, 3+ jurisdictions
        │   ORG_CONFIG:    5-of-7, 3+ jurisdictions
        └── Providers: AWS, GCP, Azure, Cloudflare, Hetzner, self-host
```

---

## FastLang Circuits

All circuits are written in FastLang `.fl` using PolyKit profiles. The build pipeline is:

```bash
estream-dev build-wasm-client --from-fl circuits/fl/ --sign key.pem --enforce-budget
```

### Client-Side Circuits (compiled to `.escd` WASM)

| Circuit | File | Purpose | Size Budget |
|---------|------|---------|-------------|
| `polyoauth_auth` | `polyoauth_auth.fl` | SPARK challenge-response, signature verification | ≤128 KB |
| `polyoauth_token` | `polyoauth_token.fl` | PQ-JWT issuance, refresh, revocation | ≤128 KB |
| `polyoauth_session` | `polyoauth_session.fl` | Session lifecycle management | ≤128 KB |
| `polyoauth_risk` | `polyoauth_risk.fl` | Risk scoring, anomaly evaluation | ≤128 KB |
| `polyoauth_admin` | `polyoauth_admin.fl` | Org/app management, policy CRUD | ≤128 KB |

All circuits compose PolyKit:
```fastlang
circuit polyoauth_auth(user_id: bytes(16), challenge: bytes(64), signature: bytes(4627)) -> bool
    profile poly_framework_sensitive
    composes: [polykit_identity, polykit_metering, polykit_rbac]
    lex esn/global/org/polylabs/oauth/auth
    constant_time true
    observe metrics: [auth_ops, session_count, latency_ns]
{
    ml_dsa_87_verify(user_id, challenge, signature)
}
```

### Server-Side Circuits (lattice-hosted)

| Circuit | File | Purpose |
|---------|------|---------|
| `polyoauth_session_sync` | `polyoauth_session_sync.fl` | Session scatter policy enforcement, cross-device sync |
| `polyoauth_federation_relay` | `polyoauth_federation_relay.fl` | Cross-org federation, SAML assertion relay |
| `polyoauth_metering` | `polyoauth_metering.fl` | Per-product 8D metering (isolated) |
| `polyoauth_scim` | `polyoauth_scim.fl` | SCIM provisioning lifecycle |

---

## SAML 2.0 Bridge

For legacy enterprise applications that require SAML:

```
SP (legacy app) → SAML AuthnRequest → Poly OAuth SAML endpoint
                                            │
                                            ▼
                                      SPARK biometric auth
                                            │
                                            ▼
                                      SAML Response with ML-DSA-87 signed assertion
                                            │
                                            ▼
                                      SP validates assertion (PQ-safe)
```

The SAML bridge translates between SAML 2.0 XML assertions and Poly OAuth's internal graph model. Assertions are signed with ML-DSA-87 instead of RSA/ECDSA.

---

## SCIM Provisioning

SCIM 2.0 endpoints provide automated user lifecycle management:

```
HR System / IdP → SCIM API → Poly OAuth
                                  │
                                  ├── Create user → BelongsToEdge in identity_federation
                                  ├── Update user → Overlay updates
                                  ├── Deactivate → session_lifecycle → REVOKED (all sessions)
                                  └── Delete → Purge from identity_federation graph
```

SCIM operations are exposed as standard HTTP endpoints (required by specification) while internally executing as graph mutations via the `polyoauth_scim.fl` circuit.

---

## StreamSight Observability

Per-product isolated telemetry within the `polylabs.oauth.*` lex namespace.

### Telemetry Stream Paths

```
lex://estream/apps/polylabs.oauth/telemetry
lex://estream/apps/polylabs.oauth/telemetry/sli
lex://estream/apps/polylabs.oauth/metrics/baseline
lex://estream/apps/polylabs.oauth/metrics/deviations
lex://estream/apps/polylabs.oauth/incidents
lex://estream/apps/polylabs.oauth/eslm/auth_anomaly
```

No telemetry path references any other Poly product. StreamSight baseline gate learns per-operation latency distributions and flags deviations.

---

## Console Widgets

| Widget ID | Category | Description |
|-----------|----------|-------------|
| `polyoauth-auth-activity` | observability | Authentication rate, success/failure breakdown |
| `polyoauth-session-gauge` | observability | Active sessions, session lifecycle distribution |
| `polyoauth-risk-heatmap` | observability | Risk score distribution across orgs/apps |
| `polyoauth-deviation-feed` | observability | StreamSight baseline deviation feed |
| `polyoauth-anomaly-feed` | observability | ESLM auth_anomaly real-time detections |
| `polyoauth-token-lifecycle` | governance | Token issuance/refresh/revocation rates |
| `polyoauth-org-overview` | governance | Org membership, app count, policy compliance |
| `polyoauth-scim-activity` | governance | SCIM provisioning events and sync status |

---

## Enterprise

### Migration from Existing IdP

| Source | Migration Path |
|--------|---------------|
| Okta | SCIM sync → gradual cutover |
| Azure AD | SAML federation → SCIM sync → cutover |
| Google Workspace | OIDC federation → migration |
| Auth0 | OIDC federation → migration |
| Ping Identity | SAML federation → migration |
| OneLogin | SCIM sync → migration |

During migration, Poly OAuth can federate with existing IdPs:
```
User → Poly OAuth → (if not yet migrated) → Existing IdP
                   → (if migrated) → SPARK biometric
```

### Lex Bridge (Opt-In)

Enterprise admins can opt-in to cross-product visibility via an explicit lex bridge between `esn/global/org/polylabs/oauth` and the enterprise admin namespace. The bridge is gated by **k-of-n admin witness attestation** and is revocable.

```
Enterprise admin namespace ←──lex bridge──→ polylabs.oauth.{org_id}.*
                              │
                              └── gated by k-of-n witness attestation
                              └── org-level aggregates only (no individual session data)
                              └── revocable
```

Even with the bridge, individual user session data and authentication events are never exposed — only org-level aggregates (auth rate, anomaly count, compliance posture) flow across the bridge.

---

## Why It's the Stickiest Product

Once an enterprise integrates Poly OAuth for SSO:

1. Every employee's biometric is enrolled
2. Every app is configured to use Poly OAuth (OAuth/OIDC/SAML)
3. Conditional access policies are tuned per app tag
4. ESLM has learned normal authentication patterns (baseline window)
5. SCIM provisioning is wired to HR systems
6. Audit logs are in Poly OAuth format (merkle-chained, witness-attested)

Switching to a different IdP requires:
- Re-enrolling every employee with a new auth method
- Reconfiguring every application's SSO integration
- Rewriting all conditional access policies
- Losing behavioral baselines (ESLM learning)
- Migrating audit history (merkle chain breaks)
- Re-wiring SCIM to a new provider

The switching cost increases with every employee, app, policy, and day of ESLM learning.

---

## Pricing

| Tier | Users | Features | Price |
|------|-------|----------|-------|
| Self-Service | Up to 100 | OAuth/OIDC, SPARK auth, basic admin | $2/user/mo |
| Business | Up to 1000 | + SAML 2.0, SCIM, conditional access, FIDO2 bridge | $5/user/mo |
| Enterprise | Unlimited | + ESLM anomaly, multi-org, PQ CA, custom policies, SLA | Contract |

Tier enforcement via PolyKit `metering_graph` + `subscription_lifecycle` state machine. Billing uses blinded payment tokens — backend cannot correlate which SPARK identity subscribes to which tier.

---

## Directory Structure

```
polyoauth/
├── circuits/fl/
│   ├── polyoauth_auth.fl
│   ├── polyoauth_token.fl
│   ├── polyoauth_session.fl
│   ├── polyoauth_risk.fl
│   ├── polyoauth_admin.fl
│   ├── polyoauth_saml.fl
│   ├── polyoauth_scim.fl
│   ├── polyoauth_session_sync.fl
│   ├── polyoauth_federation_relay.fl
│   ├── polyoauth_metering.fl
│   └── graphs/
│       ├── polyoauth_identity_graph.fl
│       └── polyoauth_token_dag.fl
├── crates/
│   ├── poly-oauth-server/
│   ├── saml-bridge/
│   └── scim/
├── apps/
│   ├── admin/             Organization management console
│   └── login/             SPARK biometric login UI
├── packages/
│   └── poly-oauth-sdk/    Client integration library
├── apps/console/
│   └── src/widgets/
├── docs/
│   └── ARCHITECTURE.md
├── CLAUDE.md
└── package.json
```

---

## Roadmap

### Phase 1: Core OAuth (Q3 2026)
- `identity_federation` graph with typed overlays
- `token_chain` DAG with ML-DSA-87 signing
- `session_lifecycle` state machine
- OAuth 2.0 / OIDC provider (Authorization Code + PKCE, Client Credentials)
- SPARK biometric authentication (`poly-oauth-v1`)
- PQ-JWT token issuance and verification
- Basic admin console
- StreamSight L0 metrics
- Self-Service tier

### Phase 2: Enterprise Protocols (Q4 2026)
- SAML 2.0 bridge (SP-initiated, IdP-initiated, SLO)
- SCIM 2.0 provisioning
- FIDO2/WebAuthn bridge
- Conditional access policies
- Migration tools (federation with existing IdPs)
- Business tier

### Phase 3: Intelligence (Q1 2027)
- ESLM anomaly detection (`ai_feed auth_anomaly`)
- Risk-based authentication with geo-velocity
- Multi-organization support
- Device Authorization flow (IoT/CLI)
- Console widgets (8 widgets)

### Phase 4: Advanced (2027+)
- PQ certificate authority (ML-DSA-87 CA for enterprise PKI)
- Lex bridge for enterprise cross-product visibility (opt-in, k-of-n gated)
- Poly Vault HSM integration (signing keys in hardware)
- Custom auth flows (ESCIR programmable)
- Enterprise tier + SLA
- ESN-AI optimization recommendations

---

## Related Documents

- [polylabs/business/PRODUCT_FAMILY.md] — Product specifications
- [polylabs/business/STRATEGY.md] — Overall strategy
