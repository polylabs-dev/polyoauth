# Poly OAuth Architecture

**Version**: 1.0
**Last Updated**: February 2026
**Platform**: eStream v0.8.1

---

## Overview

Poly OAuth extends eStream's SPARK Auth into a standards-compliant OAuth 2.0 / OpenID Connect identity provider with post-quantum biometric authentication. It is the first PQ biometric OAuth provider, designed for enterprise single sign-on.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                Enterprise Applications                  │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
│  │ SaaS │  │ Web  │  │ API  │  │Legacy│  │Mobile│   │
│  │ App  │  │ App  │  │ Svc  │  │ App  │  │ App  │   │
│  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘   │
│     │         │         │         │         │        │
│     └─────────┴─────┬───┴─────────┴─────────┘        │
│                      │                                 │
│           OAuth 2.0 / OIDC / SAML 2.0                 │
└──────────────────────┼─────────────────────────────────┘
                       │
┌──────────────────────┼─────────────────────────────────┐
│              Poly OAuth Server                          │
│                      │                                  │
│  ┌───────────────────┴────────────────────────────┐    │
│  │            Authorization Server                 │    │
│  │  OAuth 2.0 | OIDC | SAML 2.0 | SCIM           │    │
│  └───────────────────┬────────────────────────────┘    │
│                      │                                  │
│  ┌───────────────────┴────────────────────────────┐    │
│  │            SPARK Auth Engine                    │    │
│  │  ML-DSA-87 Biometric | Device-Bound Keys       │    │
│  └───────────────────┬────────────────────────────┘    │
│                      │                                  │
│  ┌───────────────────┴────────────────────────────┐    │
│  │            PQ Token Signing                     │    │
│  │  ML-DSA-87 Signed Tokens (PQ-safe JWT)         │    │
│  └───────────────────┬────────────────────────────┘    │
│                      │                                  │
│  ┌───────────────────┴────────────────────────────┐    │
│  │            ESLM Anomaly Detection              │    │
│  │  Login patterns | Device fingerprint | Risk    │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│           eStream Wire Protocol (internal)              │
│           Scatter-stored session state                  │
└─────────────────────────────────────────────────────────┘
                       │
                       v
┌─────────────────────────────────────────────────────────┐
│                    User's Device                         │
│                                                          │
│  SPARK Biometric -> Secure Enclave -> ML-DSA-87 Key    │
│                                                          │
│  (Private key NEVER leaves device)                      │
└─────────────────────────────────────────────────────────┘
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
6. ESLM checks for anomalies (new device? unusual location? unusual time?)
7. If clean: issue authorization code
8. App exchanges code for tokens at /token
9. Tokens signed with ML-DSA-87 (PQ-safe, verifiable by app)
```

### Key Difference from Classical OAuth

| Step | Classical | Poly OAuth |
|------|-----------|-----------|
| Authentication | Password + TOTP | **SPARK biometric** (no password) |
| Token signing | RSA/ECDSA | **ML-DSA-87** (quantum-safe) |
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
  "signature": "<ML-DSA-87 signature>"
}
```

Apps verify tokens using Poly OAuth's published ML-DSA-87 public key (available at JWKS endpoint).

---

## Conditional Access Policies

```yaml
# Enterprise access policies
policies:
  - name: "High-security apps"
    conditions:
      app_tags: [financial, hr, admin]
    require:
      auth_method: spark_biometric  # No fallback
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

Poly OAuth uses ESLM to detect suspicious authentication patterns:

| Signal | What It Detects |
|--------|----------------|
| Device fingerprint | New/unknown device |
| Location | Unusual geographic location |
| Time pattern | Login at unusual time for user |
| Velocity | Impossible travel (login from two distant locations) |
| Behavior | Unusual app access pattern |
| Network | Connection from high-risk network/VPN |

Risk score (0.0-1.0) attached to every authentication. Apps can enforce minimum risk thresholds.

---

## Multi-Organization Support

```
Poly OAuth Server
    |
    +-- Org: Acme Corp
    |   +-- Users: 500
    |   +-- Apps: 25
    |   +-- Policies: enterprise_standard
    |
    +-- Org: Startup Inc
    |   +-- Users: 50
    |   +-- Apps: 10
    |   +-- Policies: business_standard
    |
    +-- Personal (no org)
        +-- Individual Poly Labs users
        +-- Apps: personal Poly suite
```

---

## Enterprise Integration

### Migration from Existing IdP

| Source | Migration Path |
|--------|---------------|
| Okta | SCIM sync -> gradual cutover |
| Azure AD | SAML federation -> SCIM sync -> cutover |
| Google Workspace | OIDC federation -> migration |
| Auth0 | OIDC federation -> migration |
| Ping Identity | SAML federation -> migration |
| OneLogin | SCIM sync -> migration |

### Coexistence

During migration, Poly OAuth can federate with existing IdPs:
```
User -> Poly OAuth -> (if not yet migrated) -> Existing IdP
                    -> (if migrated) -> SPARK biometric
```

---

## ESCIR Circuits

### Auth Circuit

```yaml
escir: "0.8.1"
name: poly-oauth-auth
version: "1.0.0"
lex: polylabs.oauth

stream:
  - topic: "polylabs.oauth.{org_id}.auth.challenge"
    pattern: request_reply
    retention: 5m
    signature_required: true

  - topic: "polylabs.oauth.{org_id}.auth.verify"
    pattern: request_reply
    retention: none
    signature_required: true

  - topic: "polylabs.oauth.{org_id}.session.{session_id}"
    pattern: scatter
    retention: session_ttl
    signature_required: true

  - topic: "polylabs.oauth.{org_id}.audit"
    pattern: scatter
    retention: policy_based
    hash_chain: true
    signature_required: true

fsm:
  initial_state: unauthenticated
  states:
    unauthenticated:
      transitions:
        - event: challenge_issued
          target: challenge_pending
    challenge_pending:
      transitions:
        - event: spark_verified
          target: risk_assessment
        - event: timeout
          target: unauthenticated
    risk_assessment:
      transitions:
        - event: risk_acceptable
          target: authenticated
        - event: risk_high
          target: step_up_required
        - event: risk_blocked
          target: blocked
    authenticated:
      transitions:
        - event: token_issued
          target: active_session
    active_session:
      transitions:
        - event: token_refresh
          target: active_session
        - event: logout
          target: unauthenticated
        - event: session_expired
          target: unauthenticated
```

---

## Why It's the Stickiest Product

Once an enterprise integrates Poly OAuth for SSO:

1. Every employee's biometric is enrolled
2. Every app is configured to use Poly OAuth
3. Conditional access policies are tuned
4. ESLM has learned normal patterns
5. Audit logs are in Poly OAuth format

Switching to a different IdP requires:
- Re-enrolling every employee
- Reconfiguring every app
- Rewriting access policies
- Losing behavioral baselines
- Migrating audit history

The switching cost increases with every employee, app, and day of ESLM learning.

---

## Pricing

| Tier | Users | Features | Price |
|------|-------|----------|-------|
| Self-Service | Up to 100 | OAuth/OIDC, SPARK auth | $2/user/mo |
| Business | Up to 1000 | + SAML, SCIM, conditional access | $5/user/mo |
| Enterprise | Unlimited | + ESLM anomaly, multi-org, custom, SLA | Contract |

---

## Roadmap

### Phase 1: Core (Q3 2026)
- OAuth 2.0 / OIDC provider
- SPARK biometric authentication
- ML-DSA-87 token signing
- Basic admin console
- Self-service tier

### Phase 2: Enterprise (Q4 2026)
- SAML 2.0 support
- SCIM provisioning
- Conditional access policies
- FIDO2/WebAuthn bridge
- Migration tools

### Phase 3: Intelligence (Q1 2027)
- ESLM anomaly detection
- Risk-based authentication
- Multi-organization
- Federation with existing IdPs
- Business tier

### Phase 4: Advanced (2027+)
- PQ certificate authority
- Poly Vault HSM integration (signing keys in hardware)
- Custom auth flows (ESCIR programmable)
- Enterprise tier + SLA

---

## Related Documents

- [polylabs/business/PRODUCT_FAMILY.md] -- Product specifications
- [polylabs/business/STRATEGY.md] -- Overall strategy
