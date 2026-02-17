# Poly OAuth

Post-quantum biometric OAuth/OIDC identity provider built on eStream v0.8.1 SPARK Auth.

## Overview

Poly OAuth extends SPARK Auth into a standards-compliant OAuth 2.0 / OpenID Connect identity provider. Enterprise applications integrate with Poly OAuth for single sign-on using PQ biometric authentication -- no passwords, no TOTP, no SMS codes.

## Architecture

```
Any Enterprise App
    |
    +-- OAuth 2.0 / OIDC redirect
    |
    v
Poly OAuth Server
    |
    +-- SPARK Auth (ML-DSA-87 biometric on user's device)
    +-- ML-DSA-87 signed tokens (PQ-safe JWT equivalent)
    +-- Session state scatter-stored
    +-- ESLM anomaly detection
    |
    v
Token issued -> App authenticates user
```

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| OAuth Server | crates/poly-oauth-server/ | OAuth 2.0 / OIDC provider |
| SAML Bridge | crates/saml-bridge/ | SAML 2.0 for legacy enterprise apps |
| SCIM Provider | crates/scim/ | User provisioning |
| Admin Console | apps/admin/ | Organization management |
| SDK | packages/poly-oauth-sdk/ | Client integration library |

## Key Differentiator

First PQ biometric OAuth provider. Tokens signed with ML-DSA-87 (quantum-safe). No passwords to phish, no TOTP to intercept, no SMS to SIM-swap. Once an enterprise integrates Poly OAuth SSO, switching cost is enormous.

## No REST API (Internal)

Internal management uses eStream Wire Protocol. External OAuth/OIDC endpoints follow the OAuth 2.0 standard (HTTP-based by specification) as the interop layer for third-party applications.

## Platform

- eStream v0.8.1
- ESCIR SmartCircuits
- ML-KEM-1024, ML-DSA-87, SHA3-256
- 8-Dimension metering
- Compatible with: OAuth 2.0, OIDC, SAML 2.0, SCIM, FIDO2/WebAuthn
