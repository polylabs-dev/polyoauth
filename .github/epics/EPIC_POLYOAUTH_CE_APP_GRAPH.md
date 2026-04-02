# Epic: PolyOAuth — CE + App Graph Integration

> **Repo**: `polyoauth`
> **Spec**: `specs/POLYOAUTH_CE_APP_GRAPH_SPEC.md`
> **Priority**: P1
> **Status**: Planned

---

## Summary

Integrate the Cognitive Engine and App Graph into Poly OAuth. This registers all 12 OAuth modules (10 circuits + 2 graphs) into the Stratum module graph, wires 11 dependency edges plus 3 cross-graph bridges (PolyPass credential sync, PolyAuthenticator MFA, PolyKit SSO consumer), and configures 3 CE meaning domains with noise filtering and 2 SME panels.

---

## Tasks

### Phase 1: App Graph Registration

- [ ] **P1.1** — Implement `polyoauth_app_graph.fl` with 12 module definitions and `make_polyoauth_module` helper
- [ ] **P1.2** — Wire 11 `EDGE_REQUIRES` dependency edges in `polyoauth_app_graph_register`
- [ ] **P1.3** — Implement `polyoauth_register_bridge_edges` (3 bridges: PolyPass vault, PolyAuthenticator ceremony, PolyKit SSO consumer)
- [ ] **P1.4** — Add `find_polyoauth_module_id` helper and `polyoauth_app_graph_metrics` store
- [ ] **P1.5** — Add 3 golden tests for graph registration, bridge edges, and module factory

### Phase 2: CE Meaning Domains

- [ ] **P2.1** — Define `AuthPatternsDomain`, `SessionHealthDomain`, `FederationCoverageDomain` data types with cortex blocks
- [ ] **P2.2** — Implement `register_auth_patterns_domain` circuit (threshold 75, impact 80)
- [ ] **P2.3** — Implement `register_session_health_domain` circuit (threshold 80, impact 90)
- [ ] **P2.4** — Implement `register_federation_coverage_domain` circuit (threshold 65, impact 60)
- [ ] **P2.5** — Add observation streams (`auth_patterns_obs`, `session_health_obs`, `federation_coverage_obs`)

### Phase 3: Noise Filter & SME Panels

- [ ] **P3.1** — Define `OAuthNoiseFilterConfig` with token refresh, session keepalive, OIDC discovery, CORS preflight suppression
- [ ] **P3.2** — Implement `configure_oauth_noise_filter` (suppress lifecycle events, 15s keepalive dedup)
- [ ] **P3.3** — Define `IdentitySecurityPosturePanel` and `FederationHealthPanel` data types
- [ ] **P3.4** — Implement `configure_identity_security_posture_panel` (4 specializations, 80% calibration floor)
- [ ] **P3.5** — Implement `configure_federation_health_panel` (4 specializations, 75% calibration floor)
- [ ] **P3.6** — Implement `polyoauth_register_ce` orchestrator and `full_ce_pipeline_setup` golden test

### Phase 4: Integration & Validation

- [ ] **P4.1** — Verify all 12 modules resolve via `find_polyoauth_module_id` after registration
- [ ] **P4.2** — Verify bridge edges connect to live PolyPass, PolyAuthenticator, and PolyKit SSO module graphs
- [ ] **P4.3** — Verify CE domains produce observations that flow through noise filter to cortex
- [ ] **P4.4** — Verify SME panels accept and adjudicate crystallization candidates
- [ ] **P4.5** — Run full FLIR codegen (WASM + Rust targets) on both circuit files

---

## Acceptance Criteria

1. `polyoauth_app_graph_register` produces a `CsrStorage` with exactly 12 nodes and 11 edges
2. `polyoauth_register_bridge_edges` adds 3 bridge nodes with `EDGE_BRIDGE_TO` edges
3. All 3 meaning domains register with correct crystallization thresholds (75, 80, 65)
4. Noise filter suppresses token refresh cycles, session keepalives, OIDC discovery re-fetches, CORS preflight probes
5. Both SME panels require min 3 panelists with calibration floors >= 75%
6. `polyoauth_register_ce` orchestrator returns true on successful full pipeline setup
7. All golden tests pass under `fl test --golden`
8. Both files compile to WASM and Rust via `fl build --target wasm,rust`

---

## Files

| File | Description |
|------|-------------|
| `circuits/fl/polyoauth_app_graph.fl` | 12-module app graph, 11 edges, 3 bridges, golden tests |
| `circuits/fl/polyoauth_meaning.fl` | 3 CE domains, noise filter, 2 SME panels, orchestrator, golden tests |
| `specs/POLYOAUTH_CE_APP_GRAPH_SPEC.md` | Integration spec |
