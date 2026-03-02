//! Poly OAuth Journey Tests
//!
//! End-to-end journey for Poly OAuth: biometric authentication via SPARK,
//! token granting, federated identity, risk assessment, session lifecycle,
//! and blind telemetry — following the eStream Convoy pattern.

use estream_test::{
    Journey, JourneyParty, JourneyStep, StepAction, JourneyMetrics,
    assert_metric_emitted, assert_blinded, assert_povc_witness,
};
use estream_test::convoy::{ConvoyContext, ConvoyResult};
use estream_test::stratum::{StratumVerifier, CsrTier, SeriesMerkleChain};
use estream_test::cortex::{CortexVisibility, RedactPolicy, ObfuscatePolicy};

pub struct PolyoauthJourney;

impl Journey for PolyoauthJourney {
    fn name(&self) -> &str {
        "polyoauth_e2e"
    }

    fn description(&self) -> &str {
        "End-to-end journey for PolyOAuth: biometric auth, SPARK verification, token grant, federation, risk assessment, session expiry, and blind telemetry"
    }

    fn parties(&self) -> Vec<JourneyParty> {
        vec![
            JourneyParty::new("alice")
                .with_spark_context("poly-oauth-v1")
                .with_role("authenticating_user"),
            JourneyParty::new("bob")
                .with_spark_context("poly-oauth-v1")
                .with_role("federated_user"),
            JourneyParty::new("risk_engine")
                .with_spark_context("poly-oauth-v1")
                .with_role("risk_assessor"),
            JourneyParty::new("relying_party")
                .with_spark_context("poly-oauth-v1")
                .with_role("service_provider"),
        ]
    }

    fn steps(&self) -> Vec<JourneyStep> {
        vec![
            // Step 1: Alice initiates biometric authentication
            JourneyStep::new("alice_initiates_biometric_auth")
                .party("alice")
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let challenge = ctx.polyoauth().begin_auth(
                        "biometric_fido2",
                        "relying_party",
                    )?;

                    ctx.set("auth_challenge_id", &challenge.challenge_id);
                    ctx.set("session_nonce", &challenge.nonce);

                    assert!(!challenge.challenge_id.is_empty());
                    assert!(challenge.pq_safe);
                    assert_eq!(challenge.method, "biometric_fido2");

                    assert_metric_emitted!(ctx, "polyoauth.auth.initiated", {
                        "method" => "biometric_fido2",
                        "pq_safe" => "true",
                    });

                    assert_blinded!(ctx, "polyoauth.auth.initiated", {
                        field: "user_id",
                        blinding: "hmac_sha3",
                    });

                    Ok(())
                }))
                .timeout_ms(8_000),

            // Step 2: SPARK verification of biometric attestation
            JourneyStep::new("spark_verification")
                .party("alice")
                .depends_on(&["alice_initiates_biometric_auth"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let challenge_id = ctx.get::<String>("auth_challenge_id");

                    let spark_result = ctx.polyoauth().verify_spark(
                        &challenge_id,
                        "ML-DSA-87",
                    )?;

                    ctx.set("spark_attestation_id", &spark_result.attestation_id);

                    assert!(spark_result.verified);
                    assert_eq!(spark_result.signature_algo, "ML-DSA-87");
                    assert!(spark_result.liveness_confirmed);
                    assert!(spark_result.replay_protected);

                    assert_metric_emitted!(ctx, "polyoauth.spark.verified", {
                        "algo" => "ML-DSA-87",
                        "liveness" => "confirmed",
                    });

                    assert_povc_witness!(ctx, "polyoauth.spark_verify", {
                        witness_type: "biometric_attestation",
                        attestation_id: &spark_result.attestation_id,
                    });

                    assert_blinded!(ctx, "polyoauth.spark.verified", {
                        field: "biometric_template",
                        blinding: "absent",
                    });

                    Ok(())
                }))
                .timeout_ms(10_000),

            // Step 3: Token granted to Alice
            JourneyStep::new("token_granted")
                .party("relying_party")
                .depends_on(&["spark_verification"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let attestation_id = ctx.get::<String>("spark_attestation_id");

                    let token = ctx.polyoauth().grant_token(
                        &attestation_id,
                        &["openid", "profile", "email"],
                        3_600, // 1h TTL
                    )?;

                    ctx.set("access_token_id", &token.token_id);
                    ctx.set("session_id", &token.session_id);

                    assert!(!token.token_id.is_empty());
                    assert!(token.pq_signed);
                    assert!(token.ttl_secs > 0);
                    assert_eq!(token.scopes, vec!["openid", "profile", "email"]);

                    assert_metric_emitted!(ctx, "polyoauth.token.granted", {
                        "scopes" => "openid,profile,email",
                        "ttl_secs" => "3600",
                    });

                    assert_povc_witness!(ctx, "polyoauth.token_grant", {
                        witness_type: "token_issuance",
                        token_id: &token.token_id,
                    });

                    assert_blinded!(ctx, "polyoauth.token.granted", {
                        field: "token_secret",
                        blinding: "absent",
                    });

                    Ok(())
                }))
                .timeout_ms(8_000),

            // Step 4: Bob federates identity via Alice's provider
            JourneyStep::new("bob_federates")
                .party("bob")
                .depends_on(&["token_granted"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let federation = ctx.polyoauth().federate(
                        "alice",
                        "relying_party",
                        &["openid", "profile"],
                    )?;

                    ctx.set("federation_id", &federation.federation_id);

                    assert!(federation.trust_established);
                    assert!(federation.pq_key_exchange);
                    assert!(federation.cross_origin_isolated);

                    let bob_spark = ctx.polyoauth().verify_spark(
                        &federation.challenge_id,
                        "ML-DSA-87",
                    )?;
                    assert!(bob_spark.verified);

                    assert_metric_emitted!(ctx, "polyoauth.federation.established", {
                        "pq_key_exchange" => "true",
                        "cross_origin" => "isolated",
                    });

                    assert_povc_witness!(ctx, "polyoauth.federation", {
                        witness_type: "identity_federation",
                        federation_id: &federation.federation_id,
                    });

                    assert_blinded!(ctx, "polyoauth.federation.established", {
                        field: "federated_user_id",
                        blinding: "hmac_sha3",
                    });

                    Ok(())
                }))
                .timeout_ms(12_000),

            // Step 5: Risk assessment evaluates session
            JourneyStep::new("risk_assessment")
                .party("risk_engine")
                .depends_on(&["bob_federates"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let session_id = ctx.get::<String>("session_id");

                    let risk = ctx.polyoauth().assess_risk(&session_id)?;

                    assert!(risk.score <= 1.0 && risk.score >= 0.0);
                    assert!(risk.factors_evaluated >= 3);
                    assert!(!risk.action_required || risk.score > 0.7);

                    assert_metric_emitted!(ctx, "polyoauth.risk.assessed", {
                        "factors_evaluated" => &risk.factors_evaluated.to_string(),
                    });

                    assert_blinded!(ctx, "polyoauth.risk.assessed", {
                        field: "device_fingerprint",
                        blinding: "hmac_sha3",
                    });

                    assert_blinded!(ctx, "polyoauth.risk.assessed", {
                        field: "ip_address",
                        blinding: "hmac_sha3",
                    });

                    assert_povc_witness!(ctx, "polyoauth.risk_assess", {
                        witness_type: "risk_evaluation",
                        session_id: &session_id,
                    });

                    Ok(())
                }))
                .timeout_ms(8_000),

            // Step 6: Session expiry and cleanup
            JourneyStep::new("session_expiry")
                .party("relying_party")
                .depends_on(&["risk_assessment"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let session_id = ctx.get::<String>("session_id");
                    let token_id = ctx.get::<String>("access_token_id");

                    ctx.polyoauth().advance_clock(3_601); // past 1h TTL

                    let token_status = ctx.polyoauth().validate_token(&token_id)?;
                    assert!(token_status.expired);
                    assert!(!token_status.valid);

                    let session_status = ctx.polyoauth().session_status(&session_id)?;
                    assert!(session_status.ended);
                    assert!(session_status.artifacts_cleaned);

                    // Stratum storage verification
                    let stratum = StratumVerifier::new(ctx);

                    let csr_report = stratum.verify_csr_tiers(&session_id)?;
                    assert!(csr_report.tier_matches(CsrTier::Ephemeral));

                    let merkle = stratum.verify_series_merkle_chain(&session_id)?;
                    assert!(merkle.chain_intact);
                    assert!(merkle.root_hash_valid);
                    assert!(merkle.series_count >= 1);

                    assert_metric_emitted!(ctx, "polyoauth.session.expired", {
                        "artifacts_cleaned" => "true",
                    });

                    assert_povc_witness!(ctx, "polyoauth.session_expire", {
                        witness_type: "session_cleanup",
                        session_id: &session_id,
                    });

                    Ok(())
                }))
                .timeout_ms(10_000),

            // Step 7: Verify blind telemetry and Cortex visibility
            JourneyStep::new("verify_blind_telemetry")
                .party("alice")
                .depends_on(&["session_expiry"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let telemetry = ctx.streamsight().drain_telemetry("poly-oauth-v1");

                    for event in &telemetry {
                        assert_blinded!(ctx, &event.event_type, {
                            field: "user_id",
                            blinding: "hmac_sha3",
                        });

                        assert_blinded!(ctx, &event.event_type, {
                            field: "biometric_data",
                            blinding: "absent",
                        });

                        assert_blinded!(ctx, &event.event_type, {
                            field: "token_secret",
                            blinding: "absent",
                        });
                    }

                    let cortex = CortexVisibility::new(ctx);
                    cortex.assert_redacted("polyoauth", RedactPolicy::ContentFields)?;
                    cortex.assert_obfuscated("polyoauth", ObfuscatePolicy::PartyIdentifiers)?;

                    assert!(telemetry.len() >= 7, "Expected at least 7 telemetry events");

                    let namespaces: Vec<&str> = telemetry
                        .iter()
                        .map(|e| e.namespace.as_str())
                        .collect();
                    for ns in &namespaces {
                        assert!(
                            ns.starts_with("poly-oauth-v1"),
                            "Telemetry must stay within poly-oauth-v1 namespace, found: {}",
                            ns,
                        );
                    }

                    Ok(())
                }))
                .timeout_ms(5_000),
        ]
    }

    fn metrics(&self) -> JourneyMetrics {
        JourneyMetrics {
            expected_events: vec![
                "polyoauth.auth.initiated",
                "polyoauth.spark.verified",
                "polyoauth.token.granted",
                "polyoauth.federation.established",
                "polyoauth.risk.assessed",
                "polyoauth.session.expired",
            ],
            max_duration_ms: 70_000,
            required_povc_witnesses: 6,
            lex_namespace: "poly-oauth-v1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use estream_test::convoy::ConvoyRunner;

    #[tokio::test]
    async fn run_polyoauth_journey() {
        let runner = ConvoyRunner::new()
            .with_streamsight("poly-oauth-v1")
            .with_stratum()
            .with_cortex()
            .with_spark();

        runner.run(PolyoauthJourney).await.expect("PolyOAuth journey failed");
    }
}
