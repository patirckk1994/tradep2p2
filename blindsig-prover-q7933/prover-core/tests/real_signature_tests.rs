// Cross-language correctness test: checks this crate's own
// relation_holds()/norm_squared() (prover-core/src/relation.rs, the same
// functions the NIZK2 guest calls) against a REAL, genuinely-produced
// q=7933, d=512 signature from the C++ q7933-reference substrate
// (BLIND/q7933-reference/rust_crosscheck_dump_512.cpp), not a Rust-
// fabricated instance. The C++ side's own verify()/verify_target() had
// already accepted this exact signature before rust_crosscheck_data.rs
// was written - this test confirms the Rust PORT of the same relation
// agrees with the C++ reference it was ported from, on real data, not
// just that it's internally self-consistent (relation.rs's own unit
// tests already cover that).
//
// Two integration test, matching the two facts a signature must
// establish (falcon.pdf's own two-part Verify): the algebraic relation
// holds, AND the norm bound holds - both checked here with the exact
// same real (t,s0,s1) triple.

include!("data/rust_crosscheck_data.rs");

#[test]
fn real_cpp_produced_signature_satisfies_the_ported_relation() {
    assert!(prover_core::relation::relation_holds(&T, &S0, &S1, &TARGET_C));
}

#[test]
fn real_cpp_produced_signature_is_within_the_norm_bound() {
    let norm_sq = prover_core::relation::norm_squared(&S0, &S1);
    assert!(norm_sq <= prover_core::NORM_BOUND_SQUARED);
    // Sanity: this should be the SAME norm the C++ side's own
    // sign_512_diagnostic run reported this session (51,497,427) for its
    // own signature - not necessarily THIS exact signature (different
    // message/seed reuse across runs can still produce different (s0,s1)
    // even from the same trapdoor), but in the same real ballpark, not a
    // degenerate near-zero or near-bound value.
    assert!(norm_sq > 1_000_000, "a genuine Gaussian-sampled signature's norm should not be tiny");
}

#[test]
fn tampering_with_the_real_target_is_rejected() {
    let mut tampered = TARGET_C;
    tampered[0] = (tampered[0] + 1).rem_euclid(7933);
    assert!(!prover_core::relation::relation_holds(&T, &S0, &S1, &tampered));
}

