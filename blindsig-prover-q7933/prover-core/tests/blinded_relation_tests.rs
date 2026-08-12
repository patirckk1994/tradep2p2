// Companion to real_signature_tests.rs: checks a SECOND, independently
// produced real signature - this one from sign_target() over a genuinely
// blinded c (not a plain hash_to_point(message)), the same data
// examples/prove_nizk2.rs uses for a real end-to-end zkVM proof.
// Checking it here too, without a zkVM, confirms the pure-Rust relation
// logic agrees before spending minutes on a real prove.

include!("../../methods/examples/data/blinded_target_data.rs"); // B, R, RHO, MU, C
include!("data/rust_crosscheck_data.rs"); // T, S0, S1, TARGET_C, BLINDED_S0, BLINDED_S1

#[test]
fn the_blinded_target_signature_satisfies_the_relation() {
    assert!(prover_core::relation::relation_holds(&T, &BLINDED_S0, &BLINDED_S1, &C));
}

#[test]
fn the_blinded_target_signature_is_within_the_norm_bound() {
    let norm_sq = prover_core::relation::norm_squared(&BLINDED_S0, &BLINDED_S1);
    assert!(norm_sq <= prover_core::NORM_BOUND_SQUARED);
}
