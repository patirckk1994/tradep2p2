// This project's own signature verification relation - A=(t,1),
// t=f*g^-1 mod q (see blindsig_blns7933.hpp's PublicKey/derive_public(),
// built and empirically validated earlier this session on this same
// branch). Extracted into its own function, shared between the NIZK2
// guest (main.rs) and this crate's own tests, rather than inlined only in
// the guest - mirrors enc.rs's own generate/check sharing rationale: one
// implementation, not two hand-synced copies, and a place to unit-test
// against real signature data without needing a zkVM.

use crate::poly_mul::poly_mul_mod_q_karatsuba;
use crate::{add_mod_q, N};

/// Checks t*s0 + s1 == c (mod q). s0/s1 are used RAW (signed, not
/// pre-reduced mod q) - poly_mul's internal reduction makes this correct
/// regardless (ordinary modular-arithmetic homomorphism), and pre-
/// reducing would be pointless here since only the multiplication needs
/// canonical-range inputs at all, which poly_mul already handles.
pub fn relation_holds(t: &[i64], s0: &[i64], s1: &[i64], c: &[i64]) -> bool {
    let t_s0 = poly_mul_mod_q_karatsuba(t, s0);
    let lhs = add_mod_q(&t_s0, s1);
    (0..N).all(|i| lhs[i] == c[i])
}

/// ||s||^2 = sum(s0_i^2) + sum(s1_i^2), computed on the RAW signed
/// coefficients (see relation_holds's own comment on why raw, not
/// mod-q-reduced) - reducing mod q first would destroy the very
/// shortness property this measures.
pub fn norm_squared(s0: &[i64], s1: &[i64]) -> i64 {
    let mut sq_sum: i64 = 0;
    for i in 0..N {
        sq_sum += s0[i] * s0[i];
        sq_sum += s1[i] * s1[i];
    }
    sq_sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NORM_BOUND_SQUARED;

    // A tiny, hand-constructed instance: pick t, s0, s1 directly (not a
    // real trapdoor-derived signature - that cross-language check lives
    // in real_signature_tests.rs, using genuine C++ q7933-reference
    // output) and derive c = t*s0+s1 mod q INDEPENDENTLY via the trusted
    // schoolbook oracle (not by calling relation_holds() circularly, and
    // not via the same Karatsuba implementation relation_holds() itself
    // now uses) - this way the test also cross-checks Karatsuba against
    // schoolbook at this one instance, on top of confirming
    // relation_holds's own logic is self-consistent and rejects a
    // tampered c.
    #[test]
    fn relation_holds_for_a_self_consistent_instance_and_rejects_tampering() {
        let t: Vec<i64> = (0..N as i64).map(|i| (i * 37 + 11) % 7933).collect();
        let s0: Vec<i64> = (0..N as i64).map(|i| ((i * 13) % 21) - 10).collect();
        let s1: Vec<i64> = (0..N as i64).map(|i| ((i * 19) % 21) - 10).collect();

        let t_s0 = crate::poly_mul::poly_mul_mod_q_schoolbook(&t, &s0);
        let c = add_mod_q(&t_s0, &s1);

        assert!(relation_holds(&t, &s0, &s1, &c));

        let mut tampered_c = c.clone();
        tampered_c[0] = (tampered_c[0] + 1).rem_euclid(7933);
        assert!(!relation_holds(&t, &s0, &s1, &tampered_c));
    }

    #[test]
    fn norm_bound_constant_is_positive_and_matches_the_c_plus_plus_side() {
        // sigma=232, d=512, n=2: beta_s^2 = sigma^2*2*n*d =
        // 232^2*2*2*512 = 110,231,552 - this session's own validated
        // bound (a real d=512 signature had ||s||^2=51,497,427, well
        // inside it). Recomputed here from first principles as a sanity
        // check on the constant itself, not just trusting the literal.
        let sigma: i64 = 232;
        let expected = sigma * sigma * 2 * 2 * 512;
        assert_eq!(NORM_BOUND_SQUARED, expected);
    }
}
