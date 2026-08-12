// Shared arithmetic for the q=7933 blind-signature prover - the sibling
// of ../../blindsig-prover/prover-core, which stays at FALCON's own
// q=12289 and is NEVER modified by this crate's existence. This crate is
// compiled into BOTH the RISC0 guest binaries (methods/guest) and the
// native host CLI (prover), same reasoning as the q=12289 sibling: "what
// the client computed" and "what the guest independently recomputes and
// checks" must be calls to the exact same compiled function.
//
// Ported from blindsig-prover/prover-core, NOT from FALCON's own C source
// this time - the previous crate's own NTT/table port had FALCON's real
// vrfy.c to port function-by-function against; this crate's polynomial
// multiplication (poly_mul.rs) and verification relation are this
// project's own q=7933 NTRU trapdoor scheme (blindsig_blns7933_sign.cpp,
// built and empirically validated - algebraic correctness, statistical
// distribution, and CSPRNG-secured randomness - earlier this session on
// this same branch), not FALCON's.

pub mod enc;
pub mod poly_mul;
pub mod relation;

use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const N: usize = 512;
pub const Q: i64 = 7933;

// This scheme's own norm bound, not FALCON's L2_BOUND: beta_s^2 =
// sigma^2 * 2*n*d with n=2 (s has two ring-element components, s0 and
// s1), sigma=232 (BLNS23's own Table 2 value), d=512. Validated for real,
// not just computed: this session's own d=512 sign_512_diagnostic
// produced a genuine signature with ||s||^2=51,497,427, comfortably
// inside this bound (~47% of it).
pub const NORM_BOUND_SQUARED: i64 = 110_231_552;

pub fn add_mod_q(a: &[i64], b: &[i64]) -> Vec<i64> {
    (0..N).map(|i| (a[i] + b[i]).rem_euclid(Q)).collect()
}

// Mirrors the q=12289 sibling's hash_to_ring() exactly - same
// serialization of r, same SHA-256(r_bytes) for G(r), same
// SHA-256(rho||mu) for H(rho,mu). Independent of q, so ported unchanged.
pub fn g_of_r(r: &[i32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(N * 2);
    for &ri in r {
        let v = (ri + 2) as u16; // shift to unsigned, matches C++
        bytes.push((v & 0xff) as u8);
        bytes.push((v >> 8) as u8);
    }
    Sha256::digest(&bytes).into()
}

pub fn h_of_rho_mu(rho: &[u8], mu: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(rho.len() + mu.len());
    input.extend_from_slice(rho);
    input.extend_from_slice(mu.as_bytes());
    Sha256::digest(&input).into()
}

// Same real, SHAKE256-based construction as the q=12289 sibling's
// hash_to_point() (itself a genuine port of FALCON's own
// Zf(hash_to_point_vartime)(), common.c) - NOT the separate C++ q7933-
// reference substrate's own hash_to_point() (blindsig_blns7933_sign.cpp),
// which is an explicitly-documented non-cryptographic placeholder. This
// is the real one, reparametrized for q=7933: reject w >= 5*Q (computed
// from Q, not a hardcoded literal - the sibling crate hardcodes 61445/
// 12289 verbatim specifically to diff cleanly against FALCON's own C
// source, but no such source exists for this scheme at q=7933, so there
// is no reason to repeat that hardcoding style here).
pub fn hash_to_point(digest: &[u8; 32]) -> Vec<i64> {
    let reject_at = 5 * (Q as u32);
    let mut shake = Shake256::default();
    shake.update(digest);
    let mut reader = shake.finalize_xof();
    let mut out = Vec::with_capacity(N);
    while out.len() < N {
        let mut buf = [0u8; 2];
        reader.read(&mut buf);
        let w = ((buf[0] as u32) << 8) | (buf[1] as u32);
        if w < reject_at {
            out.push((w % (Q as u32)) as i64);
        }
    }
    out
}

pub fn r_in_bounds(r: &[i32]) -> bool {
    r.iter().all(|&x| (-2..=2).contains(&x))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 5*Q must comfortably fit a u16 draw's range (0..65536) with room to
    // spare for the rejection sampling to actually terminate in practice -
    // a sanity check on the constant itself, not just its arithmetic.
    #[test]
    fn reject_threshold_is_well_formed() {
        let reject_at = 5 * (Q as u32);
        assert!(reject_at < 65536, "5*Q must fit comfortably below 2^16");
        // Acceptance probability per draw: reject_at/65536. Confirms this
        // isn't a near-degenerate (almost-always-reject) threshold.
        assert!(
            reject_at as f64 / 65536.0 > 0.5,
            "rejection threshold should accept the clear majority of draws"
        );
    }

    #[test]
    fn hash_to_point_is_deterministic_and_produces_n_coefficients_in_range() {
        let digest = Sha256::digest(b"lib.rs hash_to_point regression test").into();
        let a = hash_to_point(&digest);
        let b = hash_to_point(&digest);
        assert_eq!(a, b, "hash_to_point must be a pure function of its digest");
        assert_eq!(a.len(), N);
        assert!(a.iter().all(|&v| (0..Q).contains(&v)));
    }

    #[test]
    fn g_of_r_and_h_of_rho_mu_are_deterministic() {
        let r = vec![1i32, -2, 0, 2];
        assert_eq!(g_of_r(&r), g_of_r(&r));
        let rho = g_of_r(&r);
        assert_eq!(h_of_rho_mu(&rho, "msg"), h_of_rho_mu(&rho, "msg"));
        assert_ne!(h_of_rho_mu(&rho, "msg"), h_of_rho_mu(&rho, "different msg"));
    }

    #[test]
    fn r_in_bounds_checks_the_actual_protocol_bound() {
        assert!(r_in_bounds(&[-2, -1, 0, 1, 2]));
        assert!(!r_in_bounds(&[-3, 0, 0]));
        assert!(!r_in_bounds(&[0, 0, 3]));
    }
}
