// Shared arithmetic for the blind-FALCON prover. This crate is compiled
// into BOTH the RISC0 guest binaries (methods/guest, which prove/check
// these relations in zero knowledge) and the native host CLI (prover,
// which the client and signer roles both use to generate the values the
// guest later re-derives and checks) - so "what the client computed" and
// "what the guest independently recomputes and compares against" are
// calls to the exact same compiled function, never two hand-synced
// copies in two places.
//
// Ported (not redesigned) from the original research prototype at
// pq-blind-sig-research/prototype/nizk2_zkvm/methods/guest/src/lib.rs -
// see that project's REVIEW_REQUEST.md and RESEARCH_STATUS.md for the
// full design rationale and verification history (NTT cross-checked
// against a schoolbook reference on 200 random trials; the encryption
// construction cross-checked against real generated ciphertexts plus a
// negative control) before any of this was trusted inside a zkVM guest.

pub mod enc;
pub mod ntt;
pub mod ntt_tables;

use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const N: usize = 512;
pub const Q: i64 = 12289;
pub const L2_BOUND: i64 = 34_034_726; // FALCON-512's own l2bound[9] - matches the paper's own beta_s^2

pub fn add_mod_q(a: &[i64], b: &[i64]) -> Vec<i64> {
    (0..N).map(|i| (a[i] + b[i]).rem_euclid(Q)).collect()
}

// Mirrors the original C++ prototype's hash_to_ring() exactly - same
// serialization of r, same SHA-256(r_bytes) for G(r), same
// SHA-256(rho||mu) for H(rho,mu).
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

// Mirrors FALCON's own Zf(hash_to_point_vartime)() (common.c) exactly:
// SHAKE256 XOF, extract 2 bytes big-endian at a time, reject w >= 61445
// (=5*12289, keeps the mod-q reduction unbiased), reduce by repeated
// subtraction, collect N coefficients.
pub fn hash_to_point(digest: &[u8; 32]) -> Vec<i64> {
    let mut shake = Shake256::default();
    shake.update(digest);
    let mut reader = shake.finalize_xof();
    let mut out = Vec::with_capacity(N);
    while out.len() < N {
        let mut buf = [0u8; 2];
        reader.read(&mut buf);
        let w = ((buf[0] as u32) << 8) | (buf[1] as u32);
        if w < 61445 {
            out.push((w % 12289) as i64);
        }
    }
    out
}

pub fn r_in_bounds(r: &[i32]) -> bool {
    r.iter().all(|&x| (-2..=2).contains(&x))
}
