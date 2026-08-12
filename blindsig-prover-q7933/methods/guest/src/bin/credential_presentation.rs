// Single-credential q=7933 presentation proof.
//
// This is deliberately a NEW RISC Zero method, separate from NIZK1 (blind
// request construction) and NIZK2 (finalization/signature relation). It
// proves possession of one finalized blind-signed credential while keeping
// the bearer material private:
//
//   private: r, s0, s1, credential serial
//   public:  signer t/B, issuer scope, epoch, presentation scope, nullifier
//
// The guest reconstructs the exact credential `mu` used by the C++ client,
// recomputes c = B*r + H(G(r),mu), checks t*s0+s1=c and the signature norm,
// derives the scoped nullifier from the hidden serial, and commits only the
// public values plus valid=true/false.
//
// This prevents a verifier from learning the credential serial/signature and
// then re-presenting that bearer credential itself. It is NOT the future
// aggregate proof over N distinct credentials; that remains a separate
// statement.

use prover_core::{
    add_mod_q, g_of_r, h_of_rho_mu, hash_to_point,
    poly_mul::poly_mul_mod_q_karatsuba,
    relation::{norm_squared, relation_holds},
    r_in_bounds, N, NORM_BOUND_SQUARED, Q,
};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CREDENTIAL_VERSION: u8 = 1;
const CREDENTIAL_EPOCH_V1: u32 = 0;
const MAX_PRESENTATION_SCOPE_BYTES: usize = 4096;
const MAX_SIGNATURE_COEFF_ABS: i32 = 10_499; // floor(sqrt(NORM_BOUND_SQUARED))
const CREDENTIAL_BLIND_DOMAIN: &[u8] = b"TRADEP2P-Q7933-CREDENTIAL-FOR-BLIND-v1";
const CREDENTIAL_MU_PREFIX: &str = "tradep2p-q7933-credential-v1:";
const NULLIFIER_DOMAIN: &[u8] = b"TRADEP2P-Q7933-CREDENTIAL-NULLIFIER-v1";

#[derive(Deserialize)]
struct CredentialPresentationInput {
    // Public issuer parameters.
    t: Vec<u16>,
    b: Vec<u16>,
    issuer_scope: u8,
    epoch: u32,
    presentation_scope: Vec<u8>,
    claimed_nullifier: [u8; 32],

    // Private credential witness. Never committed.
    r: Vec<i32>,
    s0: Vec<i32>,
    s1: Vec<i32>,
    serial: [u8; 32],
}

#[derive(Serialize)]
struct CredentialPresentationPublicOutput {
    t: Vec<u16>,
    b: Vec<u16>,
    issuer_scope: u8,
    epoch: u32,
    presentation_scope: Vec<u8>,
    nullifier: [u8; 32],
    valid: bool,
}

fn append_hex_lower(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

// Must exactly match C++ CredentialPayload::encode() followed by
// encode_credential_for_blind(), then blindsig_client_q7933.cpp's
// kCredentialMuPrefix + lowercase-hex wrapper. V1 has an empty reserved
// field, encoded as a zero u16 length.
fn credential_mu(issuer_scope: u8, epoch: u32, serial: &[u8; 32]) -> String {
    let mut encoded = Vec::with_capacity(CREDENTIAL_BLIND_DOMAIN.len() + 40);
    encoded.extend_from_slice(CREDENTIAL_BLIND_DOMAIN);
    encoded.push(CREDENTIAL_VERSION);
    encoded.push(issuer_scope);
    encoded.extend_from_slice(&epoch.to_be_bytes());
    encoded.extend_from_slice(serial);
    encoded.extend_from_slice(&0u16.to_be_bytes()); // reserved length

    let mut mu = String::with_capacity(CREDENTIAL_MU_PREFIX.len() + encoded.len() * 2);
    mu.push_str(CREDENTIAL_MU_PREFIX);
    append_hex_lower(&mut mu, &encoded);
    mu
}

// Must exactly match C++ q7933_credential::derive_nullifier().
fn derive_nullifier(
    serial: &[u8; 32],
    issuer_scope: u8,
    epoch: u32,
    presentation_scope: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULLIFIER_DOMAIN);
    h.update([issuer_scope]);
    h.update(epoch.to_be_bytes());
    h.update((presentation_scope.len() as u32).to_be_bytes());
    h.update(presentation_scope);
    h.update(serial);
    h.finalize().into()
}

fn canonical_ring_poly(v: &[u16]) -> bool {
    v.len() == N && v.iter().all(|&x| i64::from(x) < Q)
}

fn signature_witness_is_safely_bounded(v: &[i32]) -> bool {
    v.len() == N && v.iter().all(|&x| (-MAX_SIGNATURE_COEFF_ABS..=MAX_SIGNATURE_COEFF_ABS).contains(&x))
}

fn main() {
    let input: CredentialPresentationInput = env::read();

    // Validate all attacker-controlled vector lengths/ranges BEFORE any
    // arithmetic that indexes N coefficients. The explicit s bound also
    // makes every i64 Karatsuba/norm intermediate comfortably safe from
    // overflow; a genuinely valid signature necessarily satisfies it
    // because one coefficient alone cannot exceed the total norm bound.
    let shape_ok = canonical_ring_poly(&input.t)
        && canonical_ring_poly(&input.b)
        && input.r.len() == N
        && r_in_bounds(&input.r)
        && signature_witness_is_safely_bounded(&input.s0)
        && signature_witness_is_safely_bounded(&input.s1)
        && input.presentation_scope.len() <= MAX_PRESENTATION_SCOPE_BYTES
        && input.epoch == CREDENTIAL_EPOCH_V1;

    let valid = if shape_ok {
        let mu = credential_mu(input.issuer_scope, input.epoch, &input.serial);
        let rho = g_of_r(&input.r);
        let h_digest = h_of_rho_mu(&rho, &mu);
        let hash_term = hash_to_point(&h_digest);

        let b_i64: Vec<i64> = input.b.iter().map(|&x| i64::from(x)).collect();
        let r_i64: Vec<i64> = input.r.iter().map(|&x| i64::from(x)).collect();
        let br = poly_mul_mod_q_karatsuba(&b_i64, &r_i64);
        let c = add_mod_q(&br, &hash_term);

        let t_i64: Vec<i64> = input.t.iter().map(|&x| i64::from(x)).collect();
        let s0_i64: Vec<i64> = input.s0.iter().map(|&x| i64::from(x)).collect();
        let s1_i64: Vec<i64> = input.s1.iter().map(|&x| i64::from(x)).collect();

        let signature_ok = relation_holds(&t_i64, &s0_i64, &s1_i64, &c)
            && norm_squared(&s0_i64, &s1_i64) <= NORM_BOUND_SQUARED;
        let nullifier_ok = derive_nullifier(
            &input.serial,
            input.issuer_scope,
            input.epoch,
            &input.presentation_scope,
        ) == input.claimed_nullifier;

        signature_ok && nullifier_ok
    } else {
        false
    };

    env::commit(&CredentialPresentationPublicOutput {
        t: input.t,
        b: input.b,
        issuer_scope: input.issuer_scope,
        epoch: input.epoch,
        presentation_scope: input.presentation_scope,
        nullifier: input.claimed_nullifier,
        valid,
    });
}
