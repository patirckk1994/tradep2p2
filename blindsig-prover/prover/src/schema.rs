// JSON shapes spoken across the C++ <-> Rust sidecar boundary. See
// REVIEW_REQUEST.md / specs.txt SS9.3a for the protocol these mirror.
// Deliberately plain, serde-derived structs - no cleverness, so the
// C++-side schema (blindsig_wire.hpp) can be visually diffed against
// this file.

use serde::{Deserialize, Serialize};

// ---- what user-blind produces, and what user-prove-nizk1 consumes ----

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicBlindRequest {
    pub b: Vec<u16>,
    pub c: Vec<u16>,
    pub rho_hex: String,
    pub enc_a: Vec<u16>,
    pub enc_pk: Vec<u16>,
    pub ct1_r: Vec<u16>,
    pub ct2_r: Vec<u16>,
    pub ct1_mu: Vec<u16>,
    pub ct2_mu: Vec<u16>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateBlindWitness {
    pub r: Vec<i32>,
    pub mu: String,
    pub coins_hex: String,
}

#[derive(Serialize, Deserialize)]
pub struct BlindInstance {
    pub public: PublicBlindRequest,
    pub private: PrivateBlindWitness,
}

// ---- the NIZK1 guest's own input/output shape (mirrors
// methods/guest/src/bin/nizk1.rs exactly - coins as raw bytes, not hex) ----

#[derive(Serialize, Deserialize)]
pub struct Nizk1Input {
    pub b: Vec<u16>,
    pub c: Vec<u16>,
    pub enc_a: Vec<u16>,
    pub enc_pk: Vec<u16>,
    pub ct1_r: Vec<u16>,
    pub ct2_r: Vec<u16>,
    pub ct1_mu: Vec<u16>,
    pub ct2_mu: Vec<u16>,
    pub r: Vec<i32>,
    pub mu: String,
    pub coins: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Nizk1PublicOutput {
    pub b: Vec<u16>,
    pub c: Vec<u16>,
    pub enc_a: Vec<u16>,
    pub enc_pk: Vec<u16>,
    pub ct1_r: Vec<u16>,
    pub ct2_r: Vec<u16>,
    pub ct1_mu: Vec<u16>,
    pub ct2_mu: Vec<u16>,
    pub valid: bool,
}

// What the C++ signer supplies on stdin to signer-verify-nizk1: the
// public fields it expects the receipt to have committed, taken from
// what the client actually submitted over the wire (and, critically,
// from the SIGNER'S OWN keystore for `b` - never from the client's
// claim - see blindsig_signer.cpp).
#[derive(Deserialize)]
pub struct Nizk1ExpectedPublic {
    pub b: Vec<u16>,
    pub c: Vec<u16>,
    pub enc_a: Vec<u16>,
    pub enc_pk: Vec<u16>,
    pub ct1_r: Vec<u16>,
    pub ct2_r: Vec<u16>,
    pub ct1_mu: Vec<u16>,
    pub ct2_mu: Vec<u16>,
}

// ---- the NIZK2 guest's own input/output shape ----

#[derive(Serialize, Deserialize)]
pub struct Nizk2Input {
    pub h: Vec<u16>,
    pub b: Vec<u16>,
    pub r: Vec<i32>,
    pub sig: Vec<i16>,
    pub rho: Vec<u8>,
    pub mu: String,
}

#[derive(Serialize, Deserialize)]
pub struct Nizk2PublicOutput {
    pub h: Vec<u16>,
    pub b: Vec<u16>,
    pub rho: Vec<u8>,
    pub mu: String,
    pub valid: bool,
}

// What user-finalize-prove-nizk2 reads on stdin: the public statement
// plus this client's own private (r, s) - r came from this client's own
// user-blind call, s came from the signer's response.
#[derive(Deserialize)]
pub struct FinalizeNizk2Request {
    pub h: Vec<u16>,
    pub b: Vec<u16>,
    pub rho_hex: String,
    pub mu: String,
    pub r: Vec<i32>,
    pub s: Vec<i16>,
}

// What verify-signature reads on stdin: the public credential being
// checked.
#[derive(Deserialize)]
pub struct VerifySignatureExpected {
    pub h: Vec<u16>,
    pub b: Vec<u16>,
    pub rho_hex: String,
    pub mu: String,
}
