// JSON shapes spoken across the C++ <-> Rust q=7933 sidecar boundary.
// Kept deliberately plain so the eventual C++ wire/subprocess adapter can
// be visually diffed against this file.

use serde::{Deserialize, Serialize};

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

// q=7933 differs materially from the q=12289 FALCON sidecar here: the
// public key is t=f*g^-1, and both signature halves are explicit.
#[derive(Serialize, Deserialize)]
pub struct Nizk2Input {
    pub t: Vec<u16>,
    pub b: Vec<u16>,
    pub r: Vec<i32>,
    pub s0: Vec<i32>,
    pub s1: Vec<i32>,
    pub rho: Vec<u8>,
    pub mu: String,
}

#[derive(Serialize, Deserialize)]
pub struct Nizk2PublicOutput {
    pub t: Vec<u16>,
    pub b: Vec<u16>,
    pub rho: Vec<u8>,
    pub mu: String,
    pub valid: bool,
}

#[derive(Deserialize)]
pub struct FinalizeNizk2Request {
    pub t: Vec<u16>,
    pub b: Vec<u16>,
    pub rho_hex: String,
    pub mu: String,
    pub r: Vec<i32>,
    pub s0: Vec<i32>,
    pub s1: Vec<i32>,
}

#[derive(Deserialize)]
pub struct VerifySignatureExpected {
    pub t: Vec<u16>,
    pub b: Vec<u16>,
    pub rho_hex: String,
    pub mu: String,
}
