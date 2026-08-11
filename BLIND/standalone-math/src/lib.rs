//! Standalone extraction of two pieces of math from a larger experimental
//! post-quantum blind-signature implementation, isolated here specifically
//! for outside cryptographic review. See README.md for full context,
//! provenance, and what to look at first.
//!
//! `ntt`/`ntt_tables`: a faithful port of FALCON's own NTT-based
//! polynomial multiplication (ported from the reference C implementation,
//! not re-derived) - included mainly as a correctness dependency of `enc`
//! below, and cross-checked against a schoolbook reference in its own
//! tests.
//!
//! `enc`: "encryption to the sky" - a Ring-LWE (LPR-style) dual encryption
//! used only inside a security-proof extraction argument, never decrypted
//! in the live protocol. This is the original, not-ported-from-anywhere
//! part, and the one most in need of independent scrutiny.
//!
//! Both modules are byte-for-byte identical to the versions running in the
//! parent project (verified via `diff` at extraction time, not retyped),
//! aside from this crate shell existing to hold them.

pub mod enc;
pub mod ntt;
pub mod ntt_tables;

pub const N: usize = 512;
pub const Q: i64 = 12289;
