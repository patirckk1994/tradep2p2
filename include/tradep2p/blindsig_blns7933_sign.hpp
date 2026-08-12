#pragma once

// Sign/Verify (falcon.pdf Algorithm 10, adapted), tying together TrapGen,
// the Falcon tree, and ffSampling.
//
// IMPORTANT DEVIATION FROM FALCON, worked out and symbolically verified
// this session, not copied from the paper: FALCON's own public key is
// h=g*f^-1 (verification s1+s2*h=c mod q); THIS project's trapdoor uses
// BLNS23's own orientation, t=f*g^-1 (see blindsig_blns7933.hpp's
// PublicKey/derive_public()). FALCON's Sign (Algorithm 10 line 3) sets
// its initial target as t=(-c*F/q, c*f/q), which lands at t.B=(c,0) for
// ITS OWN h=g/f relation - that formula does NOT carry over unchanged
// here.
//
// For THIS project's A=(t_pub,1), t_pub=f/g convention, the target that
// makes the analogous derivation work out is
//
//     t = (-c*capG/q, c*g/q)
//
// which gives t.B = (0,c) exactly (B=[[g,-f],[capG,-capF]]), and for
// s=(t-z).B, f*s0+g*s1 == g*c (mod q) for ANY integer combination
// z.B added in - i.e. exactly the coset condition equivalent to
// A.s=c with A=(f/g,1). Verified symbolically (SymPy, not just by hand)
// during this session; see the session's own notes for the full
// derivation. Swapping f<->g and capF<->capG relative to FALCON's own
// formula is not a typo - it is what the different A orientation
// requires.

#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_blns7933_csprng.hpp"
#include "tradep2p/blindsig_blns7933_integer_ring.hpp"
#include "tradep2p/blindsig_blns7933_ldl.hpp"

#include <string>

namespace tradep2p::blns7933 {

// Despite t and the intermediate ffSampling computation being real-
// valued, s=(t-z).B is an EXACT integer vector: t.B=(0,c) exactly, and
// z.B is an integer combination of B's integer rows, so s=(0,c)-z.B is
// exactly integer regardless of t's own fractional value. sign() rounds
// to the nearest integer (with an internal sanity check that the
// rounding residual is negligible, not just truncating and hoping) and
// returns PolyQ, the same int64_t-coefficient type this substrate already
// uses for trapdoor material (blindsig_blns7933.hpp).
struct Signature {
    PolyQ s0;
    PolyQ s1;
};

// Precomputes the Falcon tree for `key` at `target_sigma` - do this once
// per keypair, reuse across many Sign() calls (mirrors falcon.pdf's own
// "computed once at keygen" framing for the tree). Real usage should pass
// Parameters::sigma (BLNS23's own 232, calibrated for d=512); taken as an
// explicit parameter rather than hardcoded so toy-dimension tests can use
// a value appropriate to their own (much smaller) ring instead of the
// real target's calibration.
[[nodiscard]] std::unique_ptr<FalconTreeNode> build_signing_tree(
    const RingArithmetic& ring, const TrapdoorKey& key, const HighReal& target_sigma);

// Cryptographic deterministic point-in-the-ring hash used by the plain
// message convenience wrapper. It absorbs `message` into SHAKE256,
// consumes 16-bit big-endian words, rejects w >= 5*q, and reduces accepted
// words modulo q until `degree` coefficients have been produced. The 5*q
// cutoff contains exactly five complete residue classes, so the reduction
// is unbiased; at the real q=7933, 5*q=39665 < 2^16.
//
// This intentionally still has NO per-signature salt/nonce field of its
// own. Therefore repeated sign() calls on the same message target the same
// c and differ only in ffSampling's randomized draw. That is a remaining
// plain-wrapper deviation from real FALCON's salted HashToPoint, not a
// weakness in the blind-signature path: a real blind signer never calls
// this helper at all and instead receives an opaque blinded target `c`
// which it signs through sign_target().
[[nodiscard]] PolyQ hash_to_point(const RingArithmetic& ring, const std::string& message);

// Produces a signature via ffSampling on the target this project's own
// A=(f*g^-1,1) convention requires (see header comment above), retrying
// (fresh ffSampling draw, same target) up to `max_attempts` times if the
// resulting (s0,s1) exceeds `norm_bound_squared` - falcon.pdf Algorithm
// 10's own rejection loop (lines 4-8), same reasoning: ffSampling's
// output is Gaussian-distributed but not UNCONDITIONALLY short, so a
// norm check with resampling is required, not optional.
//
// Signs an ARBITRARY target polynomial `target`, not a message this
// function hashes itself. This is what a real blind signer actually
// needs: in the blind-signature protocol, the signer only ever receives
// an opaque blinded target `c` from the client (see specs.txt SS9.3a /
// the NIZK1 blinding relation) and must never learn, let alone hash, the
// underlying message - a signer that internally re-derived its own
// hash_to_point(message) would defeat blindness entirely. sign(message,
// ...) below is the plain (non-blind) convenience wrapper used by this
// reference substrate's own tests/diagnostics so far; sign_target() is
// the one a real signer, or a genuine end-to-end blind-signature test,
// needs to call.
[[nodiscard]] Signature sign_target(
    const RingArithmetic& ring, const TrapdoorKey& key, const FalconTreeNode& tree,
    const PolyQ& target, const BigInt& norm_bound_squared, CryptoRng& rng,
    std::size_t max_attempts = 100U);

// Plain (non-blind) convenience wrapper: signs hash_to_point(message)
// via sign_target().
[[nodiscard]] Signature sign(
    const RingArithmetic& ring, const TrapdoorKey& key, const FalconTreeNode& tree,
    const std::string& message, const BigInt& norm_bound_squared, CryptoRng& rng,
    std::size_t max_attempts = 100U);

// Checks A.s = target (mod q) (this project's own verification equation,
// A=(f*g^-1,1)) AND ||s||^2 <= norm_bound_squared, exactly mirroring
// falcon.pdf's own two-part Verify (norm bound + algebraic relation) -
// this project's blindsig_blns7933.hpp already has
// NTRUTrapdoorGenerator::verify_ntru_relation() for the trapdoor's OWN
// relation; this is the analogous check for a SIGNATURE against a
// PUBLIC key, taking no trapdoor material at all. See sign_target()'s
// own comment for why an arbitrary target (not a message this function
// hashes itself) is the one a real verifier over a blinded target needs.
[[nodiscard]] bool verify_target(
    const RingArithmetic& ring, const PublicKey& public_key, const PolyQ& target,
    const Signature& signature, const BigInt& norm_bound_squared);

// Plain (non-blind) convenience wrapper: verifies against
// hash_to_point(message) via verify_target().
[[nodiscard]] bool verify(
    const RingArithmetic& ring, const PublicKey& public_key, const std::string& message,
    const Signature& signature, const BigInt& norm_bound_squared);

} // namespace tradep2p::blns7933
