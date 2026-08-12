#include "tradep2p/blindsig_blns7933_sign.hpp"

#include "tradep2p/blindsig_blns7933.hpp"

#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::CryptoRng;
using tradep2p::blns7933::HighReal;
using tradep2p::blns7933::PublicKey;
using tradep2p::blns7933::RingArithmetic;
using tradep2p::blns7933::Signature;
using tradep2p::blns7933::TrapdoorKey;
using tradep2p::blns7933::build_signing_tree;
using tradep2p::blns7933::sign;
using tradep2p::blns7933::verify;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// The exact d=4, q=17 trapdoor this project's own TrapGen produced and
// exactly verified (f*G-g*F=17) earlier this session - reused across
// this whole module's tests, same reasoning as
// blindsig_blns7933_ldl_tests.cpp: an arbitrary hand-picked (f,g,F,G)
// isn't guaranteed to give a usable trapdoor (e.g. a positive-definite
// Gram matrix), and this one is known-good.
TrapdoorKey known_good_trapdoor() {
    TrapdoorKey key;
    key.f = {0, 0, -3, 0};
    key.g = {0, 1, 2, -3};
    key.F = {-1, -1, 2, 1};
    key.G = {0, -1, 3, 1};
    return key;
}

// Generous for a toy-scale correctness test - the point here is
// confirming the algebra (Sign produces something Verify accepts, and
// rejects tampering), not calibrating a tight, security-meaningful bound
// for this dimension.
constexpr std::int64_t kToyNormBoundSquared = 100000;
const HighReal kToySigma(20);

void test_sign_verify_round_trip_toy() {
    const RingArithmetic ring(4, 17);
    const TrapdoorKey key = known_good_trapdoor();
    const auto tree = build_signing_tree(ring, key, kToySigma);

    const PublicKey public_key = tradep2p::blns7933::NTRUTrapdoorGenerator(ring).derive_public(key);

    CryptoRng rng(123);
    const Signature signature =
        sign(ring, key, *tree, "hello blns7933", BigInt(kToyNormBoundSquared), rng);

    require(verify(ring, public_key, "hello blns7933", signature, BigInt(kToyNormBoundSquared)),
            "a genuinely produced signature must verify against its own message and public key");
}

void test_verify_rejects_wrong_message() {
    const RingArithmetic ring(4, 17);
    const TrapdoorKey key = known_good_trapdoor();
    const auto tree = build_signing_tree(ring, key, kToySigma);
    const PublicKey public_key = tradep2p::blns7933::NTRUTrapdoorGenerator(ring).derive_public(key);

    CryptoRng rng(456);
    const Signature signature = sign(ring, key, *tree, "message A", BigInt(kToyNormBoundSquared), rng);

    require(!verify(ring, public_key, "message B", signature, BigInt(kToyNormBoundSquared)),
            "a signature for one message must not verify against a different message");
}

void test_verify_rejects_corrupted_signature() {
    const RingArithmetic ring(4, 17);
    const TrapdoorKey key = known_good_trapdoor();
    const auto tree = build_signing_tree(ring, key, kToySigma);
    const PublicKey public_key = tradep2p::blns7933::NTRUTrapdoorGenerator(ring).derive_public(key);

    CryptoRng rng(789);
    Signature signature = sign(ring, key, *tree, "tamper test", BigInt(kToyNormBoundSquared), rng);
    require(verify(ring, public_key, "tamper test", signature, BigInt(kToyNormBoundSquared)),
            "sanity: genuine signature must verify before corrupting it");

    signature.s0[0] += 1;
    require(!verify(ring, public_key, "tamper test", signature, BigInt(kToyNormBoundSquared)),
            "a corrupted signature must not verify - the check must not be vacuous");
}

void test_hash_to_point_is_deterministic() {
    const RingArithmetic ring(4, 17);
    const auto c1 = tradep2p::blns7933::hash_to_point(ring, "same message");
    const auto c2 = tradep2p::blns7933::hash_to_point(ring, "same message");
    const auto c3 = tradep2p::blns7933::hash_to_point(ring, "different message");
    require(c1 == c2, "hash_to_point must be deterministic given the same message");
    require(c1 != c3, "hash_to_point must (almost certainly) differ for different messages");
}

} // namespace

int main() {
    try {
        test_sign_verify_round_trip_toy();
        test_verify_rejects_wrong_message();
        test_verify_rejects_corrupted_signature();
        test_hash_to_point_is_deterministic();
        std::cout << "blindsig_blns7933_sign_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_sign_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
