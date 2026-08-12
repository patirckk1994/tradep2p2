#include "tradep2p/blindsig_blns7933.hpp"

#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blns7933::CryptoRng;
using tradep2p::blns7933::NTRUTrapdoorGenerator;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::PublicKey;
using tradep2p::blns7933::RingArithmetic;
using tradep2p::blns7933::TrapdoorKey;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename ExceptionT, typename Fn>
void require_throws(Fn&& fn, const char* message) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return;
    }
    throw std::runtime_error(message);
}

void test_negacyclic_multiplication_toy() {
    RingArithmetic ring(4, 17);
    // x^3 * x == x^4 == -1 in Z_17[x]/(x^4+1).
    require(ring.mul(PolyQ{0, 0, 0, 1}, PolyQ{0, 1}) == PolyQ({16, 0, 0, 0}),
            "negacyclic wrap must apply x^d = -1");
}

void test_inverse_toy() {
    RingArithmetic ring(4, 17);
    const PolyQ a{3, 1, 0, 0};
    const auto inv = ring.inverse(a);
    require(inv.has_value(), "toy polynomial should be invertible");
    require(ring.mul(a, *inv) == PolyQ({1, 0, 0, 0}),
            "inverse must multiply to one");
}

void test_public_derivation_toy() {
    RingArithmetic ring(4, 17);
    NTRUTrapdoorGenerator gen(ring);
    TrapdoorKey key;
    key.f = {2, 3, 4, 5};
    key.g = {1, 0, 0, 0};
    const auto pk = gen.derive_public(key);
    require(pk.t == PolyQ({2, 3, 4, 5}), "BLNS t=f/g with g=1 must equal f");
}

void test_ntru_relation_oracle_toy() {
    RingArithmetic ring(4, 17);
    NTRUTrapdoorGenerator gen(ring);

    TrapdoorKey good;
    good.f = {1, 0, 0, 0};
    good.g = {0, 0, 0, 0};
    good.F = {0, 0, 0, 0};
    good.G = {17, 0, 0, 0};
    require(gen.verify_ntru_relation(good), "exact fG-gF=q relation must verify");

    TrapdoorKey bad = good;
    bad.G[0] = 16;
    require(!gen.verify_ntru_relation(bad), "wrong exact NTRU relation must fail");
}

// generate() now performs candidate sampling, invertibility/quality
// checks, NTRUSolve, and reduction (blindsig_blns7933_gaussian.hpp,
// blindsig_blns7933_quality.hpp) - it no longer fails closed by design.
// This replaces the old test_generate_fails_closed(), which would now be
// asserting the WRONG thing (that the tested behavior doesn't exist).
void test_generate_produces_valid_trapdoor_toy() {
    RingArithmetic ring(4, 17);
    NTRUTrapdoorGenerator gen(ring);
    CryptoRng rng(1);
    const TrapdoorKey key = gen.generate(rng);

    require(gen.verify_ntru_relation(key),
            "generate() must return a key satisfying f*G - g*F = q exactly");

    // derive_public() itself throws if g is not invertible - reaching this
    // line without an exception is itself part of what's being checked.
    const PublicKey pub = gen.derive_public(key);
    require(pub.t.size() == 4U, "derived public key must have the ring's degree");
}

void test_generate_is_repeatable_with_same_rng_seed() {
    // Not a security property (this is exactly why the RNG needs to be a
    // real CSPRNG before this is trusted for anything beyond testing - see
    // generate()'s own header comment) - just confirms determinism given a
    // fixed seed, useful for reproducing a specific run while debugging.
    RingArithmetic ring(4, 17);
    NTRUTrapdoorGenerator gen(ring);
    CryptoRng rng_a(99);
    CryptoRng rng_b(99);
    const TrapdoorKey key_a = gen.generate(rng_a);
    const TrapdoorKey key_b = gen.generate(rng_b);
    require(key_a.f == key_b.f && key_a.g == key_b.g &&
                key_a.F == key_b.F && key_a.G == key_b.G,
            "identical RNG seed must produce an identical trapdoor");
}

} // namespace

int main() {
    try {
        test_negacyclic_multiplication_toy();
        test_inverse_toy();
        test_public_derivation_toy();
        test_ntru_relation_oracle_toy();
        test_generate_produces_valid_trapdoor_toy();
        test_generate_is_repeatable_with_same_rng_seed();
        std::cout << "blindsig_blns7933_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
