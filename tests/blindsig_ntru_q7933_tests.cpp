#include "tradep2p/blindsig_ntru_q7933.hpp"

#include <iostream>
#include <stdexcept>

namespace {

using tradep2p::blindsig::Q7933NTRUSigner;
using tradep2p::blns7933::BigInt;
using tradep2p::blns7933::CryptoRng;
using tradep2p::blns7933::HighReal;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::RingArithmetic;
using tradep2p::blns7933::TrapdoorKey;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

TrapdoorKey known_good_trapdoor() {
    TrapdoorKey key;
    key.f = {0, 0, -3, 0};
    key.g = {0, 1, 2, -3};
    key.F = {-1, -1, 2, 1};
    key.G = {0, -1, 3, 1};
    return key;
}

Q7933NTRUSigner make_toy_backend(std::uint64_t seed) {
    return Q7933NTRUSigner(known_good_trapdoor(), PolyQ{1, 2, 3, 4},
                           RingArithmetic(4, 17), HighReal(20), BigInt(100000),
                           CryptoRng(seed));
}

void test_sign_target_round_trip() {
    auto backend = make_toy_backend(123);
    const PolyQ target{3, 5, 7, 9};
    const auto signature = backend.sign_target(target);
    require(backend.verify_target(target, signature),
            "adapter must verify a signature it genuinely produced");

    auto tampered = signature;
    tampered.s0[0] += 1;
    require(!backend.verify_target(target, tampered),
            "adapter must reject a tampered signature");
}

void test_public_material_is_stable() {
    auto backend = make_toy_backend(456);
    require(backend.degree() == 4U, "toy adapter degree mismatch");
    require(backend.modulus() == 17, "toy adapter modulus mismatch");
    require(backend.b() == PolyQ({1, 2, 3, 4}), "adapter changed B");
    require(backend.public_key().t.size() == 4U, "derived public key has wrong degree");
}

void test_rejects_bad_trapdoor() {
    TrapdoorKey bad = known_good_trapdoor();
    bad.G[0] += 1;
    bool threw = false;
    try {
        Q7933NTRUSigner backend(std::move(bad), PolyQ{1, 2, 3, 4},
                                RingArithmetic(4, 17), HighReal(20), BigInt(100000),
                                CryptoRng(1));
        (void)backend;
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "adapter must reject a trapdoor that fails fG-gF=q");
}

void test_rejects_noncanonical_input() {
    auto backend = make_toy_backend(789);
    bool threw = false;
    try {
        (void)backend.sign_target(PolyQ{3, 5, 17, 9});
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "adapter must reject non-canonical target coefficients");
}

void test_production_bound_constant() {
    require(Q7933NTRUSigner::production_norm_bound_squared() == BigInt(110231552),
            "production q7933 norm bound changed unexpectedly");
}

} // namespace

int main() {
    try {
        test_sign_target_round_trip();
        test_public_material_is_stable();
        test_rejects_bad_trapdoor();
        test_rejects_noncanonical_input();
        test_production_bound_constant();
        std::cout << "blindsig_ntru_q7933_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_ntru_q7933_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
