#include "tradep2p/blindsig_blns7933.hpp"

#include <iostream>
#include <random>
#include <stdexcept>

namespace {

using tradep2p::blns7933::NTRUTrapdoorGenerator;
using tradep2p::blns7933::PolyQ;
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
    key.f = {1, 0, 0, 0};
    key.g = {2, 3, 4, 5};
    const auto pk = gen.derive_public(key);
    require(pk.h == PolyQ({2, 3, 4, 5}), "g/f with f=1 must equal g");
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

void test_generate_fails_closed() {
    RingArithmetic ring(4, 17);
    NTRUTrapdoorGenerator gen(ring);
    std::mt19937_64 rng(1);
    require_throws<std::logic_error>([&] { (void)gen.generate(rng); },
                                     "unimplemented TrapGen must fail closed");
}

} // namespace

int main() {
    try {
        test_negacyclic_multiplication_toy();
        test_inverse_toy();
        test_public_derivation_toy();
        test_ntru_relation_oracle_toy();
        test_generate_fails_closed();
        std::cout << "blindsig_blns7933_tests: OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "blindsig_blns7933_tests: FAIL: " << e.what() << '\n';
        return 1;
    }
}
