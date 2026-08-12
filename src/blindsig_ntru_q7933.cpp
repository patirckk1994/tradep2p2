#include "tradep2p/blindsig_ntru_q7933.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace tradep2p::blindsig {
namespace {

blns7933::HighReal production_sigma() {
    return blns7933::HighReal(232);
}

} // namespace

blns7933::BigInt Q7933NTRUSigner::production_norm_bound_squared() {
    // BLNS23 Table-2 shape used throughout the q=7933 reference path:
    // beta_s^2 = sigma^2 * 2*n*d, with sigma=232, n=2, d=512.
    // 232^2 * 2 * 2 * 512 = 110,231,552.
    return blns7933::BigInt(110231552);
}

Q7933NTRUSigner::Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor,
                                 blns7933::PolyQ b)
    : Q7933NTRUSigner(std::move(trapdoor), std::move(b), blns7933::CryptoRng{}) {}

Q7933NTRUSigner::Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor,
                                 blns7933::PolyQ b,
                                 blns7933::CryptoRng rng)
    : Q7933NTRUSigner(std::move(trapdoor), std::move(b),
                      blns7933::RingArithmetic(blns7933::Parameters::degree,
                                               blns7933::Parameters::modulus),
                      production_sigma(), production_norm_bound_squared(),
                      std::move(rng)) {}

Q7933NTRUSigner::Q7933NTRUSigner(blns7933::TrapdoorKey trapdoor,
                                 blns7933::PolyQ b,
                                 blns7933::RingArithmetic ring,
                                 blns7933::HighReal target_sigma,
                                 blns7933::BigInt norm_bound_squared,
                                 blns7933::CryptoRng rng)
    : ring_(std::move(ring)),
      trapdoor_(std::move(trapdoor)),
      b_(std::move(b)),
      norm_bound_squared_(std::move(norm_bound_squared)),
      rng_(std::move(rng)) {
    if (ring_.degree() == 0U || ring_.modulus() <= 2) {
        throw std::invalid_argument("q7933 signer adapter: invalid ring parameters");
    }
    if (target_sigma <= 0) {
        throw std::invalid_argument("q7933 signer adapter: target sigma must be positive");
    }
    if (norm_bound_squared_ <= 0) {
        throw std::invalid_argument("q7933 signer adapter: norm bound must be positive");
    }

    const auto require_key_poly_size = [this](const blns7933::PolyQ& v, const char* name) {
        if (v.size() != ring_.degree()) {
            throw std::invalid_argument(std::string("q7933 signer adapter: trapdoor ") + name +
                                        " has wrong degree");
        }
    };
    require_key_poly_size(trapdoor_.f, "f");
    require_key_poly_size(trapdoor_.g, "g");
    require_key_poly_size(trapdoor_.F, "F");
    require_key_poly_size(trapdoor_.G, "G");
    validate_canonical_poly(ring_, b_, "B");

    blns7933::NTRUTrapdoorGenerator generator(ring_);
    if (!generator.verify_ntru_relation(trapdoor_)) {
        throw std::invalid_argument("q7933 signer adapter: trapdoor fails exact fG-gF=q relation");
    }

    public_key_ = generator.derive_public(trapdoor_);
    validate_canonical_poly(ring_, public_key_.t, "public key t");

    // This is intentionally the expensive startup step. It must happen once
    // per backend lifetime, never once per signature request.
    signing_tree_ = blns7933::build_signing_tree(ring_, trapdoor_, target_sigma);
    if (!signing_tree_) {
        throw std::runtime_error("q7933 signer adapter: signing-tree construction returned null");
    }
}

Q7933NTRUSigner::~Q7933NTRUSigner() {
    wipe_trapdoor();
}

void Q7933NTRUSigner::validate_canonical_poly(const blns7933::RingArithmetic& ring,
                                              const blns7933::PolyQ& value,
                                              const char* field_name) {
    if (value.size() != ring.degree()) {
        throw std::invalid_argument(std::string("q7933 signer adapter: ") + field_name +
                                    " has wrong degree");
    }
    const auto q = ring.modulus();
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] < 0 || value[i] >= q) {
            throw std::invalid_argument(std::string("q7933 signer adapter: ") + field_name +
                                        " contains a non-canonical coefficient at index " +
                                        std::to_string(i));
        }
    }
}

blns7933::Signature Q7933NTRUSigner::sign_target(const blns7933::PolyQ& target) {
    validate_canonical_poly(ring_, target, "target");
    std::lock_guard<std::mutex> lock(sign_mutex_);
    return blns7933::sign_target(ring_, trapdoor_, *signing_tree_, target,
                                 norm_bound_squared_, rng_);
}

bool Q7933NTRUSigner::verify_target(const blns7933::PolyQ& target,
                                    const blns7933::Signature& signature) const {
    validate_canonical_poly(ring_, target, "target");
    return blns7933::verify_target(ring_, public_key_, target, signature,
                                   norm_bound_squared_);
}

void Q7933NTRUSigner::wipe_trapdoor() noexcept {
    auto wipe = [](blns7933::PolyQ& v) {
        if (!v.empty()) {
            OPENSSL_cleanse(v.data(), v.size() * sizeof(v[0]));
        }
        v.clear();
        v.shrink_to_fit();
    };
    wipe(trapdoor_.f);
    wipe(trapdoor_.g);
    wipe(trapdoor_.F);
    wipe(trapdoor_.G);
}

} // namespace tradep2p::blindsig
