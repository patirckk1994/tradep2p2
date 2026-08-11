#include "tradep2p/blindsig_blns7933_gaussian.hpp"

#include <boost/multiprecision/cpp_int.hpp>

#include <cmath>
#include <stdexcept>

namespace tradep2p::blns7933 {
namespace {

// Tail cutoff: P(|Z| > kTailSigmas) <= exp(-kTailSigmas^2 / 2) ~ 1e-347 for
// kTailSigmas = 40 - vastly below any threshold that matters here (the
// paper's own smoothing target is 2^-139, ~1e-42). Chosen generously wide
// on purpose: the cost is a marginally larger rejection range, not
// precision, and time/range is exactly what this project is willing to
// spend to avoid ever touching the tail-truncation error as a real
// concern.
constexpr long double kTailSigmas = 40.0L;

// A uniform draw in [0,1) built from 256 bits of std::mt19937_64 output,
// converted to 256-digit-precision HighReal. Deliberately not a plain
// double: the accept/reject comparison below is only as trustworthy as its
// least-precise input, and a double's ~53 bits would silently reintroduce
// the exact class of quantization bias this module exists to avoid.
HighReal uniform_high_real(std::mt19937_64& rng) {
    boost::multiprecision::cpp_int bits = 0;
    for (int word = 0; word < 4; ++word) {
        bits <<= 64;
        bits += boost::multiprecision::cpp_int(rng());
    }
    const HighReal numerator(bits.convert_to<std::string>());
    const HighReal denominator = boost::multiprecision::pow(HighReal(2), 256);
    return numerator / denominator;
}

} // namespace

std::int64_t sample_discrete_gaussian(long double sigma, std::mt19937_64& rng) {
    if (!(sigma > 0.0L) || !std::isfinite(static_cast<double>(sigma))) {
        throw std::invalid_argument("discrete Gaussian sigma must be positive and finite");
    }

    const auto tail = static_cast<std::int64_t>(std::ceil(static_cast<double>(kTailSigmas * sigma)));
    std::uniform_int_distribution<std::int64_t> candidate_dist(-tail, tail);

    const HighReal high_sigma(std::to_string(static_cast<double>(sigma)));
    const HighReal two_sigma_sq = HighReal(2) * high_sigma * high_sigma;

    while (true) {
        const std::int64_t z = candidate_dist(rng);
        const HighReal z_sq = HighReal(z) * HighReal(z);
        const HighReal accept_probability = boost::multiprecision::exp(-z_sq / two_sigma_sq);
        const HighReal u = uniform_high_real(rng);
        if (u < accept_probability) {
            return z;
        }
    }
}

std::vector<std::int64_t> sample_discrete_gaussian_poly(
    std::size_t degree, long double sigma, std::mt19937_64& rng) {
    std::vector<std::int64_t> out;
    out.reserve(degree);
    for (std::size_t i = 0; i < degree; ++i) {
        out.push_back(sample_discrete_gaussian(sigma, rng));
    }
    return out;
}

std::int64_t sample_discrete_gaussian_centered(
    const HighReal& sigma, const HighReal& mu, std::mt19937_64& rng) {
    if (!(sigma > 0)) {
        throw std::invalid_argument("discrete Gaussian sigma must be positive");
    }

    // floor(mu) as an integer center for the candidate range - mu itself
    // may be fractional (that's the whole point of the "centered" variant),
    // but the CANDIDATE integers only need to bracket it widely enough for
    // the same kTailSigmas margin used by the mu=0 case above.
    const HighReal mu_floor_real = boost::multiprecision::floor(mu);
    const auto mu_floor = static_cast<std::int64_t>(mu_floor_real.convert_to<long long>());

    const auto tail = static_cast<std::int64_t>(
        std::ceil(static_cast<double>(kTailSigmas) * static_cast<double>(sigma.convert_to<long double>())));
    std::uniform_int_distribution<std::int64_t> candidate_dist(mu_floor - tail, mu_floor + tail + 1);

    const HighReal two_sigma_sq = HighReal(2) * sigma * sigma;

    while (true) {
        const std::int64_t z = candidate_dist(rng);
        const HighReal diff = HighReal(z) - mu;
        const HighReal accept_probability = boost::multiprecision::exp(-(diff * diff) / two_sigma_sq);
        const HighReal u = uniform_high_real(rng);
        if (u < accept_probability) {
            return z;
        }
    }
}

} // namespace tradep2p::blns7933
