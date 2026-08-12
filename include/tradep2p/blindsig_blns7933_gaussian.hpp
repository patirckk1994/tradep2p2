#pragma once

// Discrete Gaussian sampler over Z, D_{Z,sigma,0} - the distribution
// FALCON's own NTRUGen (Algorithm 5, falcon.pdf SS3.8.2) draws each
// coefficient of a trapdoor candidate f,g from, at
//
//     sigma_{f,g} = 1.17 * sqrt(q / (2*n))                          (3.27)
//
// FALCON's own reference implementation samples this via a sum of several
// draws from a NARROWER Gaussian through a precomputed CDT table (falcon.pdf
// eq. (3.29)) - an engineering trick specifically needed because their base
// sampler only supports sigma <= sigma_max. This module deliberately does
// NOT do that: per this project's standing rule (never trade away
// precision, only time/memory), it samples directly from the TARGET sigma
// via straightforward rejection sampling, evaluated at 256-digit precision
// (matching blindsig_blns7933_babai_reduce.hpp's HighReal), with a tail
// cutoff chosen so the truncation error is far below any cryptographically
// relevant threshold (see kTailSigmas below). Slower than FALCON's table
// trick; exactly as correct.

#include "tradep2p/blindsig_blns7933_csprng.hpp"
#include "tradep2p/blindsig_blns7933_highreal.hpp"

#include <cstdint>
#include <vector>

namespace tradep2p::blns7933 {

// Samples one coefficient from D_{Z,sigma,0} by rejection sampling:
// draw z uniformly from the integers in [-tail, tail] (tail = ceil(cutoff *
// sigma)), accept with probability exp(-z^2 / (2*sigma^2)), evaluated and
// compared at 256-digit precision against a high-precision uniform draw (not
// a plain double) so the accept/reject decision carries no double-precision
// quantization bias. sigma must be positive and finite.
[[nodiscard]] std::int64_t sample_discrete_gaussian(long double sigma, CryptoRng& rng);

// Samples `degree` independent coefficients from D_{Z,sigma,0} - what
// NTRUGen actually needs for one of f or g.
[[nodiscard]] std::vector<std::int64_t> sample_discrete_gaussian_poly(
    std::size_t degree, long double sigma, CryptoRng& rng);

// The general form falcon.pdf's SamplerZ(mu, sigma') (Algorithm 15)
// specifies: samples from D_{Z,mu,sigma}, an ARBITRARY real center mu, not
// just 0 - what ffSampling needs (its targets t0,t1 are generally
// non-integer reals produced by the LDL-tree recursion), unlike
// NTRUGen's mu=0 case above. A separate function, not a generalization of
// sample_discrete_gaussian() in place, specifically so the
// already-verified TrapGen call site above is untouched by this addition.
// Still returns an integer z (falcon.pdf Algorithm 15's own return type is
// z in Z, even though mu is real) - only sigma/mu are HighReal, since
// callers here already hold both at full 256-digit precision from prior
// real-ring computation and converting down to long double first would
// throw away exactly the precision this module exists to preserve.
[[nodiscard]] std::int64_t sample_discrete_gaussian_centered(
    const HighReal& sigma, const HighReal& mu, CryptoRng& rng);

} // namespace tradep2p::blns7933
