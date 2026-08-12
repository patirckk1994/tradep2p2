#pragma once

// The single canonical 256-digit-precision real type shared across the
// BLNS7933 reference modules that need to pass real values across their
// own interface boundaries (the Gaussian sampler's center, the LDL tree's
// values, ffSampling's targets). Internal HELPER FUNCTIONS built on top of
// this type (e.g. a module's own dense-linear-system solver) are still
// deliberately duplicated per translation unit, matching this codebase's
// existing precedent (see blindsig_blns7933_quality.cpp's own comment) -
// only the TYPE itself needs one canonical definition, so two modules
// passing a HighReal to each other are guaranteed to mean the same thing.
//
// 256 decimal digits is the same precision already established by
// blindsig_blns7933_babai_reduce.cpp and blindsig_blns7933_quality.cpp -
// this header does not introduce a new precision choice, only names the
// existing one so it can be shared.

#include <boost/multiprecision/cpp_dec_float.hpp>

namespace tradep2p::blns7933 {

using HighReal = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<256>>;

} // namespace tradep2p::blns7933
