#include "tradep2p/blindsig_blns7933.hpp"
#include "tradep2p/blindsig_keystore_q7933.hpp"
#include "tradep2p/keystore.hpp" // KeystoreAlreadyExistsError / KeystoreAuthenticationError / KeystoreFormatError

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

using tradep2p::blindsig::Q7933Keystore;
using tradep2p::blns7933::Parameters;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::PublicKey;
using tradep2p::blns7933::TrapdoorKey;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename ExceptionT, typename Fn>
void require_throws(Fn&& fn, const std::string& message) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error(message + " (wrong exception type thrown: " + error.what() + ")");
    }
    throw std::runtime_error(message + " (no exception thrown)");
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("test helper: cannot open " + path.string());
    }
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void write_all(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("test helper: cannot create " + path.string());
    }
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::filesystem::path make_temp_dir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_q7933_ks_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
}

// ---------------------------------------------------------------------------
// A REAL d=512, q=7933 trapdoor (seed 99, deliberately different from
// rust_crosscheck_dump_512.cpp's own seed 4 - so kFixtureT below is NOT
// cross-checkable against that file's T constant, they are different
// keypairs), generated once via a throwaway diagnostic and embedded here
// as a literal. Real measured cost at a proper -O3 build: ~215s at d=512
// (an earlier attempt at this same task, run before CMakePresets.json's
// missing CMAKE_BUILD_TYPE was caught and fixed, ran over 20 real minutes
// unoptimized before being killed - see that commit's own message).
// Paying the real cost once to produce a fixture keeps this test suite in
// the same "fast, deterministic" tier as every other ctest-registered
// test in this project, matching this codebase's established convention
// (real d=512 generation stays in manual, non-ctest diagnostics; fast
// tests reuse either a toy dimension or, as here, a pre-generated
// real-scale fixture).
// ---------------------------------------------------------------------------

// clang-format off
constexpr std::array<std::int64_t, 512> kFixtureF = {
    1,3,-1,-3,-9,-3,5,4,-4,2,1,1,6,-1,0,-1,7,-1,-1,-2,
    3,1,1,-2,2,-1,3,0,2,4,7,-1,0,3,1,5,2,-5,2,0,
    0,-4,-1,3,-2,-5,0,-4,1,-2,3,-1,4,1,6,0,0,-2,-4,2,
    -3,1,4,-3,-4,4,-2,0,-1,4,5,1,7,-4,-2,-2,5,2,1,6,
    0,-2,-3,0,-6,5,4,-3,-1,-3,-3,0,3,1,-1,3,3,2,-3,5,
    -8,-1,1,0,-3,2,1,-2,4,1,3,-2,-8,-3,-3,3,3,-3,-2,2,
    3,6,6,-1,0,4,6,-2,-4,-3,0,-2,-1,-1,-6,1,-2,-2,-3,2,
    -3,-2,0,-2,1,0,-2,-3,5,3,3,1,3,-6,-3,-1,-2,7,-2,-2,
    -2,1,0,-4,-6,3,-5,1,-4,-2,6,6,7,-1,-5,1,1,2,1,6,
    1,4,1,2,-2,-2,3,1,0,7,2,0,2,-2,-1,2,-2,1,-3,2,
    -5,2,-1,1,1,-2,-4,-1,-1,-1,0,8,-7,-2,-3,-2,2,-1,-1,1,
    -2,-4,1,0,3,1,-4,-2,-5,-5,-1,4,-1,2,3,0,1,-1,-3,2,
    -2,3,-1,1,6,-2,0,-2,-2,-2,3,0,1,-6,4,0,-1,1,-1,1,
    -3,8,4,0,5,-3,2,2,-7,1,1,-1,-1,1,-3,4,-2,-3,0,6,
    -1,1,1,4,1,-2,0,5,-1,-2,3,-4,2,-1,5,4,0,-2,1,-2,
    9,-5,0,-2,3,1,-2,0,3,-3,2,4,3,2,1,-7,3,-1,6,-6,
    -4,4,-5,1,1,2,0,2,-3,-1,6,-4,1,5,0,-2,3,-9,-2,4,
    -3,0,1,-5,-2,-1,4,2,-1,-2,-1,-3,0,5,0,-2,-5,1,4,-2,
    -5,-2,3,-1,-2,2,-4,1,3,-5,-4,3,-2,0,6,2,2,1,-1,0,
    -5,0,4,-1,1,2,-1,4,-3,-3,0,-2,-4,0,0,2,-1,0,3,2,
    0,-3,0,5,2,0,2,3,-2,4,0,2,-3,5,-2,-4,4,6,3,3,
    -2,-3,-2,0,2,-2,1,-2,4,5,2,-1,2,-2,-3,-1,4,2,2,-3,
    -3,3,-3,2,5,2,3,2,-2,4,2,2,-1,3,2,4,-5,-1,2,-4,
    -3,3,1,0,5,0,2,3,2,2,3,1,2,4,6,6,1,-1,0,0,
    -6,3,8,1,-1,4,-7,-1,-4,-4,-4,-2,0,-1,2,-4,1,1,4,1,
    0,1,2,-2,2,0,3,-3,2,0,-2,2
};
constexpr std::array<std::int64_t, 512> kFixtureG = {
    -1,-1,-3,3,1,-4,-2,-3,2,6,1,-4,-2,-3,0,-4,2,-1,-7,-1,
    0,1,6,-1,-4,-3,1,2,2,4,2,-1,-2,2,4,0,1,-3,2,2,
    2,-4,0,4,5,2,-11,-1,3,0,-1,-4,-2,-1,-3,-2,5,-4,2,-1,
    5,0,-3,0,1,3,-4,-1,-1,2,-1,1,0,-2,2,5,-6,1,-2,5,
    3,3,4,1,-3,-8,6,-1,3,-4,-1,-6,-2,-6,-2,0,3,0,4,-3,
    1,2,-1,-1,1,-1,0,2,0,-1,0,-4,-1,-4,0,2,5,4,-7,6,
    -1,0,0,1,-2,1,1,0,1,1,4,2,-4,1,1,2,1,0,4,-1,
    0,2,-3,-1,-1,-1,0,1,0,1,1,-4,0,0,1,4,3,-7,4,1,
    -1,0,5,-4,-8,2,-3,-7,-1,1,5,0,1,-4,2,-1,4,4,3,-2,
    0,-2,-1,-5,-3,-2,-4,1,-2,5,-1,2,0,3,-2,5,3,0,3,6,
    2,5,1,4,-2,-4,-1,1,7,8,-12,-3,9,-3,2,3,-1,2,-5,3,
    -1,-1,-5,-1,0,-3,-2,1,-3,4,-3,2,6,-3,6,-1,-2,3,2,-2,
    3,-4,1,-2,-3,2,1,-1,-4,-3,2,-1,2,3,-2,2,4,1,11,0,
    -2,2,1,-2,1,2,1,3,1,4,2,8,-4,1,3,-1,-4,0,-3,1,
    4,-6,6,-1,2,-3,2,-2,0,-1,-2,-2,2,3,1,0,-1,3,-2,-4,
    -1,2,-3,0,0,1,-1,5,5,4,-2,-4,-2,-1,2,-1,2,0,0,-2,
    3,-1,0,-5,2,0,4,-1,6,-4,-2,0,-1,0,-3,-3,3,-5,1,-1,
    0,5,2,2,-1,-7,-1,-1,3,-2,4,6,0,-6,-4,6,-6,-2,2,0,
    6,2,1,-4,7,0,-2,0,0,3,1,-3,-1,0,0,7,0,-10,2,-5,
    2,5,5,3,6,-1,-6,1,1,1,1,5,1,-1,-2,-6,2,0,0,3,
    2,2,-2,2,0,-4,-3,3,-4,-1,0,4,-5,3,7,2,4,2,0,-3,
    1,-2,-3,1,0,3,5,2,0,-2,-2,-1,1,-4,1,1,-2,-3,2,4,
    -1,-2,4,0,-3,0,1,2,1,-1,-8,2,8,-3,1,4,-1,2,1,-1,
    3,-3,1,-2,4,-5,5,2,-2,-4,-2,5,2,2,0,-2,4,4,-4,-3,
    -5,3,1,2,4,0,-4,-4,8,-3,-1,-6,5,0,2,0,0,0,-3,-1,
    2,1,0,3,5,-3,-6,-1,-6,-1,1,-1
};
constexpr std::array<std::int64_t, 512> kFixtureCapF = {
    5,9,-25,-25,5,2,0,8,5,-11,8,5,6,21,-2,31,10,-5,-31,13,
    7,10,1,3,25,33,-6,-5,18,19,35,17,-12,20,10,13,-4,-13,-15,17,
    10,11,0,-12,0,11,-8,16,16,11,17,-16,-24,-19,-1,-1,-8,6,32,18,
    34,1,-38,3,-11,18,1,3,-31,-33,-26,-25,-20,-41,-11,5,6,9,-10,14,
    21,-22,0,-16,0,5,22,5,19,-13,-15,-16,-35,-24,-4,37,4,1,-31,3,
    18,-26,29,-21,-19,17,13,-24,-13,3,-12,-7,-24,29,10,-6,25,-17,-18,22,
    -3,10,25,-17,14,34,-11,-24,-1,31,20,4,7,-2,9,-9,5,-7,-3,15,
    12,-31,18,11,-8,-2,27,-7,-6,5,-11,-13,34,17,-1,-27,-25,-28,-18,15,
    10,2,15,-6,14,-27,24,-8,-16,13,-1,-29,-27,-12,-35,39,-13,2,-36,16,
    9,-9,-14,4,5,2,3,-19,3,18,-14,3,-34,-8,1,6,13,-22,11,-5,
    -7,-22,-11,9,7,30,16,-27,21,-3,-1,20,2,-17,-33,8,3,-17,-12,15,
    -12,18,15,37,24,10,31,7,-27,8,16,18,14,13,-29,-6,-16,-16,5,5,
    -19,29,-30,27,-10,-15,19,0,25,-20,8,-2,-12,2,29,3,-13,-9,13,3,
    36,23,29,-11,27,-15,30,-13,15,-4,4,25,-1,21,15,32,18,3,6,-34,
    -7,-27,-24,-2,-15,-1,-8,24,-13,18,12,-27,-10,-10,-3,-14,23,-31,5,-2,
    -30,22,-2,18,21,-22,12,3,-27,-31,-8,16,11,19,19,-17,-12,-6,3,-30,
    9,-4,-12,19,9,5,14,-36,13,-6,1,22,-21,-7,-3,11,-36,16,0,-27,
    -9,-5,-4,-1,14,-11,6,10,-11,14,7,36,-19,29,4,-1,9,-1,29,-20,
    -24,7,-16,43,4,27,12,4,0,-41,5,-18,-15,2,-5,-20,-22,-16,-13,-7,
    18,-3,5,8,-22,4,3,4,-26,-16,11,29,2,29,2,7,-38,18,8,-13,
    29,-10,5,7,0,-7,-14,9,5,7,-11,5,9,-9,-5,25,-5,-11,-26,-7,
    5,-42,-6,-11,-34,-16,-16,-23,0,-13,2,23,-2,3,17,-7,18,7,7,51,
    -7,-14,-13,10,-16,-13,-43,-2,0,-6,3,-12,5,8,10,6,-11,-2,-21,25,
    -6,34,-18,-10,-18,21,8,-8,14,23,-6,-14,2,1,-21,-32,6,6,35,17,
    -28,-25,12,3,-26,39,15,6,16,1,8,-22,-9,29,9,3,2,3,-7,-8,
    -2,9,23,14,-30,13,3,-9,-16,-44,-8,-40
};
constexpr std::array<std::int64_t, 512> kFixtureCapG = {
    21,-1,-5,-27,1,0,-3,7,20,6,11,2,7,-11,-5,16,-26,21,-2,18,
    -15,-3,18,-12,-3,33,-9,-22,0,6,-42,-22,-2,9,-4,-11,35,-4,20,0,
    -33,-14,-43,23,2,5,1,-3,5,23,11,1,18,38,-20,-25,-26,-18,1,15,
    26,19,1,-9,11,-11,-27,16,22,-15,4,-30,3,0,-9,44,-16,21,18,-10,
    -41,-32,-10,0,-8,5,24,-6,15,6,-9,-34,5,33,4,-7,-12,50,11,-3,
    -34,-6,3,-1,-7,20,6,-3,-8,-2,15,-8,12,-20,25,34,6,-28,14,-23,
    6,-42,5,29,-26,-10,-7,19,-28,-5,16,26,-3,-5,45,-14,-2,5,-32,-17,
    -6,9,44,-18,-16,3,9,-16,14,0,17,25,-12,-1,-17,7,2,3,-11,-7,
    -7,-8,13,23,5,4,-25,-14,0,-5,9,-9,36,-9,-28,-25,6,8,-1,8,
    8,-7,-18,-2,-1,-10,-2,-21,35,9,6,-21,-14,-13,-2,23,9,-8,-17,11,
    -15,-29,-20,13,2,18,28,6,3,17,-47,35,-17,11,-6,18,11,-18,-9,25,
    -1,22,-2,-6,13,-12,-4,28,13,-12,-2,28,9,-7,-9,-9,12,-8,26,0,
    -15,17,14,-24,3,3,1,-1,-7,12,-11,2,-7,3,-15,1,-22,-23,-14,-39,
    -6,-7,-17,0,-2,8,-5,-33,7,22,1,-47,1,2,-7,-2,4,13,15,7,
    14,14,3,-29,36,-24,23,-20,29,16,26,-4,-9,-42,20,-26,22,-23,6,3,
    -46,-17,14,28,-13,14,-26,18,7,1,-21,19,36,-8,-5,-1,17,-16,6,-1,
    -33,-14,-6,20,3,2,27,-1,-2,-11,-9,3,2,-38,-25,-11,-29,-2,19,-1,
    -13,-40,0,-6,20,-6,28,12,5,-31,17,13,26,25,33,-19,2,-18,-34,10,
    9,15,-34,-5,-25,18,-5,1,24,9,6,15,-21,8,14,-24,22,-9,10,-21,
    3,-2,-39,7,4,17,-24,9,7,-38,-26,-36,23,-22,5,18,13,-21,-39,-14,
    -7,2,26,-19,0,3,20,18,15,-4,39,19,29,27,-10,-3,-17,-19,4,-42,
    9,-2,13,2,-10,12,-32,5,-8,-26,-26,5,13,10,6,14,-10,8,4,-40,
    4,-5,-12,8,16,-2,-25,25,11,19,-14,19,31,-34,3,-15,-10,-14,22,2,
    -29,37,-6,-1,-7,11,-6,24,-1,-19,3,0,11,15,-14,-6,-13,-20,-14,-1,
    21,-2,-10,-2,-11,2,13,-11,-5,22,-28,6,5,4,6,-3,-15,-12,-15,-22,
    10,-27,-6,11,16,-22,1,-19,16,-37,1,7
};
constexpr std::array<std::int64_t, 512> kFixtureT = {
    1203,7401,3009,2548,1315,7721,4226,6912,4355,4100,7762,4243,4826,3709,1606,3702,2797,4303,6927,3275,
    3481,7070,1302,4512,555,2327,5404,6927,7271,4179,6292,3258,1606,7712,508,3401,6328,6381,5790,2285,
    7460,351,4626,403,7210,5627,1754,6762,3983,6570,2526,5843,1112,4047,2640,4280,5194,4261,6325,2988,
    5253,230,3979,5999,6631,6345,166,2157,1640,1627,6239,831,1837,4850,3010,1497,3762,606,1809,3712,
    5791,858,2841,3076,5442,7700,7421,3473,4998,3180,6316,416,633,6313,941,1656,7886,4481,3969,3398,
    2185,5288,4342,4149,7482,441,5888,7571,3803,6909,7762,3003,2056,6255,244,4361,6521,1657,4636,5750,
    719,4045,358,3269,6415,5631,7911,5403,475,2930,7501,1705,1213,5671,3234,6588,5209,1969,7192,7612,
    5542,3250,6762,1825,7214,2955,5707,3456,7264,2376,579,4444,3678,3306,1734,6730,6481,2358,1932,4226,
    1290,6157,6592,4463,4426,5202,5450,1845,2477,492,1027,1890,6215,7229,6721,577,1597,1076,7659,1645,
    5874,4172,5553,5184,6710,3604,313,2898,4891,6918,29,5795,2706,2866,1530,2093,5006,5846,7484,3547,
    7307,7730,1287,3924,602,4689,4615,5934,6995,5944,1978,410,4047,6906,2090,4096,6873,152,5664,1139,
    5794,3822,6490,5616,5323,7620,4348,566,5958,5476,7795,2194,3906,6200,5087,2856,7632,5858,1409,7592,
    6637,6881,6669,6928,5945,1843,6119,6840,826,5082,2686,5959,5947,4538,2108,7467,29,3759,3172,3084,
    4711,6808,1229,4811,4543,191,2533,2012,3012,2487,3765,337,7759,34,6460,2145,6012,6480,6373,3350,
    1984,2894,4437,4341,7279,4761,5831,1773,6186,3995,1086,2583,1717,2832,4233,2236,1864,7827,3208,5822,
    6014,713,1887,2201,7714,299,7795,522,3299,7032,2370,4119,1511,3187,5396,1753,3513,2183,1534,5514,
    2340,6348,256,2403,6074,5821,5285,5100,955,851,502,6255,5881,2401,3163,4552,5974,6062,7409,1856,
    7691,2906,5422,4436,1443,7816,3593,7457,4629,114,7723,7225,3490,1969,1855,5571,1797,7755,3201,7640,
    7435,2683,1598,2219,194,5311,1132,6625,7607,537,5913,2900,4051,7098,7432,1180,6637,5958,7702,5414,
    3104,3833,1704,275,4458,4095,4926,1862,3790,1301,4185,7544,2017,6606,1538,736,5201,6179,5463,5632,
    5868,6032,5803,7572,2931,1103,4539,5870,3590,2757,3416,5164,1303,2007,1408,2488,7573,7886,3731,242,
    5820,6122,5603,2233,4497,3547,2185,2997,2895,2353,7632,4662,4115,6506,7736,894,3749,3164,3389,986,
    7590,4046,5143,1276,378,1587,644,6372,568,1701,5229,1530,4472,6931,7685,6289,6442,5121,4981,3946,
    6157,4158,7469,2062,6336,7094,7225,3177,3044,1942,2503,2670,4737,3320,4081,4212,7690,3637,3542,3698,
    1365,3946,6511,5757,3534,5947,5738,4157,6194,6703,5149,1849,4004,5102,4346,6978,6163,2381,283,6807,
    4046,1195,2491,1893,5180,2697,7482,4346,253,992,1124,4653
};
// clang-format on

TrapdoorKey known_good_trapdoor() {
    TrapdoorKey key;
    key.f.assign(kFixtureF.begin(), kFixtureF.end());
    key.g.assign(kFixtureG.begin(), kFixtureG.end());
    key.F.assign(kFixtureCapF.begin(), kFixtureCapF.end());
    key.G.assign(kFixtureCapG.begin(), kFixtureCapG.end());
    return key;
}

PublicKey known_good_public_key() {
    PublicKey pub;
    pub.t.assign(kFixtureT.begin(), kFixtureT.end());
    return pub;
}

PolyQ sample_b(std::int64_t seed) {
    PolyQ result(Parameters::degree);
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = (seed + static_cast<std::int64_t>(i) * 41) % Parameters::modulus;
        if (result[i] < 0) {
            result[i] += Parameters::modulus;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Create -> unlock round trip: trapdoor, public key and b must all survive
// AEAD-encrypted-at-rest custody unchanged.
// ---------------------------------------------------------------------------

void test_create_unlock_round_trip(const std::filesystem::path& dir) {
    const auto path = dir / "roundtrip.qks";
    const auto trapdoor = known_good_trapdoor();
    const auto pub = known_good_public_key();
    const auto b = sample_b(1);

    auto ks = Q7933Keystore::create(path.string(), "correct horse battery staple", trapdoor, pub, b);
    require(ks.is_unlocked(), "a freshly created q7933 keystore must be unlocked");
    require(ks.public_key().t == pub.t, "create() must return the same public key given to it");
    require(ks.trapdoor().f == trapdoor.f, "create() must return the same trapdoor.f given to it");
    require(ks.trapdoor().g == trapdoor.g, "create() must return the same trapdoor.g given to it");
    require(ks.trapdoor().F == trapdoor.F, "create() must return the same trapdoor.F given to it");
    require(ks.trapdoor().G == trapdoor.G, "create() must return the same trapdoor.G given to it");
    require(ks.b() == b, "create() must return the same b given to it");

    auto unlocked = Q7933Keystore::unlock(path.string(), "correct horse battery staple");
    require(unlocked.is_unlocked(), "unlock() must return an unlocked instance");
    require(unlocked.public_key().t == pub.t, "public key must survive a create/unlock round trip");
    require(unlocked.trapdoor().f == trapdoor.f, "trapdoor.f must survive a create/unlock round trip");
    require(unlocked.trapdoor().g == trapdoor.g, "trapdoor.g must survive a create/unlock round trip");
    require(unlocked.trapdoor().F == trapdoor.F, "trapdoor.F must survive a create/unlock round trip");
    require(unlocked.trapdoor().G == trapdoor.G, "trapdoor.G must survive a create/unlock round trip");
    require(unlocked.b() == b, "b must survive a create/unlock round trip");
}

// ---------------------------------------------------------------------------
// Wrong passphrase is rejected as an authentication failure, and does not
// corrupt the file - the correct passphrase must still work afterward.
// ---------------------------------------------------------------------------

void test_wrong_passphrase_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "wrongpass.qks";
    (void)Q7933Keystore::create(path.string(), "correct-passphrase", known_good_trapdoor(), known_good_public_key(),
                                 sample_b(2));

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)Q7933Keystore::unlock(path.string(), "incorrect-passphrase"); },
        "unlocking a q7933 keystore with the wrong passphrase must fail with an authentication error");

    auto ok = Q7933Keystore::unlock(path.string(), "correct-passphrase");
    require(ok.is_unlocked(), "the correct passphrase must still unlock after a prior failed attempt");
}

// ---------------------------------------------------------------------------
// Tampering the file's authenticated contents must be rejected, never
// silently accepted.
// ---------------------------------------------------------------------------

void test_corrupted_file_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "corrupted.qks";
    (void)Q7933Keystore::create(path.string(), "aead-pass", known_good_trapdoor(), known_good_public_key(),
                                 sample_b(3));

    auto bytes = read_all(path);
    require(!bytes.empty(), "a real q7933 keystore file must not be empty");
    bytes.back() ^= 0x01U;
    write_all(path, bytes);

    require_throws<tradep2p::KeystoreAuthenticationError>(
        [&] { (void)Q7933Keystore::unlock(path.string(), "aead-pass"); },
        "a tampered q7933 keystore file must be rejected as an authentication failure, not silently accepted");
}

// ---------------------------------------------------------------------------
// No create-if-missing path: unlocking a path that was never created must
// fail, not silently generate a fresh trapdoor.
// ---------------------------------------------------------------------------

void test_unlock_missing_file_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "does-not-exist.qks";
    require_throws<std::runtime_error>(
        [&] { (void)Q7933Keystore::unlock(path.string(), "whatever"); },
        "unlocking a q7933 keystore path that was never created must fail, not auto-generate one");
}

// ---------------------------------------------------------------------------
// create() never silently overwrites an existing file (O_CREAT|O_EXCL, not a
// racy stat-then-write).
// ---------------------------------------------------------------------------

void test_create_no_silent_overwrite(const std::filesystem::path& dir) {
    const auto path = dir / "no-overwrite.qks";
    (void)Q7933Keystore::create(path.string(), "first-pass", known_good_trapdoor(), known_good_public_key(),
                                 sample_b(4));

    require_throws<tradep2p::KeystoreAlreadyExistsError>(
        [&] {
            (void)Q7933Keystore::create(path.string(), "second-pass", known_good_trapdoor(), known_good_public_key(),
                                        sample_b(5));
        },
        "create() must refuse to overwrite an existing q7933 keystore file");

    auto still_original = Q7933Keystore::unlock(path.string(), "first-pass");
    require(still_original.is_unlocked(), "the original file must remain intact after a rejected overwrite");
}

// ---------------------------------------------------------------------------
// Malformed/truncated files are rejected with a format error, not a crash
// or an out-of-bounds read: bad magic, and a file cut off mid-record.
// ---------------------------------------------------------------------------

void test_malformed_file_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "malformed.qks";
    (void)Q7933Keystore::create(path.string(), "malformed-pass", known_good_trapdoor(), known_good_public_key(),
                                 sample_b(6));
    const auto original = read_all(path);

    const auto bad_magic_path = dir / "bad-magic.qks";
    auto bad_magic = original;
    bad_magic[0] ^= 0xffU;
    write_all(bad_magic_path, bad_magic);
    require_throws<tradep2p::KeystoreFormatError>(
        [&] { (void)Q7933Keystore::unlock(bad_magic_path.string(), "malformed-pass"); },
        "a file with the wrong magic must not be accepted as a q7933 keystore");

    const auto truncated_path = dir / "truncated.qks";
    require(original.size() > 10U, "a real q7933 keystore file must be well over 10 bytes");
    const std::vector<std::uint8_t> truncated(original.begin(), original.begin() + 10);
    write_all(truncated_path, truncated);
    require_throws<tradep2p::KeystoreFormatError>(
        [&] { (void)Q7933Keystore::unlock(truncated_path.string(), "malformed-pass"); },
        "a truncated q7933 keystore file must be rejected as a format error, not crash");
}

// ---------------------------------------------------------------------------
// Invariant checks: validate_invariants() is the SAME function create() and
// unlock() both call, so exercising it via create() (which runs it before
// ever touching the filesystem) genuinely covers what unlock() would also
// reject - there is no separate, more lenient code path. Covers: wrong
// degree ("all lengths = 512"), non-canonical coefficients, the exact
// fG-gF=q relation, and independently re-derived t=f*g^-1 matching the
// stored public key.
// ---------------------------------------------------------------------------

void test_wrong_degree_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "wrong-degree.qks";
    auto trapdoor = known_good_trapdoor();
    trapdoor.f.pop_back(); // now 511 coefficients, not 512
    require_throws<tradep2p::KeystoreFormatError>(
        [&] {
            (void)Q7933Keystore::create(path.string(), "pass", trapdoor, known_good_public_key(), sample_b(7));
        },
        "create() must reject a trapdoor whose f has the wrong degree");
    require(!std::filesystem::exists(path), "a rejected create() must not leave a file behind");
}

void test_noncanonical_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "noncanonical.qks";
    auto pub = known_good_public_key();
    pub.t[0] = Parameters::modulus; // out of [0, q)
    require_throws<tradep2p::KeystoreFormatError>(
        [&] {
            (void)Q7933Keystore::create(path.string(), "pass", known_good_trapdoor(), pub, sample_b(8));
        },
        "create() must reject a non-canonical public key coefficient");
    require(!std::filesystem::exists(path), "a rejected create() must not leave a file behind");
}

void test_relation_mismatch_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "bad-relation.qks";
    auto trapdoor = known_good_trapdoor();
    trapdoor.G[0] += 1; // breaks the exact f*G-g*F=q relation
    require_throws<tradep2p::KeystoreFormatError>(
        [&] {
            (void)Q7933Keystore::create(path.string(), "pass", trapdoor, known_good_public_key(), sample_b(9));
        },
        "create() must reject a trapdoor that fails fG-gF=q");
    require(!std::filesystem::exists(path), "a rejected create() must not leave a file behind");
}

void test_t_derivation_mismatch_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "bad-t.qks";
    auto pub = known_good_public_key();
    pub.t[0] = (pub.t[0] + 1) % Parameters::modulus; // a valid-looking but wrong public key
    require_throws<tradep2p::KeystoreFormatError>(
        [&] {
            (void)Q7933Keystore::create(path.string(), "pass", known_good_trapdoor(), pub, sample_b(10));
        },
        "create() must reject a stored public key t that does not match f*g^-1 re-derived from the trapdoor");
    require(!std::filesystem::exists(path), "a rejected create() must not leave a file behind");
}

// ---------------------------------------------------------------------------
// lock() clears in-memory secret state; every accessor must then refuse.
// ---------------------------------------------------------------------------

void test_locked_accessors_rejected(const std::filesystem::path& dir) {
    const auto path = dir / "locked.qks";
    auto ks = Q7933Keystore::create(path.string(), "lock-pass", known_good_trapdoor(), known_good_public_key(),
                                     sample_b(11));
    require(ks.is_unlocked(), "freshly created keystore must start unlocked");

    ks.lock();
    require(!ks.is_unlocked(), "lock() must clear is_unlocked()");

    require_throws<std::logic_error>([&] { (void)ks.trapdoor(); }, "trapdoor() on a locked q7933 keystore must throw");
    require_throws<std::logic_error>([&] { (void)ks.public_key(); },
                                      "public_key() on a locked q7933 keystore must throw");
    require_throws<std::logic_error>([&] { (void)ks.b(); }, "b() on a locked q7933 keystore must throw");
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_create_unlock_round_trip(dir);
        test_wrong_passphrase_rejected(dir);
        test_corrupted_file_rejected(dir);
        test_unlock_missing_file_rejected(dir);
        test_create_no_silent_overwrite(dir);
        test_malformed_file_rejected(dir);
        test_wrong_degree_rejected(dir);
        test_noncanonical_rejected(dir);
        test_relation_mismatch_rejected(dir);
        test_t_derivation_mismatch_rejected(dir);
        test_locked_accessors_rejected(dir);

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "blindsig_keystore_q7933_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "blindsig_keystore_q7933_tests: FAIL: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
