#include "tradep2p/identity.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

tradep2p::MasterSecret fixed_master_secret(std::uint8_t seed_byte) {
    std::array<std::uint8_t, tradep2p::kMasterSecretLength> raw{};
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<std::uint8_t>(seed_byte + i);
    }
    return tradep2p::MasterSecret(raw);
}

std::vector<std::uint8_t> derive_raw(const tradep2p::MasterSecret& secret,
                                      std::string_view label,
                                      std::string_view identifier) {
    const auto info = tradep2p::encode_derivation_info(label, identifier);
    return tradep2p::hkdf_sha256(secret.span(), {}, info, tradep2p::kDerivedKeyLength);
}

// ---------------------------------------------------------------------------
// Derivation-info encoding: exact serialization test vectors.
// ---------------------------------------------------------------------------

void test_derivation_info_encoding_vectors() {
    {
        const auto info = tradep2p::encode_derivation_info("login", "x");
        const std::vector<std::uint8_t> expected = {
            0x05,                          // label_len = 5
            'l', 'o', 'g', 'i', 'n',       // label = "login"
            0x00, 0x01,                    // identifier_len = 1 (u16 BE)
            'x',                            // identifier = "x"
        };
        require(info == expected, "encode_derivation_info(\"login\",\"x\") vector mismatch");
    }
    {
        const auto info = tradep2p::encode_derivation_info("logi", "nx");
        const std::vector<std::uint8_t> expected = {
            0x04,                          // label_len = 4
            'l', 'o', 'g', 'i',            // label = "logi"
            0x00, 0x02,                    // identifier_len = 2 (u16 BE)
            'n', 'x',                       // identifier = "nx"
        };
        require(info == expected, "encode_derivation_info(\"logi\",\"nx\") vector mismatch");
    }
    {
        const auto info = tradep2p::encode_derivation_info("", "");
        const std::vector<std::uint8_t> expected = {0x00, 0x00, 0x00};
        require(info == expected, "encode_derivation_info(\"\",\"\") vector mismatch");
    }
    {
        const auto info = tradep2p::encode_derivation_info("local-history", "");
        const std::vector<std::uint8_t> expected = {
            0x0D, 'l', 'o', 'c', 'a', 'l', '-', 'h', 'i', 's', 't', 'o', 'r', 'y',
            0x00, 0x00,
        };
        require(info == expected, "encode_derivation_info(\"local-history\",\"\") vector mismatch");
    }

    // Length-prefixing must make the encoding injective: naive concatenation
    // of "login"+"x" and "logi"+"nx" both yield "loginx", but the encodings
    // above must differ because the label/identifier boundary is explicit.
    const auto a = tradep2p::encode_derivation_info("login", "x");
    const auto b = tradep2p::encode_derivation_info("logi", "nx");
    require(a != b, "length-prefixed encodings for adjacent-boundary inputs must differ");

    // Over-length label/identifier must be rejected, not silently truncated.
    bool threw = false;
    try {
        (void)tradep2p::encode_derivation_info(std::string(256, 'a'), "");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "over-length label must be rejected");
}

// ---------------------------------------------------------------------------
// KDF domain separation
// ---------------------------------------------------------------------------

void test_kdf_domain_separation() {
    const tradep2p::MasterSecret secret = fixed_master_secret(0x11);

    // The exact adjacent-boundary case called out in the phase spec.
    require(derive_raw(secret, "login", "x") != derive_raw(secret, "logi", "nx"),
            "KDF(secret, info(\"login\",\"x\")) must differ from KDF(secret, info(\"logi\",\"nx\"))");

    // Same case, but repeated for every scoped label this phase defines, so
    // that a future label added to key_scope stays covered by symmetry.
    struct AdjacentCase {
        std::string_view label_a;
        std::string_view id_a;
        std::string_view label_b;
        std::string_view id_b;
    };
    const AdjacentCase cases[] = {
        {tradep2p::key_scope::kLogin, "x", "logi", "nx"},
        {tradep2p::key_scope::kMediatorPseudonym, "x", "mediato", "rx"},
        {tradep2p::key_scope::kLocalHistory, "y", "local-histor", "yy"},
    };
    for (const auto& c : cases) {
        require(derive_raw(secret, c.label_a, c.id_a) != derive_raw(secret, c.label_b, c.id_b),
                "adjacent-boundary derivation collision for a defined key_scope label");
    }

    // Two distinct real scopes over the same identifier must never collide.
    require(derive_raw(secret, tradep2p::key_scope::kLogin, "svc") !=
                derive_raw(secret, tradep2p::key_scope::kMediatorPseudonym, "svc"),
            "login and mediator-pseudonym scopes must not collide for the same identifier");
    require(derive_raw(secret, tradep2p::key_scope::kMediatorPseudonym, "svc") !=
                derive_raw(secret, tradep2p::key_scope::kLocalHistory, "svc"),
            "mediator-pseudonym and local-history scopes must not collide");

    // Same label, different identifier must not collide.
    require(derive_raw(secret, tradep2p::key_scope::kLogin, "service-a") !=
                derive_raw(secret, tradep2p::key_scope::kLogin, "service-b"),
            "same label with different identifiers must not collide");
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

void test_derivation_determinism() {
    const tradep2p::MasterSecret secret_a = fixed_master_secret(0x42);
    const tradep2p::MasterSecret secret_b = fixed_master_secret(0x42);
    const tradep2p::MasterSecret secret_c = fixed_master_secret(0x43);

    const auto key_a1 = tradep2p::derive_scoped_key(secret_a, tradep2p::key_scope::kLogin, "svc-1");
    const auto key_a2 = tradep2p::derive_scoped_key(secret_b, tradep2p::key_scope::kLogin, "svc-1");
    require(key_a1.bytes() == key_a2.bytes(),
            "same master secret + same label + same identifier must derive identically");

    const auto key_diff_id =
        tradep2p::derive_scoped_key(secret_a, tradep2p::key_scope::kLogin, "svc-2");
    require(key_a1.bytes() != key_diff_id.bytes(), "different identifier must derive differently");

    const auto key_diff_label =
        tradep2p::derive_scoped_key(secret_a, tradep2p::key_scope::kMediatorPseudonym, "svc-1");
    require(key_a1.bytes() != key_diff_label.bytes(), "different label must derive differently");

    const auto key_diff_secret =
        tradep2p::derive_scoped_key(secret_c, tradep2p::key_scope::kLogin, "svc-1");
    require(key_a1.bytes() != key_diff_secret.bytes(), "different master secret must derive differently");

    // The same determinism must hold end-to-end through Ed25519 keypair
    // derivation, not just the raw KDF output.
    const auto pair_1 = tradep2p::derive_ed25519_keypair(secret_a, tradep2p::key_scope::kLogin, "svc-1");
    const auto pair_2 = tradep2p::derive_ed25519_keypair(secret_b, tradep2p::key_scope::kLogin, "svc-1");
    require(pair_1.public_key == pair_2.public_key,
            "derived Ed25519 keypairs must be identical for identical (secret, label, identifier)");
    const auto pair_diff = tradep2p::derive_ed25519_keypair(secret_a, tradep2p::key_scope::kLogin, "svc-2");
    require(pair_1.public_key != pair_diff.public_key,
            "derived Ed25519 keypairs must differ for a different identifier");
}

// ---------------------------------------------------------------------------
// Ed25519 sign/verify round trip + negative tests
// ---------------------------------------------------------------------------

void test_ed25519_sign_verify_round_trip() {
    const tradep2p::Ed25519KeyPair pair = tradep2p::generate_ed25519_keypair();
    const std::vector<std::uint8_t> message = {'t', 'r', 'a', 'd', 'e', '-', '0', '1'};

    const tradep2p::Ed25519Signature signature =
        tradep2p::ed25519_sign(pair.private_seed, message);
    require(tradep2p::ed25519_verify(pair.public_key, message, signature),
            "a valid signature over the signed message must verify");

    // Flipped bit in the signature.
    tradep2p::Ed25519Signature bad_signature = signature;
    bad_signature[0] ^= 0x01U;
    require(!tradep2p::ed25519_verify(pair.public_key, message, bad_signature),
            "a signature with a flipped bit must not verify");

    // Flipped bit in the message.
    std::vector<std::uint8_t> bad_message = message;
    bad_message[0] ^= 0x01U;
    require(!tradep2p::ed25519_verify(pair.public_key, bad_message, signature),
            "a signature must not verify against a modified message");

    // Signature from a different keypair must not verify.
    const tradep2p::Ed25519KeyPair other_pair = tradep2p::generate_ed25519_keypair();
    require(!tradep2p::ed25519_verify(other_pair.public_key, message, signature),
            "a signature must not verify under a different public key");

    // Deterministic (derived) keypairs must sign/verify just as well.
    const tradep2p::MasterSecret secret = fixed_master_secret(0x99);
    const auto derived_pair =
        tradep2p::derive_ed25519_keypair(secret, tradep2p::key_scope::kMediatorPseudonym, "node-1");
    const auto derived_signature = tradep2p::ed25519_sign(derived_pair.private_seed, message);
    require(tradep2p::ed25519_verify(derived_pair.public_key, message, derived_signature),
            "a derived (scoped) keypair must sign/verify correctly");
}

void test_ephemeral_keys_are_not_derived_and_not_reused() {
    // Two ephemeral keypairs generated back to back must never collide -
    // they must be freshly random, unlinkable to each other.
    const auto pair_1 = tradep2p::generate_ed25519_keypair();
    const auto pair_2 = tradep2p::generate_ed25519_keypair();
    require(pair_1.public_key != pair_2.public_key,
            "two freshly generated ephemeral keypairs must not collide");
}

// ---------------------------------------------------------------------------
// Malformed / invalid public key rejection
// ---------------------------------------------------------------------------

void test_invalid_public_key_rejection() {
    // Wrong length (too short and too long).
    const std::vector<std::uint8_t> too_short(tradep2p::kEd25519PublicKeyLength - 1, 0x01);
    require(!tradep2p::parse_ed25519_public_key(too_short).has_value(),
            "a too-short buffer must be rejected");

    const std::vector<std::uint8_t> too_long(tradep2p::kEd25519PublicKeyLength + 1, 0x01);
    require(!tradep2p::parse_ed25519_public_key(too_long).has_value(),
            "a too-long buffer must be rejected");

    // All-zero key: never a valid Ed25519 public key encoding.
    const std::vector<std::uint8_t> all_zero(tradep2p::kEd25519PublicKeyLength, 0x00);
    require(!tradep2p::parse_ed25519_public_key(all_zero).has_value(),
            "an all-zero buffer must be rejected");

    // Correct length, non-zero, plausible-looking public key must parse.
    const auto pair = tradep2p::generate_ed25519_keypair();
    const auto parsed = tradep2p::parse_ed25519_public_key(
        std::span<const std::uint8_t>(pair.public_key.data(), pair.public_key.size()));
    require(parsed.has_value() && parsed.value() == pair.public_key,
            "a genuine, correctly-sized public key must parse successfully");

    // Not a valid curve point (right length, non-zero, but not necessarily
    // decodable to an on-curve point) - this phase does not eagerly
    // validate curve membership for Ed25519 (OpenSSL exposes no cheap
    // point-validity check for it), so parse_ed25519_public_key() still
    // returns a value; the rejection instead happens lazily, at verify
    // time, and must fail closed (return false, never throw/crash) rather
    // than silently accept.
    std::array<std::uint8_t, tradep2p::kEd25519PublicKeyLength> implausible{};
    implausible.fill(0xFFU);
    implausible.back() = 0x7FU; // clear the sign bit; y = 2^255 - 1 (non-canonical, >= p)
    const std::vector<std::uint8_t> message = {'x'};
    const auto signature = tradep2p::ed25519_sign(pair.private_seed, message);
    require(!tradep2p::ed25519_verify(implausible, message, signature),
            "verification against an implausible/non-canonical public key must fail closed, not crash");
}

// ---------------------------------------------------------------------------
// Constant-time comparison (functional correctness only)
// ---------------------------------------------------------------------------

void test_constant_time_equal() {
    const std::vector<std::uint8_t> a = {1, 2, 3, 4};
    const std::vector<std::uint8_t> b = {1, 2, 3, 4};
    const std::vector<std::uint8_t> c = {1, 2, 3, 5};
    const std::vector<std::uint8_t> d = {1, 2, 3};

    require(tradep2p::constant_time_equal(a, b), "identical buffers must compare equal");
    require(!tradep2p::constant_time_equal(a, c),
            "buffers differing in the last byte must compare unequal");
    require(!tradep2p::constant_time_equal(a, d), "buffers of different length must compare unequal");

    std::vector<std::uint8_t> e = {1, 2, 3, 4};
    e[0] ^= 0x01U;
    require(!tradep2p::constant_time_equal(a, e),
            "buffers differing in the first byte must compare unequal");

    require(tradep2p::constant_time_equal(std::span<const std::uint8_t>{}, std::span<const std::uint8_t>{}),
            "two empty buffers must compare equal");
}

} // namespace

int main() {
    try {
        test_derivation_info_encoding_vectors();
        test_kdf_domain_separation();
        test_derivation_determinism();
        test_ed25519_sign_verify_round_trip();
        test_ephemeral_keys_are_not_derived_and_not_reused();
        test_invalid_public_key_rejection();
        test_constant_time_equal();
        std::cout << "identity unit tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "identity test failure: " << error.what() << '\n';
        return 1;
    }
}
