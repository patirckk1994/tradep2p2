#include "tradep2p/blindsig_ticket_store_q7933.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

using tradep2p::blns7933::Parameters;
using tradep2p::blns7933::PolyQ;
using tradep2p::blns7933::Signature;
using tradep2p::blindsig::Q7933TicketStore;
using tradep2p::blindsig::Q7933TicketStoreFullError;
using tradep2p::blindsig::Q7933TicketStoreFormatError;
using tradep2p::blindsig::TicketId;
using tradep2p::blindsig::TicketStatus;

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

std::filesystem::path make_temp_dir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "tp2p_q7933_tickets_test_XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::filesystem::path(tmpl);
}

// No real cryptography is exercised here - the ticket store only ever
// treats c/s0/s1 as opaque, fixed-length int64 payloads it stores and
// returns verbatim. NTRU/relation/canonical validity is the signer's and
// keystore's job (blindsig_ntru_q7933.hpp / blindsig_keystore_q7933.hpp),
// not this layer's - so, unlike the keystore tests, arbitrary values at
// the production degree are enough, and this whole suite stays fast.
PolyQ sample_poly(std::int64_t seed) {
    PolyQ result(Parameters::degree);
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = seed + static_cast<std::int64_t>(i);
    }
    return result;
}

Signature sample_signature(std::int64_t seed) {
    Signature signature;
    signature.s0 = sample_poly(seed);
    signature.s1 = sample_poly(seed + 1000);
    return signature;
}

void test_submit_and_find_pending(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "a").string());
    const auto c = sample_poly(1);
    const auto id = store.submit(c);

    const auto found = store.find(id);
    require(found.has_value(), "a freshly submitted ticket must be found");
    require(found->status == TicketStatus::kPending, "a freshly submitted ticket must be kPending");
    require(found->c == c, "find() must return the same c given to submit()");
    require(!found->signature.has_value(), "a kPending ticket must not have a signature");
}

void test_list_pending_includes_submitted(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "b").string());
    const auto id1 = store.submit(sample_poly(2));
    const auto id2 = store.submit(sample_poly(3));

    const auto pending = store.list_pending();
    require(pending.size() == 2U, "list_pending() must report exactly the tickets submitted");
    require(std::find(pending.begin(), pending.end(), id1) != pending.end(), "list_pending() must include id1");
    require(std::find(pending.begin(), pending.end(), id2) != pending.end(), "list_pending() must include id2");
}

void test_mark_signed_transitions_and_leaves_pending_list(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "c").string());
    const auto id = store.submit(sample_poly(4));
    const auto signature = sample_signature(4);

    store.mark_signed(id, signature);

    const auto found = store.find(id);
    require(found.has_value(), "a signed ticket must still be found");
    require(found->status == TicketStatus::kSigned, "mark_signed() must transition status to kSigned");
    require(found->signature.has_value(), "a kSigned ticket must carry a signature");
    require(found->signature->s0 == signature.s0, "signed s0 must round-trip");
    require(found->signature->s1 == signature.s1, "signed s1 must round-trip");

    const auto pending = store.list_pending();
    require(pending.empty(), "a signed ticket must no longer appear in list_pending()");
}

void test_mark_signed_unknown_or_already_signed_rejected(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "d").string());
    TicketId bogus{};
    bogus.fill(0x42U);
    require_throws<std::logic_error>([&] { store.mark_signed(bogus, sample_signature(5)); },
                                      "mark_signed() on an unknown ticket must throw std::logic_error");

    const auto id = store.submit(sample_poly(6));
    store.mark_signed(id, sample_signature(6));
    require_throws<std::logic_error>([&] { store.mark_signed(id, sample_signature(7)); },
                                      "mark_signed() on an already-signed ticket must throw std::logic_error");
}

void test_remove(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "e").string());
    const auto id = store.submit(sample_poly(8));
    require(store.find(id).has_value(), "ticket must exist before remove()");

    store.remove(id);
    require(!store.find(id).has_value(), "ticket must be gone after remove()");

    // Removing an already-removed (or never-existent) ticket must not throw.
    store.remove(id);
}

void test_find_unknown_returns_nullopt(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "f").string());
    TicketId unknown{};
    unknown.fill(0x99U);
    require(!store.find(unknown).has_value(), "find() on an unknown ticket id must return std::nullopt");
}

void test_capacity_enforced(const std::filesystem::path& dir) {
    Q7933TicketStore store((dir / "g").string(), 2U);
    (void)store.submit(sample_poly(9));
    (void)store.submit(sample_poly(10));
    require_throws<Q7933TicketStoreFullError>([&] { (void)store.submit(sample_poly(11)); },
                                              "submit() past max_pending_tickets() must throw");
}

// The entire reason this type exists: a ticket submitted before a
// "restart" (destroying and re-creating the Q7933TicketStore object,
// simulating a mediator process exiting and starting again) must still be
// there afterward, with the exact same content.
void test_durability_across_store_lifetimes(const std::filesystem::path& dir) {
    const auto store_dir = (dir / "h").string();
    const auto c = sample_poly(12);
    TicketId id{};
    {
        Q7933TicketStore store(store_dir);
        id = store.submit(c);
    }
    {
        Q7933TicketStore store(store_dir);
        const auto found = store.find(id);
        require(found.has_value(), "a ticket must survive a Q7933TicketStore object being destroyed and recreated");
        require(found->c == c, "a surviving ticket's c must be unchanged");
        require(found->status == TicketStatus::kPending, "a surviving ticket's status must be unchanged");
    }
}

void test_malformed_file_rejected(const std::filesystem::path& dir) {
    const auto store_dir = (dir / "i").string();
    Q7933TicketStore store(store_dir);
    const auto id = store.submit(sample_poly(13));

    const std::string path = store_dir + "/" +
        [&id] {
            static constexpr char kDigits[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(64U);
            for (const auto byte : id) {
                hex.push_back(kDigits[(byte >> 4U) & 0x0fU]);
                hex.push_back(kDigits[byte & 0x0fU]);
            }
            return hex;
        }() +
        ".qtkt";

    std::ofstream corrupt(path, std::ios::binary | std::ios::trunc);
    corrupt << "not a real ticket file";
    corrupt.close();

    require_throws<Q7933TicketStoreFormatError>([&] { (void)store.find(id); },
                                                 "a malformed ticket file must be rejected, not silently ignored");
}

} // namespace

int main() {
    std::filesystem::path dir;
    try {
        dir = make_temp_dir();

        test_submit_and_find_pending(dir);
        test_list_pending_includes_submitted(dir);
        test_mark_signed_transitions_and_leaves_pending_list(dir);
        test_mark_signed_unknown_or_already_signed_rejected(dir);
        test_remove(dir);
        test_find_unknown_returns_nullopt(dir);
        test_capacity_enforced(dir);
        test_durability_across_store_lifetimes(dir);
        test_malformed_file_rejected(dir);

        std::error_code ignored;
        std::filesystem::remove_all(dir, ignored);

        std::cout << "blindsig_ticket_store_q7933_tests: OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "blindsig_ticket_store_q7933_tests: FAIL: " << error.what() << '\n';
        if (!dir.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir, ignored);
        }
        return 1;
    }
}
