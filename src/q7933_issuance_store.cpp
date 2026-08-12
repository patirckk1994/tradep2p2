#include "tradep2p/q7933_issuance_store.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tradep2p::q7933_credential {
namespace {

void write_all_or_throw(int fd, const std::vector<std::uint8_t>& bytes,
                        const std::string& path) {
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const ssize_t written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw IssuanceStoreError("Failed to write issuance record '" + path + "': " +
                                     std::strerror(errno));
        }
        if (written == 0) {
            throw IssuanceStoreError("Short write while creating issuance record '" + path + "'");
        }
        offset += static_cast<std::size_t>(written);
    }
}

} // namespace

IssuanceStore::IssuanceStore(std::string directory) : directory_(std::move(directory)) {
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        throw IssuanceStoreError("Failed to create issuance store directory: " + ec.message());
    }
}

std::string IssuanceStore::compute_record_path(const IssuanceContext& context) const {
    std::ostringstream filename;
    filename << "issuance_" << static_cast<int>(context.version) << "_"
             << static_cast<int>(context.issuer_scope) << "_" << context.epoch << "_";
    for (const auto byte : context.room_id) {
        filename << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    filename << "_" << static_cast<int>(context.party) << ".record";
    return directory_ + "/" + filename.str();
}

bool IssuanceStore::record_issuance(const IssuanceContext& context) {
    const std::string record_path = compute_record_path(context);

    // O_EXCL is the actual uniqueness primitive. Do not split this into an
    // exists() check followed by a create/rename: two signer workers could
    // both pass the check before either writes the marker.
    const int fd = ::open(record_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            // Parse the existing record before reporting a normal duplicate;
            // corruption must fail loudly rather than being silently accepted.
            (void)has_been_issued(context);
            return false;
        }
        throw IssuanceStoreError("Failed to create issuance record '" + record_path + "': " +
                                 std::strerror(errno));
    }

    bool committed = false;
    try {
        const auto encoded = context.encode();
        write_all_or_throw(fd, encoded, record_path);
        if (::fsync(fd) != 0) {
            throw IssuanceStoreError("Failed to fsync issuance record '" + record_path + "': " +
                                     std::strerror(errno));
        }
        if (::close(fd) != 0) {
            throw IssuanceStoreError("Failed to close issuance record '" + record_path + "': " +
                                     std::strerror(errno));
        }
        committed = true;
    } catch (...) {
        // A failed/truncated exclusive marker is deliberately retained. That
        // is fail-closed: has_been_issued() will reject it as corrupt, so a
        // crash/I/O fault can deny reissuance but can never create two valid
        // credentials for the same room/party/epoch.
        if (!committed) {
            (void)::close(fd);
        }
        throw;
    }

    return true;
}

bool IssuanceStore::has_been_issued(const IssuanceContext& context) const {
    const std::string record_path = compute_record_path(context);
    if (!std::filesystem::exists(record_path)) {
        return false;
    }

    std::ifstream file(record_path, std::ios::binary);
    if (!file.is_open()) {
        throw IssuanceStoreFormatError("Cannot open issuance record: " + record_path);
    }
    const std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(file)),
                                          std::istreambuf_iterator<char>());

    try {
        const auto decoded = IssuanceContext::decode(data);
        if (decoded.encode() != context.encode()) {
            throw IssuanceStoreFormatError("Issuance record content does not match its context");
        }
    } catch (const IssuanceStoreFormatError&) {
        throw;
    } catch (const std::exception& error) {
        throw IssuanceStoreFormatError("Corrupted issuance record: " + std::string(error.what()));
    }
    return true;
}

void IssuanceStore::rollback_uncommitted_issuance(const IssuanceContext& context) noexcept {
    std::error_code ec;
    std::filesystem::remove(compute_record_path(context), ec);
}

} // namespace tradep2p::q7933_credential
