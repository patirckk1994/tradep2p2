#include "tradep2p/q7933_issuance_store.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace tradep2p::q7933_credential {

IssuanceStore::IssuanceStore(std::string directory) : directory_(std::move(directory)) {
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        throw IssuanceStoreError("Failed to create issuance store directory: " + ec.message());
    }
}

std::string IssuanceStore::compute_record_path(const IssuanceContext& context) const {
    // Filename encodes (version, issuer_scope, epoch, room_id, party) as hex.
    // Format: "issuance_<version>_<issuer_scope>_<epoch>_<room_id_hex>_<party>.record"
    std::ostringstream filename;
    filename << "issuance_" << static_cast<int>(context.version) << "_"
             << static_cast<int>(context.issuer_scope) << "_" << context.epoch << "_";

    // Append room_id as hex
    for (auto byte : context.room_id) {
        filename << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    filename << "_" << static_cast<int>(context.party) << ".record";

    return directory_ + "/" + filename.str();
}

bool IssuanceStore::record_issuance(const IssuanceContext& context) {
    const std::string record_path = compute_record_path(context);

    // Check if already exists
    if (std::filesystem::exists(record_path)) {
        // Record already exists - this is a duplicate attempt
        return false;
    }

    // Write a new record atomically: tmp file + fsync + rename
    const std::string tmp_path = record_path + ".tmp";

    std::ofstream tmp_file(tmp_path, std::ios::binary);
    if (!tmp_file.is_open()) {
        throw IssuanceStoreError("Failed to open issuance temp file: " + tmp_path);
    }

    // Write the encoded context
    auto encoded = context.encode();
    tmp_file.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    if (!tmp_file) {
        tmp_file.close();
        std::filesystem::remove(tmp_path);
        throw IssuanceStoreError("Failed to write issuance temp file: " + tmp_path);
    }

    // Flush and sync
    tmp_file.flush();
    if (!tmp_file) {
        tmp_file.close();
        std::filesystem::remove(tmp_path);
        throw IssuanceStoreError("Failed to flush issuance temp file: " + tmp_path);
    }

    tmp_file.close();

    // std::filesystem::rename is atomic on most POSIX systems.
    // The main protection against corruption is atomicity of the rename op,
    // combined with all writes completing before the rename.

    std::error_code ec;
    std::filesystem::rename(tmp_path, record_path, ec);
    if (ec) {
        std::filesystem::remove(tmp_path);
        throw IssuanceStoreError("Failed to rename issuance record: " + ec.message());
    }

    return true;
}

bool IssuanceStore::has_been_issued(const IssuanceContext& context) const {
    const std::string record_path = compute_record_path(context);

    if (!std::filesystem::exists(record_path)) {
        return false;
    }

    // Verify the record can be parsed (corruption check).
    std::ifstream file(record_path, std::ios::binary);
    if (!file.is_open()) {
        throw IssuanceStoreFormatError("Cannot open issuance record: " + record_path);
    }

    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    file.close();

    try {
        (void)IssuanceContext::decode(data);
    } catch (const std::exception& e) {
        throw IssuanceStoreFormatError("Corrupted issuance record: " + std::string(e.what()));
    }

    return true;
}

} // namespace tradep2p::q7933_credential
