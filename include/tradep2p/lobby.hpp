#pragma once

#include "tradep2p/secure_channel.hpp"

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
#include "tradep2p/blindsig_keystore.hpp"
#include "tradep2p/blindsig_keystore_q7933.hpp"
#endif

#include <cstddef>
#include <memory>
#include <string>

namespace tradep2p {

// Anonymous multi-room lobby and fractional-settlement mediator.
// Client IDs are random connection-scoped handles, not accounts or identities.
class LobbyServer {
public:
    LobbyServer(Endpoint bind_endpoint, ServerTlsIdentity identity);
    ~LobbyServer();

    LobbyServer(const LobbyServer&) = delete;
    LobbyServer& operator=(const LobbyServer&) = delete;

    void run();

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    // Enables the experimental blind-signature primitive (specs.txt
    // SS9.3a). Must be called before run(), at most once. `keystore` must
    // already be unlocked - see main.cpp's mediator startup sequence
    // (an interactive passphrase prompt happens there, deliberately not
    // here or via any env var - see blindsig_keystore.hpp's file comment
    // for why).
    void enable_blindsig_signer(blindsig::BlindSigKeystore keystore);
    void enable_q7933_blindsig_signer(blindsig::Q7933Keystore keystore,
                                      const std::string& prover_path,
                                      const std::string& ticket_store_directory,
                                      std::size_t queue_capacity);
#endif

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tradep2p
