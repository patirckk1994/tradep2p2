#pragma once

#include "tradep2p/secure_channel.hpp"

#ifdef TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
#include "tradep2p/blindsig_keystore.hpp"
#if defined(TRADEP2P_ENABLE_BLNS7933_INTEGRATION)
#include "tradep2p/blindsig_keystore_q7933.hpp"
#endif
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
    // Enables the existing q=12289 experimental blind-signature primitive
    // (specs.txt SS9.3a). Must be called before run(), at most once.
    void enable_blindsig_signer(blindsig::BlindSigKeystore keystore);

#if defined(TRADEP2P_ENABLE_BLNS7933_INTEGRATION)
    // Enables the separate q=7933 deferred/operator-approved path. This is
    // deliberately not an overload of the q=12289 backend's configuration:
    // it has its own keystore, prover binary, durable ticket directory and
    // verifier queue. Submission verifies NIZK1 and returns Pending+ticket;
    // this hook does not expose any inline signing operation.
    void enable_q7933_blindsig_signer(blindsig::Q7933Keystore keystore,
                                      std::string ticket_directory,
                                      std::string prover_path,
                                      std::size_t queue_capacity);
#endif
#endif

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tradep2p
