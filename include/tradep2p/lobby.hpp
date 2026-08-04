#pragma once

#include "tradep2p/secure_channel.hpp"

#include <memory>

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

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tradep2p
