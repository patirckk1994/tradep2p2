#pragma once

#include "tradep2p/secure_channel.hpp"

#include <memory>

namespace tradep2p {

// Small semi-centralized directory for mediator endpoints. It is not a trust
// authority: clients still pin the mediator certificate listed for each node.
class RegistryServer {
public:
    RegistryServer(Endpoint bind_endpoint, ServerTlsIdentity identity);
    ~RegistryServer();

    RegistryServer(const RegistryServer&) = delete;
    RegistryServer& operator=(const RegistryServer&) = delete;

    void run();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

void register_node_once(const Endpoint& registry,
                        const ClientTlsPolicy& registry_tls,
                        const RegistryNode& node);

[[nodiscard]] RegistryNodesMessage list_registered_nodes(
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls);

} // namespace tradep2p
