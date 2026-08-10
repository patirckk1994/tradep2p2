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

// Same as register_node_once(), reached through a SOCKS5 proxy (e.g. Tor)
// instead of a direct connection - the registry-side counterpart of
// list_registered_nodes_via_socks5() below, needed so a mediator can
// register with an onion-only registry it cannot otherwise dial directly.
void register_node_once_via_socks5(const Endpoint& proxy,
                                   const Endpoint& registry,
                                   const ClientTlsPolicy& registry_tls,
                                   const RegistryNode& node);

[[nodiscard]] RegistryNodesMessage list_registered_nodes(
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls);

[[nodiscard]] RegistryNodesMessage list_registered_nodes_via_socks5(
    const Endpoint& proxy,
    const Endpoint& registry,
    const ClientTlsPolicy& registry_tls);

} // namespace tradep2p
