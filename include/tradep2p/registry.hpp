#pragma once

#include "tradep2p/secure_channel.hpp"

#include <memory>

namespace tradep2p {

// Small semi-centralized directory for mediator endpoints. It is not a trust
// authority: clients still pin the mediator certificate listed for each node.
// Optional peer-to-peer gossip federation (TRADEP2P_REGISTRY_GOSSIP_PEERS,
// see registry.cpp's configured_registry_gossip_peers()) is configured the
// same way every other optional feature on this server is - environment
// variables read internally at construction, not a constructor parameter -
// so this public API is unaffected by it.
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
