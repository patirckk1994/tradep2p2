#pragma once

#include "tradep2p/secure_channel.hpp"

#include <memory>
#include <optional>
#include <vector>

namespace tradep2p {

// A peer registry this registry pulls from - see registry.cpp's
// gossip_loop(). Single-hop only: this registry re-shares only its own
// directly-registered, approved entries with ITS OWN callers, never
// anything it learned from a peer via this mechanism - see the file
// comment on gossip_entries_ for why. Choosing to configure a peer at all
// IS the trust decision; auto_trust below only controls how much of that
// trust extends to what the peer vouches for.
struct RegistryPeer {
    Endpoint registry;
    ClientTlsPolicy registry_tls;
    // Set for a peer reachable only over Tor - reuses
    // list_registered_nodes_via_socks5() instead of the direct variant.
    std::optional<Endpoint> proxy;
    // false (default): a node learned from this peer sits Pending here too
    // (same LISTPENDING/APPROVE/REJECT flow as a direct registration,
    // just sourced from a pull instead of a push) - this registry's own
    // admin must separately approve it before local callers see it.
    // true: the peer's own approval is trusted outright - the node is
    // merged into this registry's listings immediately, tagged with the
    // peer as its source_registry.
    bool auto_trust{false};
};

// Small semi-centralized directory for mediator endpoints. It is not a trust
// authority: clients still pin the mediator certificate listed for each node.
class RegistryServer {
public:
    RegistryServer(Endpoint bind_endpoint, ServerTlsIdentity identity,
                   std::vector<RegistryPeer> gossip_peers = {});
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
