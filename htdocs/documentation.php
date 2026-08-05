<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$repo = e($config['repository']);
$name = e($config['name']);
$version = e($config['version']);
$webclientUrl = e($config['webclient_url'] ?? '#');
$webclientConfigured = ($config['webclient_url'] ?? '#') !== '#';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="TradeP2P source-code and protocol implementation documentation.">
    <meta name="theme-color" content="#f4f2ea">
    <title><?= $name ?> — Code documentation</title>
    <link rel="icon" href="assets/img/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="documentation-page">
    <a class="skip-link" href="#documentation">Skip to documentation</a>

    <header class="site-header" id="top">
        <div class="shell nav-shell">
            <a class="brand" href="index.php" aria-label="TradeP2P home">
                <span class="brand-mark" aria-hidden="true">T&gt;P</span>
                <span class="brand-copy">
                    <strong><?= $name ?></strong>
                    <small>code documentation</small>
                </span>
            </a>

            <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav">
                <span></span><span></span><span></span>
                <span class="sr-only">Toggle navigation</span>
            </button>

            <nav class="site-nav" id="site-nav" aria-label="Documentation navigation">
                <a href="index.php">Home</a>
                <a href="#architecture">Architecture</a>
                <a href="#state-machine">State machine</a>
                <a href="#wire">Wire format</a>
                <a href="#api">API</a>
                <?php if ($webclientConfigured): ?>
                <a href="<?= $webclientUrl ?>">Web client</a>
                <?php endif; ?>
                <a class="nav-github" href="<?= $repo ?>" target="_blank" rel="noreferrer">GitHub &#8599;</a>
            </nav>
        </div>
    </header>

    <main id="documentation">
        <section class="docs-hero">
            <div class="shell">
                <div class="eyebrow"><span class="pulse"></span> Source snapshot · v<?= $version ?> · wire v5</div>
                <h1>TradeP2P code documentation.</h1>
                <p>
                    A source-grounded map of the protocol objects, settlement state machine,
                    binary framing, TLS transport, lobby concurrency, registry, CLI and tests.
                </p>
                <div class="hero-actions">
                    <a class="button button-primary" href="#architecture">Start with architecture</a>
                    <a class="button button-secondary" href="<?= $repo ?>/blob/main/docs/CODE_DOCUMENTATION.md" target="_blank" rel="noreferrer">Markdown on GitHub ↗</a>
                </div>
            </div>
        </section>

        <div class="shell docs-layout">
            <aside class="docs-toc" aria-label="Table of contents">
                <strong>Contents</strong>
                <a href="#architecture">Architecture</a>
                <a href="#trade-model">Trade model</a>
                <a href="#state-machine">State machine</a>
                <a href="#workflow">Offer workflow</a>
                <a href="#protocol-types">Protocol types</a>
                <a href="#wire">Wire format</a>
                <a href="#transport">Secure transport</a>
                <a href="#lobby">Lobby internals</a>
                <a href="#registry">Registry</a>
                <a href="#cli">CLI modes</a>
                <a href="#build">Build and tests</a>
                <a href="#api">Public API</a>
                <a href="#boundaries">Boundaries</a>
            </aside>

            <article class="docs-content">
                <section class="docs-section" id="architecture">
                    <span class="kicker">01 / Architecture</span>
                    <h2>Five small modules and one CLI.</h2>
                    <p>
                        The implementation deliberately separates the settlement logic from transport
                        and server orchestration. The compiled static library is <code>tradep2p</code>;
                        the executable is <code>tradep2p_cli</code>.
                    </p>
                    <div class="docs-file-grid">
                        <div><code>protocol.hpp/.cpp</code><span>Types, limits, validation, tranche arithmetic and binary codecs.</span></div>
                        <div><code>mediator.hpp/.cpp</code><span>Two-party settlement state machine.</span></div>
                        <div><code>secure_channel.hpp/.cpp</code><span>TCP, SOCKS5, TLS 1.3, pinning and strict frames.</span></div>
                        <div><code>lobby.hpp/.cpp</code><span>Anonymous clients, offers, rooms, dispatch and cleanup.</span></div>
                        <div><code>registry.hpp/.cpp</code><span>Short-lived mediator endpoint directory.</span></div>
                        <div><code>main.cpp</code><span>Server modes, registry commands and terminal client.</span></div>
                    </div>
                </section>

                <section class="docs-section" id="trade-model">
                    <span class="kicker">02 / Trade model</span>
                    <h2>Integer totals divided without rounding loss.</h2>
                    <p>
                        Party A creates the offer; Party B joins it. <code>TradeTerms</code> stores two
                        asset symbols, two unsigned 64-bit totals, the round count and the first sender.
                        Floating-point arithmetic is not used.
                    </p>
                    <pre><code>base      = total / rounds
remainder = total % rounds
tranche   = base + (round_index &lt; remainder ? 1 : 0)</code></pre>
                    <p>
                        Thus 10 units over 3 rounds becomes <code>4, 3, 3</code>. Validation requires
                        <code>rounds &lt;= total_a</code> and <code>rounds &lt;= total_b</code>, so every leg
                        carries a positive integer amount.
                    </p>
                </section>

                <section class="docs-section" id="state-machine">
                    <span class="kicker">03 / State machine</span>
                    <h2>Every round contains two acknowledged legs.</h2>
                    <pre><code>WaitingForPeer
    → WaitingForSent
    → WaitingForReceived
    → WaitingForSent ...
    → Complete

Any non-complete session may become Aborted.</code></pre>
                    <p>
                        The sender reports <code>Sent</code>; the receiver verifies the external transfer
                        and reports <code>Received</code>. The counter-leg then begins. After both legs,
                        the round index advances. The configured first sender alternates each round.
                    </p>
                    <div class="docs-callout">
                        <strong>Acknowledgements are claims.</strong>
                        <span>The mediator does not query a blockchain and cannot prove that an external transfer occurred.</span>
                    </div>
                </section>

                <section class="docs-section" id="workflow">
                    <span class="kicker">04 / Offer workflow</span>
                    <h2>Current terminal commands.</h2>
                    <pre><code>/offer SELL_SYMBOL SELL_AMOUNT BUY_SYMBOL BUY_AMOUNT ROUNDS RECEIVE_ADDRESS
/offers [AFTER_ROOM_ID] [LIMIT]
/join ROOM_ID RECEIVE_ADDRESS
/cancel ROOM_ID
/sent ROOM_ID
/received ROOM_ID
/abort ROOM_ID
/help
/quit</code></pre>
                    <p>
                        Public offer pages contain room IDs and trade terms, but not receive addresses.
                        Pagination uses a stable lexical room-ID cursor with a hard limit of 32 entries.
                        Joining removes the open offer and converts the same room ID into an active session.
                    </p>
                    <p>
                        On disconnect, the server removes the client's offers, clears related pending
                        invitations and aborts active rooms with <code>peer disconnected</code>.
                    </p>
                </section>

                <section class="docs-section" id="protocol-types">
                    <span class="kicker">05 / Protocol types</span>
                    <h2>Fixed IDs, bounded strings, explicit messages.</h2>
                    <div class="docs-table-wrap">
                        <table class="docs-table">
                            <thead><tr><th>Type</th><th>Bytes</th><th>Hex text</th></tr></thead>
                            <tbody>
                                <tr><td><code>RoomId</code></td><td>32</td><td>64 characters</td></tr>
                                <tr><td><code>ClientId</code></td><td>16</td><td>32 characters</td></tr>
                                <tr><td><code>InviteId</code></td><td>16</td><td>32 characters</td></tr>
                                <tr><td><code>CertificatePin</code></td><td>32</td><td>64 characters</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <p>
                        All-zero identifiers are rejected. Asset codes are limited to 16 bytes and may
                        contain alphanumerics, dot, underscore and hyphen. Addresses are opaque printable
                        ASCII without spaces, from 1 to 256 bytes. Reasons are printable ASCII with spaces,
                        up to 128 bytes.
                    </p>
                    <p>
                        Message values 1–28 cover welcome, legacy peer invitations, settlement,
                        registry and offer-room operations. The current client and server dispatch path
                        expose only the offer-room workflow plus settlement acknowledgements.
                    </p>
                </section>

                <section class="docs-section" id="wire">
                    <span class="kicker">06 / Wire format</span>
                    <h2>A 20-byte frame header inside TLS.</h2>
                    <div class="docs-table-wrap">
                        <table class="docs-table">
                            <thead><tr><th>Offset</th><th>Size</th><th>Field</th></tr></thead>
                            <tbody>
                                <tr><td>0</td><td>4</td><td>ASCII magic <code>TP2P</code></td></tr>
                                <tr><td>4</td><td>2</td><td>Protocol version, big-endian</td></tr>
                                <tr><td>6</td><td>2</td><td>Message type, big-endian</td></tr>
                                <tr><td>8</td><td>8</td><td>Per-direction sequence, big-endian</td></tr>
                                <tr><td>16</td><td>4</td><td>Payload length, big-endian</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <p>
                        Payloads are capped at 4096 bytes. Sequence numbers begin at 1 in each direction
                        and must match exactly. Payload codecs use big-endian integers and <code>u16</code>
                        length-prefixed strings. Decoders reject truncation, limit violations and trailing bytes.
                    </p>
                </section>

                <section class="docs-section" id="transport">
                    <span class="kicker">07 / Secure transport</span>
                    <h2>TLS 1.3 with an exact certificate pin.</h2>
                    <p>The OpenSSL context requires:</p>
                    <ul>
                        <li>TLS 1.3 only;</li>
                        <li>no compression or session tickets;</li>
                        <li>ChaCha20-Poly1305 or AES-256-GCM;</li>
                        <li>X25519 or P-256 key-exchange groups.</li>
                    </ul>
                    <p>
                        Clients remain anonymous and present no client certificate. They authenticate
                        the mediator by comparing the exact SHA-256 digest of its certificate with the
                        command-line pin. Normal CA verification is disabled by design in favor of this pin.
                    </p>
                    <p>
                        The Tor path connects through a no-auth SOCKS5 proxy, submits the destination as
                        a domain name so onion resolution stays in Tor, and then performs the same end-to-end
                        TLS handshake and certificate-pin check.
                    </p>
                </section>

                <section class="docs-section" id="lobby">
                    <span class="kicker">08 / Lobby internals</span>
                    <h2>Thread-per-client with queued outbound frames.</h2>
                    <p>
                        Each accepted client receives a random OpenSSL-generated connection ID, a secure
                        channel, a nonblocking wake pipe and a mutex-protected outgoing queue. The client
                        thread polls its TLS socket and wake pipe; other threads enqueue rather than writing
                        directly to the same TLS connection.
                    </p>
                    <div class="docs-stat-grid">
                        <div><strong>128</strong><span>connected clients</span></div>
                        <div><strong>256</strong><span>active rooms</span></div>
                        <div><strong>256</strong><span>open offers</span></div>
                        <div><strong>16</strong><span>offers per client</span></div>
                        <div><strong>128</strong><span>queued frames per client</span></div>
                        <div><strong>3</strong><span>bad messages before removal</span></div>
                    </div>
                    <p>
                        A global mutex protects the client, offer, invitation and room maps. Each room has
                        its own mutex for state transitions; each client has a separate queue mutex.
                    </p>
                </section>

                <section class="docs-section" id="registry">
                    <span class="kicker">09 / Registry</span>
                    <h2>Discovery data, not an authority.</h2>
                    <p>
                        The optional registry stores a host, port and mediator certificate pin for 300 seconds.
                        Registered mediators refresh every 60 seconds and retry after 15 seconds on failure.
                        Registry transport is pinned TLS, but node advertisements themselves are unauthenticated.
                        A client must still verify the chosen mediator's own pin.
                    </p>
                </section>

                <section class="docs-section" id="cli">
                    <span class="kicker">10 / CLI modes</span>
                    <h2>One executable, seven modes.</h2>
                    <pre><code>tradep2p_cli registry BIND CERT KEY
tradep2p_cli nodes REGISTRY REGISTRY_PIN
tradep2p_cli register-node REGISTRY REGISTRY_PIN NODE NODE_PIN
tradep2p_cli mediator BIND CERT KEY
tradep2p_cli mediator-registered BIND CERT KEY REGISTRY REGISTRY_PIN ADVERTISED_NODE NODE_PIN
tradep2p_cli client NODE NODE_PIN
tradep2p_cli client-tor SOCKS_PROXY ONION_NODE NODE_PIN</code></pre>
                    <p>Endpoints use <code>host:port</code>; IPv6 uses <code>[address]:port</code>.</p>
                    <h3>Optional internal logging</h3>
                    <pre><code>export TRADEP2P_LOG_ENABLED=1
export TRADEP2P_LOG_FILE=/path/to/tradep2p.log</code></pre>
                    <p>
                        The log records startup mode, connection and TLS events, pin verification,
                        frame type and sequence, timeout changes, closure and fatal errors.
                    </p>
                </section>

                <section class="docs-section" id="build">
                    <span class="kicker">11 / Build and tests</span>
                    <h2>CMake, C++20 and OpenSSL.</h2>
                    <pre><code>cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure</code></pre>
                    <p>
                        The registered unit test covers integer tranches, offer/address serialization,
                        offer pagination, registry serialization and a complete mediator flow.
                        <code>tests/demo_io.sh</code> runs a temporary TLS mediator plus two clients and
                        records a full settlement transcript.
                    </p>
                    <div class="docs-callout warning">
                        <strong>Snapshot tooling note.</strong>
                        <span><code>tests/quick_test.sh</code> points at a missing <code>scripts/</code> directory, while <code>tests/test2.sh</code> references a missing <code>tests/common.sh</code>. The CMake + CTest path is the authoritative working path.</span>
                    </div>
                </section>

                <section class="docs-section" id="api">
                    <span class="kicker">12 / Public API</span>
                    <h2>Embedding points.</h2>
                    <h3><code>protocol.hpp</code></h3>
                    <p>Construct and validate messages, calculate integer tranches, convert IDs and pins, and encode/decode payloads.</p>
                    <h3><code>MediatorSession</code></h3>
                    <pre><code>MediatorSession(CreateRoomMessage creator, RoomId room_id);
void join(const JoinRoomMessage&amp; message);
TradeReadyMessage ready_message(Party party, ClientId peer_id) const;
TurnMessage current_turn() const;
void sender_reported_sent(Party, const RoundSignalMessage&amp;);
void receiver_reported_received(Party, const RoundSignalMessage&amp;);
void abort(std::string reason);</code></pre>
                    <h3><code>SecureChannel</code></h3>
                    <pre><code>static SecureChannel connect_direct(...);
static SecureChannel connect_via_socks5(...);
void send_frame(MessageType, std::span&lt;const std::uint8_t&gt;);
Frame receive_frame();
void set_timeout(std::uint32_t seconds);</code></pre>
                    <p><code>SecureChannel</code> is movable and non-copyable.</p>
                    <h3><code>LobbyServer</code> and <code>RegistryServer</code></h3>
                    <p>Both expose a constructor and blocking <code>run()</code> loop. Registry helper functions perform one registration or one list request.</p>
                </section>

                <section class="docs-section" id="boundaries">
                    <span class="kicker">13 / Security boundary</span>
                    <h2>What the software does—and deliberately does not do.</h2>
                    <div class="docs-boundary-grid">
                        <div>
                            <strong>The mediator handles</strong>
                            <ul>
                                <li>asset symbols and integer totals;</li>
                                <li>round counts and turn order;</li>
                                <li>temporary client and room IDs;</li>
                                <li>opaque receive addresses after joining;</li>
                                <li><code>sent</code>/<code>received</code> claims.</li>
                            </ul>
                        </div>
                        <div>
                            <strong>Outside its scope</strong>
                            <ul>
                                <li>private keys, seeds, wallets or balances;</li>
                                <li>transaction creation, signing or broadcast;</li>
                                <li>blockchain searches or confirmations;</li>
                                <li>accounts, durable identities or KYC;</li>
                                <li>escrow, custody or price discovery.</li>
                            </ul>
                        </div>
                    </div>
                    <p>
                        Current limitations include memory-only state, no reconnect or crash recovery,
                        no automatic room timeout, unauthenticated registry advertisements, no NAT traversal,
                        POSIX-only networking and one detached thread per client. This is protocol-test source,
                        not audited production financial software.
                    </p>
                </section>
            </article>
        </div>
    </main>

    <footer class="site-footer">
        <div class="shell footer-grid">
            <div>
                <strong><?= $name ?></strong>
                <p>Source-grounded documentation for protocol version 5.</p>
            </div>
            <div class="footer-links">
                <a href="index.php">Home</a>
                <a href="#top">Back to top</a>
                <a href="<?= $repo ?>" target="_blank" rel="noreferrer">Source</a>
            </div>
            <div class="footer-note">No custody. No accounts. No ceremonial “trust us.”</div>
        </div>
    </footer>

    <script src="assets/js/site.js" defer></script>
</body>
</html>
