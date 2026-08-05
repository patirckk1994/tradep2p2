<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$repo = e($config['repository']);
$name = e($config['name']);
$tagline = e($config['tagline']);
$version = e($config['version']);
$status = e($config['status']);
$documentation = e($config['documentation']);
$webclientUrl = e($config['webclient_url'] ?? '#');
$webclientConfigured = ($config['webclient_url'] ?? '#') !== '#';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="<?= $tagline ?>">
    <meta name="theme-color" content="#f4f2ea">
    <meta property="og:type" content="website">
    <meta property="og:title" content="<?= $name ?> — Fractional P2P Settlement">
    <meta property="og:description" content="<?= $tagline ?>">
    <meta property="og:url" content="<?= $repo ?>">
    <title><?= $name ?> — Fractional P2P Settlement</title>
    <link rel="icon" href="assets/img/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body data-repository-api="<?= e($config['repository_api']) ?>">
    <a class="skip-link" href="#main">Skip to content</a>

    <header class="site-header" id="top">
        <div class="shell nav-shell">
            <a class="brand" href="#top" aria-label="TradeP2P home">
                <span class="brand-mark" aria-hidden="true">T&gt;P</span>
                <span class="brand-copy">
                    <strong><?= $name ?></strong>
                    <small>fractional settlement protocol</small>
                </span>
            </a>

            <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav">
                <span></span><span></span><span></span>
                <span class="sr-only">Toggle navigation</span>
            </button>

            <nav class="site-nav" id="site-nav" aria-label="Primary navigation">
                <a href="#protocol">Protocol</a>
                <a href="#security">Security</a>
                <a href="#workflow">Workflow</a>
                <a href="#status">Status</a>
                <a href="<?= $documentation ?>">Documentation</a>
                <?php if ($webclientConfigured): ?>
                <a href="<?= $webclientUrl ?>">Web client</a>
                <?php endif; ?>
                <a class="nav-github" href="<?= $repo ?>" target="_blank" rel="noreferrer">GitHub &#8599;</a>
            </nav>
        </div>
    </header>

    <?php if ($webclientConfigured): ?>
    <div class="notice-banner">
        <div class="shell">
            <strong>&#9888; Privacy notice:</strong>
            <span>The hosted web client is a convenience tool, not an anonymity guarantee. Privacy is not guaranteed for accounts or sessions created there &mdash; see the warning on the <a href="<?= $webclientUrl ?>">web client</a> page before using it.</span>
        </div>
    </div>
    <?php endif; ?>

    <main id="main">
        <section class="hero">
            <div class="hero-grid shell">
                <div class="hero-copy">
                    <div class="eyebrow"><span class="pulse"></span> <?= $status ?> &middot; v<?= $version ?></div>
                    <h1>Trade value in <span>bounded steps</span>, not one blind leap.</h1>
                    <p class="hero-lead">
                        TradeP2P is a minimal, non-custodial mediator for anonymous peer-to-peer
                        offers and progressive fractional settlement. The mediator coordinates
                        turns. The actual transfers remain between the peers.
                    </p>
                    <div class="hero-actions">
                        <?php if ($webclientConfigured): ?>
                        <a class="button button-primary" href="<?= $webclientUrl ?>">Open web client</a>
                        <a class="button button-secondary" href="<?= $repo ?>" target="_blank" rel="noreferrer">View source on GitHub</a>
                        <?php else: ?>
                        <a class="button button-primary" href="<?= $repo ?>" target="_blank" rel="noreferrer">View source on GitHub</a>
                        <?php endif; ?>
                        <a class="button button-secondary" href="<?= $documentation ?>">Read code documentation</a>
                    </div>
                    <div class="repo-meta" aria-live="polite">
                        <span>Open source</span>
                        <span>C++20</span>
                        <span>TLS 1.3</span>
                        <span id="repo-stats">public repository</span>
                    </div>
                </div>

                <div class="hero-terminal" aria-label="Protocol summary">
                    <div class="terminal-head">
                        <span></span><span></span><span></span>
                        <code>tradep2p://session</code>
                    </div>
                    <div class="terminal-body">
                        <p><i>$</i> /offer QRL 500000 BTC 100000 10 bc1...</p>
                        <p class="muted">offer room created: 015e52...</p>
                        <p><i>$</i> /join 015e52... q1...</p>
                        <p class="good">room ready · anonymous peers connected</p>
                        <p><b>round 1/10</b> SEND 50000 QRL → q1...</p>
                        <p class="muted">peer verifies externally</p>
                        <p><b>round 1/10</b> EXPECT 10000 BTC → bc1...</p>
                        <p class="caret">_</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="principle-section" id="protocol">
            <div class="shell">
                <div class="section-heading compact">
                    <span class="kicker">01 / Core invariant</span>
                    <h2>Fractional settlement is fixed. Everything around it is negotiable.</h2>
                    <p>
                        Peer discovery, transport, pricing, identity, reputation and chain-specific
                        behavior can change. The central rule stays simple: never expose the full trade
                        value in one trust event.
                    </p>
                </div>

                <div class="invariant-panel">
                    <div class="risk-block risk-large">
                        <span>Traditional bilateral trade</span>
                        <strong>100%</strong>
                        <small>single counterparty exposure</small>
                    </div>
                    <div class="transform-arrow" aria-hidden="true">→</div>
                    <div class="fraction-stack" aria-label="Trade split into fractional rounds">
                        <div>10%</div><div>10%</div><div>10%</div><div>10%</div><div>10%</div>
                        <div>10%</div><div>10%</div><div>10%</div><div>10%</div><div>10%</div>
                    </div>
                    <div class="risk-copy">
                        <strong>One tranche at a time</strong>
                        <p>If a peer stops, later rounds never execute.</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="features-section">
            <div class="shell feature-grid">
                <article class="feature-card">
                    <span class="feature-index">01</span>
                    <h3>Non-custodial</h3>
                    <p>The mediator never holds funds, private keys or wallet balances.</p>
                </article>
                <article class="feature-card">
                    <span class="feature-index">02</span>
                    <h3>Anonymous clients</h3>
                    <p>No accounts, usernames or client certificates. Connection IDs are temporary handles.</p>
                </article>
                <article class="feature-card">
                    <span class="feature-index">03</span>
                    <h3>Opaque addresses</h3>
                    <p>Peers provide receive addresses. The mediator does not identify chains or validate address formats.</p>
                </article>
                <article class="feature-card">
                    <span class="feature-index">04</span>
                    <h3>External verification</h3>
                    <p>Transfers are sent and checked outside the mediator. The protocol coordinates acknowledgements only.</p>
                </article>
            </div>
        </section>

        <section class="flow-section" id="workflow">
            <div class="shell">
                <div class="section-heading split-heading">
                    <div>
                        <span class="kicker">02 / Protocol flow</span>
                        <h2>Minimal offer-room workflow</h2>
                    </div>
                    <p>No chat, no hosted wallet and no automated transaction inspection.</p>
                </div>

                <div class="flowchart" role="list" aria-label="TradeP2P workflow">
                    <div class="flow-node" role="listitem">
                        <span>1</span>
                        <strong>Publish offer</strong>
                        <small>Assets, integer amounts, rounds and receive address.</small>
                    </div>
                    <div class="flow-link" aria-hidden="true"></div>
                    <div class="flow-node" role="listitem">
                        <span>2</span>
                        <strong>Join room</strong>
                        <small>The second peer supplies its receive address.</small>
                    </div>
                    <div class="flow-link" aria-hidden="true"></div>
                    <div class="flow-node active" role="listitem">
                        <span>3</span>
                        <strong>Settle rounds</strong>
                        <small>Send, verify externally, acknowledge and advance.</small>
                    </div>
                    <div class="flow-link" aria-hidden="true"></div>
                    <div class="flow-node" role="listitem">
                        <span>4</span>
                        <strong>Complete or abort</strong>
                        <small>Remaining value stays unexposed after a stop.</small>
                    </div>
                </div>

                <div class="command-panel">
                    <div class="command-tabs" role="tablist" aria-label="Command examples">
                        <button class="command-tab is-active" data-target="offer-code" role="tab" aria-selected="true">Offer</button>
                        <button class="command-tab" data-target="join-code" role="tab" aria-selected="false">Join</button>
                        <button class="command-tab" data-target="settle-code" role="tab" aria-selected="false">Settle</button>
                    </div>
                    <pre id="offer-code" class="command-code is-active"><code>/offer SELL_SYMBOL SELL_AMOUNT BUY_SYMBOL BUY_AMOUNT ROUNDS RECEIVE_ADDRESS

/offer QRL 500000 BTC 100000 10 bc1-my-bitcoin-address</code></pre>
                    <pre id="join-code" class="command-code"><code>/offers
/join ROOM_ID q1-my-qrl-address
/cancel ROOM_ID</code></pre>
                    <pre id="settle-code" class="command-code"><code>/sent ROOM_ID
/received ROOM_ID
/abort ROOM_ID</code></pre>
                </div>
            </div>
        </section>

        <section class="boundary-section" id="webclient">
            <div class="shell">
                <div class="section-heading compact">
                    <span class="kicker">Web client</span>
                    <h2>Trade from a browser, without pretending it is anonymous.</h2>
                    <p>
                        The hosted web client is a convenience session, not a privacy tool.
                        It keeps a local username and password on the server it runs on so
                        you can leave and come back, then drives an ordinary anonymous
                        connection to a mediator on your behalf.
                    </p>
                </div>

                <div class="boundary-grid">
                    <article class="boundary-card sees">
                        <span class="kicker">What a session gives you</span>
                        <h3>Register, log in, log out</h3>
                        <ul>
                            <li>A username and password local to that web client only</li>
                            <li>One persistent mediator connection while you are logged in</li>
                            <li>The same offer, join and settlement actions as the CLI</li>
                            <li>A session you can end at any time from the page</li>
                        </ul>
                    </article>
                    <article class="boundary-card never">
                        <span class="kicker">What it does not give you</span>
                        <h3>Anonymity guarantees</h3>
                        <ul>
                            <li>The operator can see your session activity and IP address</li>
                            <li>Your account is not a protocol identity of any kind</li>
                            <li>No custody, wallet access or transaction broadcasting</li>
                            <li>No promise this server is trustworthy &mdash; you choose it</li>
                        </ul>
                    </article>
                </div>

                <div class="docs-callout warning stack-gap">
                    <strong>Privacy is not guaranteed.</strong>
                    <span>Run the CLI or dashboard client yourself, ideally over Tor, if you need stronger guarantees than a hosted session can offer.</span>
                </div>

                <?php if ($webclientConfigured): ?>
                <div class="hero-actions stack-gap">
                    <a class="button button-primary" href="<?= $webclientUrl ?>">Open the web client</a>
                </div>
                <?php else: ?>
                <p class="stack-gap">No public web client is configured for this deployment yet. Run <code>tradep2p-webclient</code> and set <code>webclient_url</code> in <code>config.php</code>.</p>
                <?php endif; ?>
            </div>
        </section>

        <section class="security-section" id="security">
            <div class="shell security-grid">
                <div class="section-heading compact">
                    <span class="kicker">03 / Transport</span>
                    <h2>Small protocol surface. Strict wire behavior.</h2>
                    <p>
                        The current implementation keeps client identity out of the protocol while
                        authenticating the mediator through exact certificate pinning.
                    </p>
                    <a class="text-link" href="<?= $documentation ?>#transport">Read the transport documentation →</a>
                </div>

                <div class="security-list">
                    <div><strong>TLS 1.3 only</strong><span>Encrypted transport with no legacy protocol fallback.</span></div>
                    <div><strong>Exact server pin</strong><span>Clients require the mediator certificate SHA-256 fingerprint.</span></div>
                    <div><strong>Strict frames</strong><span>Fixed header, 4 KiB payload ceiling and exact-length reads.</span></div>
                    <div><strong>Replay rejection</strong><span>Monotonic per-direction sequence numbers reject repeated or reordered frames.</span></div>
                    <div><strong>Optional Tor path</strong><span>SOCKS5 transport supports onion endpoints without changing protocol semantics.</span></div>
                </div>
            </div>
        </section>

        <section class="boundary-section">
            <div class="shell boundary-grid">
                <article class="boundary-card sees">
                    <span class="kicker">The mediator coordinates</span>
                    <h3>What it sees</h3>
                    <ul>
                        <li>Asset symbols and integer amounts</li>
                        <li>Number of settlement rounds</li>
                        <li>Opaque receive addresses after a room is joined</li>
                        <li><code>sent</code> and <code>received</code> acknowledgements</li>
                    </ul>
                </article>
                <article class="boundary-card never">
                    <span class="kicker">Outside protocol scope</span>
                    <h3>What it never handles</h3>
                    <ul>
                        <li>Private keys or wallet custody</li>
                        <li>Transaction creation or broadcast</li>
                        <li>Blockchain searches or confirmations</li>
                        <li>Accounts, legal identities or user profiles</li>
                    </ul>
                </article>
            </div>
        </section>

        <section class="status-section" id="status">
            <div class="shell">
                <div class="section-heading split-heading">
                    <div>
                        <span class="kicker">04 / Current status</span>
                        <h2>Protocol-test source, deliberately narrow.</h2>
                    </div>
                    <p>Designed to prove the mediator and fractional state machine before adding more machinery.</p>
                </div>

                <div class="status-layout">
                    <div class="status-card current">
                        <span>Implemented</span>
                        <ul>
                            <li>Anonymous offer rooms</li>
                            <li>Fractional round coordination</li>
                            <li>Strict binary protocol</li>
                            <li>Pinned TLS 1.3 transport</li>
                            <li>Optional mediator registry</li>
                            <li>Optional Tor SOCKS5 connection</li>
                        </ul>
                    </div>
                    <div class="status-card limits">
                        <span>Current limitations</span>
                        <ul>
                            <li>Memory-only room state</li>
                            <li>No reconnect or crash recovery</li>
                            <li>No automatic offer timeout</li>
                            <li>User acknowledgements are not transaction proofs</li>
                            <li>No NAT traversal</li>
                            <li>Linux/POSIX implementation</li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>

        <section class="build-section">
            <div class="shell build-grid">
                <div>
                    <span class="kicker">05 / Build</span>
                    <h2>Clone. Compile. Test.</h2>
                    <p>Zero web framework dependencies. The protocol implementation uses CMake, C++20 and OpenSSL 3.x. <a class="text-link" href="<?= $documentation ?>#build">Build and test notes →</a></p>
                </div>
                <pre><code>git clone <?= $repo ?>.git
cd tradep2p2
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure</code></pre>
            </div>
        </section>

        <section class="cta-section">
            <div class="shell cta-panel">
                <div>
                    <span class="kicker">Open protocol</span>
                    <h2>Read the code. Break the assumptions. Improve the state machine.</h2>
                </div>
                <div class="cta-actions">
                    <a class="button button-secondary" href="<?= $documentation ?>">Code documentation</a>
                    <a class="button button-primary" href="<?= $repo ?>" target="_blank" rel="noreferrer">GitHub source ↗</a>
                </div>
            </div>
        </section>
    </main>

    <footer class="site-footer">
        <div class="shell footer-grid">
            <div>
                <strong><?= $name ?></strong>
                <p>Non-custodial coordination for progressive peer-to-peer settlement.</p>
            </div>
            <div class="footer-links">
                <a href="#protocol">Protocol</a>
                <a href="#security">Security</a>
                <a href="<?= $documentation ?>">Documentation</a>
                <a href="<?= $repo ?>" target="_blank" rel="noreferrer">Source</a>
            </div>
            <div class="footer-note">No custody. No accounts. No ceremonial “trust us.”</div>
        </div>
    </footer>

    <script src="assets/js/site.js" defer></script>
</body>
</html>
