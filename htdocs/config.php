<?php

declare(strict_types=1);

return [
    'name' => 'TradeP2P',
    'tagline' => 'Progressive fractional settlement for direct peer-to-peer crypto trades.',
    'version' => '0.5.0',
    'repository' => 'https://github.com/patirckk1994/tradep2p2',
    'repository_api' => 'https://api.github.com/repos/patirckk1994/tradep2p2',
    'documentation' => 'documentation.php',
    'license' => 'Open source',
    'status' => 'Protocol test source',
    // Point this at wherever tradep2p-webclient is reverse-proxied for the
    // public (see setup_mediator.sh and README.md). Leave as '#' to hide
    // the web client from the navigation until it is actually deployed.
    'webclient_url' => '#',
];
