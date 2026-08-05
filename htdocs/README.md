# TradeP2P website

A small PHP website for the TradeP2P project.

## Requirements

- PHP 7.4 or newer
- Any normal Apache, nginx or PHP-capable shared host
- No database
- No Composer
- No build step

## Install

Upload the contents of this directory to the web root, for example `public_html/`.

For a local preview:

```bash
php -S 127.0.0.1:8080
```

Then open `http://127.0.0.1:8080`.

## Configuration

Edit `config.php` to change the project name, version, repository URL or status text.

Set `webclient_url` in `config.php` to the public address of a running
`tradep2p-webclient` (see the root `README.md`) to show a "Web client" link
in the navigation and hero, plus a dedicated section explaining what a
hosted session does and does not give a visitor. Leave it as `'#'` to hide
that entirely.

The GitHub star/fork counter is optional client-side JavaScript. If the GitHub API is unavailable, the page silently falls back to “public repository.”

## Documentation

`documentation.php` contains the source-code documentation. The home page links to it from the main navigation, hero, transport section, build section, call-to-action, and footer.
