#!/usr/bin/env sh
set -eu

name="${1:-mediator}"
# ML-DSA-65 (FIPS 204) post-quantum signature, pinned by SHA-256 fingerprint
# rather than CA-validated - see setup_mediator.sh for why RSA/ECDSA would
# leave authentication non-PQ. Requires OpenSSL 3.5+.
openssl req -x509 -newkey ML-DSA-65 -nodes -days 365 \
  -subj "/CN=TradeP2P Mediator" \
  -keyout "${name}.key.pem" \
  -out "${name}.cert.pem"
chmod 600 "${name}.key.pem"
openssl x509 -in "${name}.cert.pem" -noout -fingerprint -sha256
