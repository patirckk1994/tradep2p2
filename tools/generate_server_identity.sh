#!/usr/bin/env sh
set -eu

name="${1:-mediator}"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj "/CN=TradeP2P Mediator" \
  -keyout "${name}.key.pem" \
  -out "${name}.cert.pem"
chmod 600 "${name}.key.pem"
openssl x509 -in "${name}.cert.pem" -noout -fingerprint -sha256
