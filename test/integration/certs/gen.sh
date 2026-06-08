#!/usr/bin/env bash
# Generates an internal CA + a TLS cert for the `central` service. The SANs cover
# the compose service name (`central`, used by standalones pushing over the
# internal network) AND loopback (`localhost`/`127.0.0.1`, used by the host-side
# driver), so both validate against the same CA. Idempotent — delete *.crt/*.key
# to regenerate.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f ca.crt && -f central.crt && -f central.key ]]; then
  echo "certs already present (delete certs/*.crt certs/*.key to regenerate)"
  exit 0
fi

echo "generating internal CA + central cert..."
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=SimpleAuth Integration Test CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout central.key -out central.csr \
  -subj "/CN=central" >/dev/null 2>&1

ext="$(mktemp)"
printf "subjectAltName=DNS:central,DNS:localhost,IP:127.0.0.1\n" > "$ext"
openssl x509 -req -in central.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out central.crt -days 3650 -extfile "$ext" >/dev/null 2>&1
rm -f central.csr ca.srl "$ext"

echo "  -> certs/ca.crt, certs/central.crt, certs/central.key (SAN: central, localhost, 127.0.0.1)"
