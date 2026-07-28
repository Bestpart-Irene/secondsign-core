#!/usr/bin/env bash
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# Generate the ephemeral PKI the reference deployment runs on (ADR 0004 §3).
#
# Everything here is thrown away when the stack comes down. No key in this
# directory is ever committed, and `.gitignore` enforces that rather than
# trusting anyone to remember.
#
# The output is deliberately split into three directories, because *which
# container can read which file* is the property the deployment exists to
# demonstrate. Compose mounts each one read-only into exactly one service:
#
#   ca/       the signing key. Mounted nowhere. If an agent could read this it
#             could mint a certificate naming itself any principal it liked,
#             and every other control here would be decoration.
#   gateway/  server certificate and key, plus the CA *certificate* (not the
#             signing key) so it can verify clients.
#   agent/    client certificate and key, plus the CA certificate so it can
#             verify the gateway.
#
# What this does NOT provide is a secret-at-rest guarantee. A bind mount is
# readable by anyone with access to the host. It demonstrates custody
# separation between containers and nothing more; production deployments bring
# their own Vault, Kubernetes Secret or cloud KMS and hand the gateway a file
# path. See README.md.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# One hour. The reference deployment is deliberately far below the 24-hour cap
# the gateway enforces, because short-lived certificates are the *entire*
# revocation story: there is no CRL and no OCSP, so a leaked certificate stays
# valid until it expires. How long that is is the security property.
LIFETIME_HOURS="${SECONDSIGN_CERT_LIFETIME_HOURS:-1}"

# SPIFFE-shaped, and a URI SAN rather than a DNS name or a CN. The gateway reads
# exactly one URI SAN as the ClientPrincipal; a certificate carrying none, or
# more than one, is refused at connection time, because an ambiguous identity is
# not an identity.
CLIENT_PRINCIPAL="${SECONDSIGN_CLIENT_PRINCIPAL:-spiffe://secondsign.example/agent/reference}"

# The name the agent container resolves. It must match, or TLS hostname
# verification fails — which is the correct failure, and a confusing one to
# debug, so it is named here once.
GATEWAY_DNS="${SECONDSIGN_GATEWAY_DNS:-gateway}"

CA_DIR="${HERE}/ca"
GATEWAY_DIR="${HERE}/gateway"
AGENT_DIR="${HERE}/agent"

rm -rf "${CA_DIR}" "${GATEWAY_DIR}" "${AGENT_DIR}"
mkdir -p "${CA_DIR}" "${GATEWAY_DIR}" "${AGENT_DIR}"

# openssl counts -days in whole days, and this needs hours. -not_after takes an
# explicit UTC timestamp, so the lifetime is exact rather than rounded up to a
# day — which would silently make the reference deployment 24× weaker than it
# claims and still pass a test that only checked "it expires".
if date -u -v+1H >/dev/null 2>&1; then
    NOT_AFTER="$(date -u -v"+${LIFETIME_HOURS}H" +%Y%m%d%H%M%SZ)"   # BSD/macOS
else
    NOT_AFTER="$(date -u -d "+${LIFETIME_HOURS} hours" +%Y%m%d%H%M%SZ)"  # GNU
fi

umask 077

# --- The CA -----------------------------------------------------------------
# Longer-lived than the leaves it signs: rotating the CA means overlapping an
# old and a new one in the bundle, which is a different operation from a leaf
# expiring, and conflating their lifetimes makes rotation impossible to rehearse.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CA_DIR}/ca-key.pem" \
    -out "${CA_DIR}/ca-cert.pem" \
    -days 1 \
    -subj "/CN=SecondSign reference CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    2>/dev/null

# --- The gateway leaf: server auth, verified by DNS name ---------------------
openssl req -newkey rsa:2048 -nodes \
    -keyout "${GATEWAY_DIR}/gateway-key.pem" \
    -out "${HERE}/gateway.csr" \
    -subj "/CN=${GATEWAY_DNS}" \
    2>/dev/null

openssl x509 -req \
    -in "${HERE}/gateway.csr" \
    -CA "${CA_DIR}/ca-cert.pem" -CAkey "${CA_DIR}/ca-key.pem" -CAcreateserial \
    -out "${GATEWAY_DIR}/gateway-cert.pem" \
    -not_after "${NOT_AFTER}" \
    -extfile <(printf '%s\n' \
        "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth" \
        "subjectAltName=DNS:${GATEWAY_DNS}") \
    2>/dev/null

# --- The client leaf: client auth, identified by a single URI SAN ------------
openssl req -newkey rsa:2048 -nodes \
    -keyout "${AGENT_DIR}/client-key.pem" \
    -out "${HERE}/client.csr" \
    -subj "/CN=reference-agent" \
    2>/dev/null

openssl x509 -req \
    -in "${HERE}/client.csr" \
    -CA "${CA_DIR}/ca-cert.pem" -CAkey "${CA_DIR}/ca-key.pem" -CAcreateserial \
    -out "${AGENT_DIR}/client-cert.pem" \
    -not_after "${NOT_AFTER}" \
    -extfile <(printf '%s\n' \
        "basicConstraints=critical,CA:FALSE" \
        "keyUsage=critical,digitalSignature" \
        "extendedKeyUsage=clientAuth" \
        "subjectAltName=URI:${CLIENT_PRINCIPAL}") \
    2>/dev/null

# The CA *certificate* goes to both sides so each can verify the other. The CA
# *key* stays in ca/, which Compose mounts into nothing.
cp "${CA_DIR}/ca-cert.pem" "${GATEWAY_DIR}/ca-cert.pem"
cp "${CA_DIR}/ca-cert.pem" "${AGENT_DIR}/ca-cert.pem"

rm -f "${HERE}/gateway.csr" "${HERE}/client.csr" "${CA_DIR}/ca-cert.srl"

# Readable by the container user; the mount is read-only in any case.
chmod 0644 "${GATEWAY_DIR}"/*.pem "${AGENT_DIR}"/*.pem
chmod 0600 "${CA_DIR}/ca-key.pem"

echo "issued: client principal ${CLIENT_PRINCIPAL}, valid ${LIFETIME_HOURS}h, not after ${NOT_AFTER}"
