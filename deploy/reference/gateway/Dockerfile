# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# The gateway container. Build context is the repository root, because this is
# the one service that runs the real `secondsign-core` — the reference
# deployment must not demonstrate a stand-in.
#
# It holds the rail credential and the only route to the rail network. Its
# private key arrives as a read-only mount from `tls/gateway/`; the CA signing
# key that issued it is mounted into nothing at all.

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

# No CMD: compose.yaml supplies the command, so the module being started is
# visible in the same file as the networks it is joined to and the credential it
# is given. Until CORE-S019's server module lands, that command fails — which is
# the accurate state, and the deployment suite reports it as such rather than
# as a passing test.
