# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# The agent container: a stand-in for a workload that has stopped cooperating.
#
# It deliberately installs **nothing**. Not `secondsign-core`, not
# `secondsign-client`, not a rail SDK — a plain Python runtime and the standard
# library, which is what the adversarial suite attacks with.
#
# The reason it installs nothing rather than installing `secondsign-client` is
# that the client is not the threat. An agent bypassing its authorization
# boundary does not politely call the sanctioned client; it opens a socket. A
# suite that could only demonstrate the sanctioned path behaving correctly would
# be testing the one caller that was never in question.
#
# `secondsign-client` will be installed here when it exists, so that the
# sanctioned path can be exercised alongside the attacks — but the attacks stay
# standard-library, and stay the point.

FROM python:3.12-slim

# `probe.py` and the TLS material arrive as read-only mounts rather than COPY,
# so what this container can read is decided by compose.yaml — in one place, in
# the file that also decides which networks it is on.
WORKDIR /work
