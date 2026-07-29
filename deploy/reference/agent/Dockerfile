# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# The agent container: a stand-in for a workload that has stopped cooperating,
# and — since CORE-S019 step 7 — also for one that has not.
#
# It installs `secondsign-client` and nothing else. Not `secondsign-core`, not a
# rail SDK: the client declares pydantic alone, so this environment ends up with
# the sanctioned path and no gateway, no policy, no approval, no audit and no
# rails. `python -c "import secondsign.gateway"` in here is a ModuleNotFoundError,
# and the deployment suite executes exactly that rather than asserting it.
#
# The adversarial suite stays standard-library, and stays the point. An agent
# bypassing its authorization boundary does not politely call the sanctioned
# client; it opens a socket. What the client buys this container is the other
# half of the demonstration: the same workload, asking properly, gets an answer
# and moves money it could not have moved itself.

FROM python:3.12-slim

WORKDIR /app

# The build context is the repository root, so the client is installed from
# source rather than from an index — the container runs the code in this commit.
COPY client ./client
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ./client

# `probe.py` and the TLS material arrive as read-only mounts rather than COPY,
# so what this container can read is decided by compose.yaml — in one place, in
# the file that also decides which networks it is on.
WORKDIR /work
