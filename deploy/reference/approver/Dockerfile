# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# The approver container: a stand-in for the human who answers reviews.
#
# It installs nothing. The approver's console is a standard-library script
# (`console.py`, mounted read-only) speaking mTLS with a credential the agent
# CA cannot mint — which is the point: answering a review requires a different
# door, a different anchor and a different population than proposing one, and
# this container holds exactly the first-and-only credential for that door.

FROM python:3.12-slim

# `console.py` and the TLS material arrive as read-only mounts rather than
# COPY, so what this container can read is decided by compose.yaml — in one
# place, in the file that also decides which networks it is on.
WORKDIR /work
