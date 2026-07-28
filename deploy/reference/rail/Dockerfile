# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
#
# The mock rail. Standard library only, so nothing is installed and the
# recording path has no dependency that could fail and lose a line.

FROM python:3.12-slim

RUN mkdir -p /var/log/rail
COPY rail/mock_rail.py /app/mock_rail.py

WORKDIR /app
CMD ["python", "mock_rail.py"]
