# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the client suite: a real gateway to talk to, and where the
client distribution lives on disk.

The transport tests run the actual `secondsign.gateway.server` on loopback with
the reference PKI, because the client's job is to speak to that process and the
interesting failures — a refused handshake, a stopped gateway, a 503 — are
transport-level facts a mock would only assert about itself.
"""

from __future__ import annotations

import importlib.util
import threading
from pathlib import Path

import pytest

from secondsign.gateway.server import (
    ConfigurationRefusal,
    GatewayConfig,
    create_server,
    load_config,
)
from tests.deployment.conftest import REFERENCE, REPO_ROOT

#: The client distribution's home in this repository.
CLIENT_DIR = REPO_ROOT / "client"

PRINCIPAL = "spiffe://secondsign.example/agent/reference"


def load_reference_pki_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_client", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> dict[str, Path]:
    """The reference PKI, with the gateway leaf naming `localhost`.

    The client verifies the gateway's name — it has no knob to switch that
    off — so these tests dial `localhost` and the certificate must say so.
    The reference deployment's own leaf says `gateway` for the same reason.
    """
    root = tmp_path_factory.mktemp("client-pki")
    load_reference_pki_generator().generate(root=root, gateway_dns="localhost")
    return {
        "gateway_cert": root / "gateway" / "gateway-cert.pem",
        "gateway_key": root / "gateway" / "gateway-key.pem",
        "ca_cert": root / "gateway" / "ca-cert.pem",
        "client_cert": root / "agent" / "client-cert.pem",
        "client_key": root / "agent" / "client-key.pem",
    }


@pytest.fixture(scope="module")
def gateway(pki):
    """The real gateway process's server, on loopback with mTLS."""
    config = load_config(
        {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": str(pki["gateway_cert"]),
            "SECONDSIGN_TLS_KEY": str(pki["gateway_key"]),
            "SECONDSIGN_CLIENT_CA": str(pki["ca_cert"]),
            "SECONDSIGN_CLIENT_ALLOWLIST": PRINCIPAL,
        }
    )
    assert isinstance(config, GatewayConfig)
    server = create_server(config)
    assert not isinstance(server, ConfigurationRefusal)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.bound_address
    finally:
        server.shutdown()
        server.close()
        thread.join(timeout=5)
