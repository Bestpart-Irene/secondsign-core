# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: the gateway process boundary (CORE-S019, ADR 0004 §5).

The gateway is the one process that holds the rail credential and a route to the
rail, so the attacks here are aimed at how it comes up and who it believes.
Three groups:

**Startup.** Off loopback, the gateway starts only when all seven conditions of
ADR 0004 §5 hold: a server certificate, its key, a client CA bundle, client
verification enabled, a minimum TLS version, a derivable principal, and
fail-closed handling of unknown principals. The first six of these an operator
could plausibly half-configure; every half-configuration must be a refusal to
start, never a warning. "TLS is configured" is not sufficient — a listener with
a server certificate and no client verification is an unauthenticated listener
wearing encryption.

**Configuration.** The manifest forbids "a process boundary that a configuration
setting can collapse". The strongest form of that is structural: verification
mode and the TLS floor are constants, and a `SECONDSIGN_`-prefixed setting the
gateway does not recognise is refused rather than ignored — an ignored
`SECONDSIGN_TLS_DISABLE=1` is indistinguishable, to the operator who set it,
from one that worked.

**Identity.** `ClientPrincipal` is derived from the TLS session's single URI
SAN and from nothing else. No identity, ambiguous identity, malformed identity,
a certificate that outlives the 24-hour cap, and a principal not on the
allowlist are all refusals. A request body that carries a principal is refused
rather than ignored, because accepted-and-ignored is a field a later change can
quietly start honouring.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import ssl
import threading

import pytest

from secondsign.gateway.server import (
    MAX_CLIENT_LEAF_SECONDS,
    ConfigurationRefusal,
    DerivedPrincipal,
    GatewayConfig,
    PrincipalRefusal,
    PrincipalRefusalReason,
    StartupRefusalReason,
    build_authorization,
    build_ssl_context,
    create_server,
    derive_principal,
    load_config,
)
from tests.deployment.conftest import REFERENCE

#: The workload identity the reference deployment issues, reused here so the
#: tests speak the same principal the deployment does.
PRINCIPAL = "spiffe://secondsign.example/agent/reference"

#: A TEST-NET-3 address: unambiguously not loopback, never routable, never bound.
NON_LOOPBACK_BIND = "203.0.113.9:8787"


def _load_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_redteam", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> dict[str, str]:
    """A real, throwaway PKI, for the cases that must load actual material."""
    root = tmp_path_factory.mktemp("redteam-pki")
    _load_generator().generate(root=root)
    return {
        "cert": str(root / "gateway" / "gateway-cert.pem"),
        "key": str(root / "gateway" / "gateway-key.pem"),
        "ca": str(root / "gateway" / "ca-cert.pem"),
    }


@pytest.fixture()
def tls_files(tmp_path) -> dict[str, str]:
    """Readable files that are not certificates.

    `load_config` checks presence and readability; whether the material parses
    is `create_server`'s problem, and there is a case for that seam too.
    """
    paths = {}
    for name in ("gateway-cert.pem", "gateway-key.pem", "ca-cert.pem"):
        path = tmp_path / name
        path.write_text("not certificate material")
        paths[name] = str(path)
    return {
        "SECONDSIGN_TLS_CERT": paths["gateway-cert.pem"],
        "SECONDSIGN_TLS_KEY": paths["gateway-key.pem"],
        "SECONDSIGN_CLIENT_CA": paths["ca-cert.pem"],
    }


def _non_loopback_env(tls_files: dict[str, str], **overrides: str) -> dict[str, str]:
    env = {
        "SECONDSIGN_BIND": NON_LOOPBACK_BIND,
        "SECONDSIGN_CLIENT_ALLOWLIST": PRINCIPAL,
        **tls_files,
    }
    env.update(overrides)
    return env


def _refusal(env: dict[str, str]) -> ConfigurationRefusal:
    result = load_config(env)
    assert isinstance(result, ConfigurationRefusal), (
        f"expected a refusal to start, got a usable configuration: {result!r}"
    )
    return result


class TestTheSevenConditionBindCheck:
    """ADR 0004 §5: off loopback, every missing condition is a refusal to start."""

    def test_a_non_loopback_bind_with_no_tls_material_is_refused(self) -> None:
        refusal = _refusal({"SECONDSIGN_BIND": NON_LOOPBACK_BIND})

        assert refusal.reason is StartupRefusalReason.missing_server_certificate

    def test_a_server_certificate_without_client_verification_is_refused_not_warned(
        self, tls_files
    ) -> None:
        """The red-team case the manifest names explicitly.

        A server certificate and key with no client CA bundle is the
        half-configuration an operator lands on by following a generic TLS
        how-to. It must be a refusal — a warning is a log line nobody reads on
        a listener that authenticates nobody.
        """
        env = _non_loopback_env(tls_files)
        del env["SECONDSIGN_CLIENT_CA"]

        refusal = _refusal(env)

        assert refusal.reason is StartupRefusalReason.missing_client_ca
        assert "unauthenticated" in refusal.detail

    def test_a_missing_server_key_is_refused(self, tls_files) -> None:
        env = _non_loopback_env(tls_files)
        del env["SECONDSIGN_TLS_KEY"]

        assert _refusal(env).reason is StartupRefusalReason.missing_server_key

    def test_a_named_file_that_is_not_there_is_refused(self, tls_files, tmp_path) -> None:
        env = _non_loopback_env(tls_files, SECONDSIGN_TLS_CERT=str(tmp_path / "does-not-exist.pem"))

        assert _refusal(env).reason is StartupRefusalReason.unreadable_tls_material

    def test_an_absent_allowlist_is_refused(self, tls_files) -> None:
        """Condition six: without an allowlist no principal is derivable, and a
        gateway that cannot derive a principal has nobody it may serve."""
        env = _non_loopback_env(tls_files)
        del env["SECONDSIGN_CLIENT_ALLOWLIST"]

        assert _refusal(env).reason is StartupRefusalReason.missing_principal_allowlist

    def test_an_empty_allowlist_is_refused(self, tls_files) -> None:
        env = _non_loopback_env(tls_files, SECONDSIGN_CLIENT_ALLOWLIST="  , ")

        assert _refusal(env).reason is StartupRefusalReason.missing_principal_allowlist

    @pytest.mark.parametrize("entry", ["*", "spiffe://secondsign.example/agent/*"])
    def test_a_wildcard_principal_is_refused(self, tls_files, entry) -> None:
        """Condition seven, made structural: with no wildcard representable,
        "unknown principals are allowed" is not an expressible configuration."""
        env = _non_loopback_env(tls_files, SECONDSIGN_CLIENT_ALLOWLIST=entry)

        assert _refusal(env).reason is StartupRefusalReason.wildcard_principal_entry

    def test_a_malformed_allowlist_entry_is_refused(self, tls_files) -> None:
        env = _non_loopback_env(tls_files, SECONDSIGN_CLIENT_ALLOWLIST="not-a-uri")

        assert _refusal(env).reason is StartupRefusalReason.malformed_principal_entry

    @pytest.mark.parametrize(
        "bind", ["no-port-at-all", ":8787", "host:", "host:banana", "host:70000"]
    )
    def test_a_malformed_bind_is_refused(self, bind) -> None:
        assert _refusal({"SECONDSIGN_BIND": bind}).reason is StartupRefusalReason.malformed_bind

    def test_a_hostname_bind_gets_the_non_loopback_treatment(self) -> None:
        """`localhost` usually resolves to loopback. Usually is the problem: a
        name is an indirection through a resolver, and the plaintext concession
        is scoped to what the kernel guarantees, not what DNS asserts today."""
        refusal = _refusal({"SECONDSIGN_BIND": "localhost:8787"})

        assert refusal.reason is StartupRefusalReason.missing_server_certificate


class TestNoSettingCollapsesTheBoundary:
    """The manifest's forbidden shape: a boundary a configuration can turn off."""

    @pytest.mark.parametrize(
        "setting", ["SECONDSIGN_TLS_DISABLE", "SECONDSIGN_CLIENT_VERIFY", "SECONDSIGN_INSECURE"]
    )
    def test_an_unrecognised_setting_is_refused_rather_than_ignored(
        self, tls_files, setting
    ) -> None:
        """The operator who sets `SECONDSIGN_CLIENT_VERIFY=off` believes it did
        something. Ignoring it would leave that belief intact; refusing to start
        is the only answer that corrects it."""
        env = _non_loopback_env(tls_files, **{setting: "off"})

        refusal = _refusal(env)

        assert refusal.reason is StartupRefusalReason.unknown_setting
        assert setting in refusal.detail

    def test_client_verification_and_the_tls_floor_are_constants(self, pki) -> None:
        """Conditions four and five have no configuration surface at all: the
        built context requires a client certificate and speaks TLS 1.3 or
        nothing, and no environment variable exists that reaches either."""
        context = build_ssl_context(cert=pki["cert"], key=pki["key"], client_ca=pki["ca"])

        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.minimum_version is ssl.TLSVersion.TLSv1_3

    def test_material_that_does_not_parse_is_refused_at_start(self, tls_files) -> None:
        """Readable-but-garbage material passes `load_config` and must still be
        a startup refusal, not a listener that limps up without TLS."""
        config = load_config(_non_loopback_env(tls_files, SECONDSIGN_BIND="127.0.0.1:0"))
        assert isinstance(config, GatewayConfig)

        result = create_server(config)

        assert isinstance(result, ConfigurationRefusal)
        assert result.reason is StartupRefusalReason.unreadable_tls_material

    def test_the_default_bind_is_loopback(self) -> None:
        """An empty environment yields a loopback listener, never an open one."""
        config = load_config({})

        assert isinstance(config, GatewayConfig)
        assert config.host == "127.0.0.1"
        assert config.tls is None

    def test_naming_tls_material_on_loopback_requires_all_of_it(self, tls_files) -> None:
        """Half a TLS configuration on loopback is not quietly ignored: naming
        any of it opts into all seven conditions."""
        env = {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": tls_files["SECONDSIGN_TLS_CERT"],
        }

        assert _refusal(env).reason is StartupRefusalReason.missing_server_key

    def test_the_configuration_never_carries_the_rail_credential(self, tls_files) -> None:
        """The rail credential is consumed by the executor when the rail is
        wired; the configuration object must not hold it, so no repr, log line
        or refusal detail can ever leak it."""
        env = _non_loopback_env(
            tls_files,
            SECONDSIGN_BIND="127.0.0.1:0",
            SECONDSIGN_RAIL_URL="http://rail:9000",
            SECONDSIGN_RAIL_API_KEY="sk_reference_not_a_real_key",  # noqa: S106 — the fake key the reference deployment uses
        )

        config = load_config(env)

        assert isinstance(config, GatewayConfig)
        assert "sk_reference_not_a_real_key" not in repr(config)


def _peercert(
    *uris: str,
    not_before: str = "Jul 28 12:00:00 2026 GMT",
    not_after: str = "Jul 28 13:00:00 2026 GMT",
    extra_san: tuple = (),
) -> dict:
    """A peer certificate as `ssl.SSLSocket.getpeercert` reports one."""
    return {
        "subjectAltName": tuple(("URI", uri) for uri in uris) + tuple(extra_san),
        "notBefore": not_before,
        "notAfter": not_after,
    }


ALLOWLIST = frozenset({PRINCIPAL})


class TestPrincipalDerivation:
    """One URI SAN, well formed, short lived, on the allowlist — or nothing."""

    def test_a_single_allowlisted_uri_san_derives(self) -> None:
        derived = derive_principal(_peercert(PRINCIPAL), ALLOWLIST)

        assert isinstance(derived, DerivedPrincipal)
        assert derived.uri == PRINCIPAL

    def test_no_certificate_is_no_identity(self) -> None:
        assert_refused(derive_principal(None, ALLOWLIST), PrincipalRefusalReason.no_identity)

    def test_no_uri_san_is_no_identity(self) -> None:
        cert = _peercert(extra_san=(("DNS", "agent.internal"),))

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.no_identity)

    def test_two_uri_sans_are_no_identity(self) -> None:
        """Ambiguous identity is no identity. Picking either SAN would let a
        certificate carry one allowlisted name and one it actually uses."""
        cert = _peercert(PRINCIPAL, "spiffe://secondsign.example/agent/second")

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.ambiguous_identity)

    def test_a_malformed_uri_is_refused(self) -> None:
        cert = _peercert("not-a-uri")

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.malformed_identity)

    def test_an_unknown_principal_is_refused_fail_closed(self) -> None:
        cert = _peercert("spiffe://secondsign.example/agent/stranger")

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.unknown_principal)

    def test_a_certificate_outliving_the_cap_is_refused(self) -> None:
        """Short-lived certificates are the entire revocation story (ADR 0004
        §4): there is no CRL and no OCSP, so a 25-hour certificate is a 25-hour
        window in which a leaked key stays valid. The cap is enforced, not
        recommended, because an operator who cannot automate issuance drifts to
        the longest thing that works."""
        cert = _peercert(PRINCIPAL, not_after="Jul 29 13:00:00 2026 GMT")

        assert_refused(
            derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.lifetime_beyond_cap
        )

    def test_exactly_the_cap_is_permitted(self) -> None:
        cert = _peercert(PRINCIPAL, not_after="Jul 29 12:00:00 2026 GMT")

        assert isinstance(derive_principal(cert, ALLOWLIST), DerivedPrincipal)
        assert MAX_CLIENT_LEAF_SECONDS == 24 * 3600

    def test_missing_validity_fields_are_refused(self) -> None:
        cert = _peercert(PRINCIPAL)
        del cert["notAfter"]

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.malformed_identity)

    def test_unparseable_validity_is_refused(self) -> None:
        cert = _peercert(PRINCIPAL, not_after="whenever")

        assert_refused(derive_principal(cert, ALLOWLIST), PrincipalRefusalReason.malformed_identity)


def assert_refused(result: object, reason: PrincipalRefusalReason) -> None:
    assert isinstance(result, PrincipalRefusal), f"expected a refusal, got {result!r}"
    assert result.reason is reason


@pytest.fixture()
def loopback_gateway():
    """A plaintext loopback gateway — the one place plaintext is permitted,
    because on loopback the process boundary is the authentication (ADR 0004
    §5). The wire-level refusals below are identical under TLS; the e2e suite
    exercises that path with real certificates."""
    config = load_config({"SECONDSIGN_BIND": "127.0.0.1:0"})
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


def _post(address: tuple[str, int], body: bytes, path: str = "/authorize") -> tuple[int, dict]:
    connection = http.client.HTTPConnection(*address, timeout=5)
    try:
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class TestABodySuppliedPrincipalIsRefused:
    """The sentence ADR 0004 protects, at the wire: scope derives from the TLS
    session alone, and a body that says otherwise is refused, not ignored."""

    @pytest.mark.parametrize("field", ["client_principal", "principal"])
    def test_a_body_carrying_a_principal_is_refused(self, loopback_gateway, field) -> None:
        body = json.dumps({field: "spiffe://secondsign.example/agent/impersonated"}).encode()

        status, payload = _post(loopback_gateway, body)

        assert status == 400
        assert payload == {"refused": "body_supplied_principal"}

    def test_a_body_without_a_principal_gets_no_verdict(self, loopback_gateway) -> None:
        """This gateway has no rail configured, so it declares itself unable to
        authorize — a refusal stated as unavailability, never a locally invented
        verdict. A gateway that *does* have one is exercised below."""
        status, payload = _post(loopback_gateway, json.dumps({"wire_version": 1}).encode())

        assert status == 503
        assert payload == {"refused": "authorization_unavailable"}

    def test_a_principal_nested_in_the_request_is_refused(self, loopback_gateway) -> None:
        """The wire envelope wraps the request one level down; a smuggled
        principal there is the same claim in a different pocket."""
        body = json.dumps(
            {"wire_version": 1, "request": {"principal": "spiffe://impersonated"}}
        ).encode()

        status, payload = _post(loopback_gateway, body)

        assert status == 400
        assert payload == {"refused": "body_supplied_principal"}

    @pytest.mark.parametrize("version", [99, "1", None])
    def test_an_unrecognised_wire_version_is_refused_not_parsed(
        self, loopback_gateway, version
    ) -> None:
        """ADR 0003 §3: a client announcing a version the gateway does not
        recognise is refused rather than best-effort parsed — a peer speaking a
        different dialect may mean something different by every word in it.
        The string "1" is not the integer 1: type coercion is best-effort
        parsing wearing a smaller costume."""
        body: dict = {"anything": 1}
        if version is not None:
            body["wire_version"] = version

        status, payload = _post(loopback_gateway, json.dumps(body).encode())

        assert status == 400
        assert payload == {"refused": "wire_version_unrecognised"}

    def test_malformed_json_is_refused(self, loopback_gateway) -> None:
        status, payload = _post(loopback_gateway, b"{not json")

        assert status == 400
        assert payload == {"refused": "malformed_body"}

    def test_a_non_object_body_is_refused(self, loopback_gateway) -> None:
        status, payload = _post(loopback_gateway, b'["a", "list"]')

        assert status == 400
        assert payload == {"refused": "malformed_body"}

    def test_an_oversized_body_is_refused_unread(self, loopback_gateway) -> None:
        """The limit is checked against the declared length before any read, so
        an attacker cannot make the gateway buffer an arbitrary body."""
        connection = http.client.HTTPConnection(*loopback_gateway, timeout=5)
        try:
            connection.putrequest("POST", "/authorize")
            connection.putheader("Content-Length", str(2 * 1024 * 1024))
            connection.endheaders()
            response = connection.getresponse()
            assert response.status == 413
        finally:
            connection.close()

    def test_a_nonsense_content_length_is_refused(self, loopback_gateway) -> None:
        for declared in ("banana", "-5"):
            connection = http.client.HTTPConnection(*loopback_gateway, timeout=5)
            try:
                connection.putrequest("POST", "/authorize")
                connection.putheader("Content-Length", declared)
                connection.endheaders()
                response = connection.getresponse()
                assert response.status == 400, f"Content-Length {declared!r} was not refused"
            finally:
                connection.close()

    def test_a_post_anywhere_else_is_refused(self, loopback_gateway) -> None:
        status, payload = _post(loopback_gateway, b"{}", path="/healthz")

        assert status == 404
        assert payload == {"refused": "unknown_path"}


@pytest.fixture()
def wired_loopback_gateway():
    """A loopback gateway that *does* have a rail, so `/authorize` reaches the
    decision path instead of stopping at unavailability."""
    config = load_config({"SECONDSIGN_BIND": "127.0.0.1:0"})
    assert isinstance(config, GatewayConfig)
    service = build_authorization(
        {
            "SECONDSIGN_RAIL_URL": "http://127.0.0.1:1/dispatch",
            "SECONDSIGN_RAIL_API_KEY": "sk_reference_not_a_real_key",
        }
    )
    assert service is not None
    server = create_server(config, authorization=service)
    assert not isinstance(server, ConfigurationRefusal)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.bound_address
    finally:
        server.shutdown()
        server.close()
        thread.join(timeout=5)


class TestAuthorizationNeedsAPrincipalAndARail:
    """Two things `/authorize` will not do without: authorize onto a rail that
    is not configured, and authorize *for* a caller it cannot name."""

    def test_no_rail_configured_means_no_verdict(self) -> None:
        """Both settings, or nothing. A URL without a credential is not a rail
        this process can reach, and half a configuration must not become a
        gateway that looks wired and refuses everything for a subtler reason."""
        assert build_authorization({}) is None
        assert build_authorization({"SECONDSIGN_RAIL_URL": "http://rail:9000"}) is None
        assert build_authorization({"SECONDSIGN_RAIL_API_KEY": "sk_x"}) is None
        assert (
            build_authorization({"SECONDSIGN_RAIL_URL": "", "SECONDSIGN_RAIL_API_KEY": ""}) is None
        )

    def test_a_caller_with_no_derived_identity_is_refused(self, wired_loopback_gateway) -> None:
        """Plaintext loopback authenticates *reaching* the gateway and does not
        make the caller a principal. An authorization needs one — to namespace
        idempotency by, to scope policy to, and to fingerprint into the trail —
        so it is refused rather than run under an anonymous identity."""
        body = json.dumps({"wire_version": 1, "request": _valid_proposal()}).encode()

        status, payload = _post(wired_loopback_gateway, body)

        assert status == 403
        assert payload == {"refused": "no_identity"}

    def test_the_refusal_order_puts_identity_before_the_proposal(
        self, wired_loopback_gateway
    ) -> None:
        """A caller with no identity learns nothing about whether its proposal
        would have parsed."""
        body = json.dumps({"wire_version": 1, "request": {"nonsense": True}}).encode()

        status, payload = _post(wired_loopback_gateway, body)

        assert status == 403
        assert payload == {"refused": "no_identity"}


def _valid_proposal() -> dict:
    fingerprint = "fp:" + "ab" * 32
    return {
        "action": "payment",
        "rail": "card",
        "currency": "USD",
        "amount_minor": 4200,
        "reversibility": "irreversible",
        "counterparty_ref": fingerprint,
        "source_account_ref": fingerprint,
        "request_ref": fingerprint,
    }
