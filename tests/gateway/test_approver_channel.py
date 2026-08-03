# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver channel's configuration and separation rules (CORE-S023).

What is tested here is everything that must be true *before a byte is served*:
the channel loads whole or not at all, the two structural separations — one
trust anchor per door, one door per principal — refuse the process rather than
warn it, and what a checker would be shown is a projection of the stored
review with nothing added. The listener itself, under real mTLS, is
`tests/e2e/test_approver_channel.py`.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path

import pytest

from secondsign.gateway import server as server_module
from secondsign.gateway.approver import (
    ApproverConfig,
    _ApproverHTTPServer,
    check_channel_separation,
    load_approver_config,
    render_review,
)
from secondsign.gateway.server import (
    APPROVER_SETTINGS,
    KNOWN_SETTINGS,
    ConfigurationRefusal,
    StartupRefusalReason,
    load_config,
    main,
)

CHECKER = "spiffe://secondsign.example/approver/reference"
AGENT = "spiffe://secondsign.example/agent/reference"


def _material(tmp_path: Path, name: str, content: bytes = b"pem bytes\n") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def _full_settings(tmp_path: Path, **overrides: str) -> dict[str, str]:
    settings = {
        "SECONDSIGN_APPROVER_BIND": "127.0.0.1:0",
        "SECONDSIGN_APPROVER_TLS_CERT": str(_material(tmp_path, "approver-cert.pem")),
        "SECONDSIGN_APPROVER_TLS_KEY": str(_material(tmp_path, "approver-key.pem")),
        "SECONDSIGN_APPROVER_CA": str(_material(tmp_path, "approver-ca.pem", b"approver ca\n")),
        "SECONDSIGN_APPROVER_ALLOWLIST": CHECKER,
    }
    settings.update(overrides)
    return settings


class TestTheChannelLoadsWholeOrNotAtAll:
    def test_no_approver_settings_means_no_channel(self) -> None:
        assert load_approver_config({}) is None
        assert load_approver_config({"SECONDSIGN_BIND": "127.0.0.1:0"}) is None

    @pytest.mark.parametrize("kept", sorted(APPROVER_SETTINGS))
    def test_any_partial_configuration_is_a_refusal(self, tmp_path, kept) -> None:
        """One setting alone is the sharpest partial: four are missing."""
        alone = {kept: _full_settings(tmp_path)[kept]}
        refusal = load_approver_config(alone)
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.incomplete_approver_channel

    def test_a_full_configuration_loads(self, tmp_path) -> None:
        config = load_approver_config(_full_settings(tmp_path))
        assert isinstance(config, ApproverConfig)
        assert config.allowlist == frozenset({CHECKER})

    def test_the_registry_recognises_every_approver_setting(self, tmp_path) -> None:
        """The unknown-setting refusal and the loader must agree, or a full
        approver configuration would refuse the whole process to start."""
        assert APPROVER_SETTINGS <= KNOWN_SETTINGS
        config = load_config({"SECONDSIGN_BIND": "127.0.0.1:0", **_full_settings(tmp_path)})
        assert not isinstance(config, ConfigurationRefusal)

    def test_a_malformed_bind_is_a_refusal(self, tmp_path) -> None:
        refusal = load_approver_config(
            _full_settings(tmp_path, SECONDSIGN_APPROVER_BIND="not a bind")
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.malformed_bind

    def test_unreadable_material_is_a_refusal(self, tmp_path) -> None:
        refusal = load_approver_config(
            _full_settings(tmp_path, SECONDSIGN_APPROVER_TLS_CERT=str(tmp_path / "absent.pem"))
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.unreadable_tls_material

    def test_a_whitespace_allowlist_is_a_refusal(self, tmp_path) -> None:
        refusal = load_approver_config(
            _full_settings(tmp_path, SECONDSIGN_APPROVER_ALLOWLIST="  ,  ")
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.missing_principal_allowlist

    def test_a_wildcard_entry_is_a_refusal(self, tmp_path) -> None:
        refusal = load_approver_config(
            _full_settings(tmp_path, SECONDSIGN_APPROVER_ALLOWLIST="spiffe://x/*")
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.wildcard_principal_entry

    def test_a_relative_entry_is_a_refusal(self, tmp_path) -> None:
        refusal = load_approver_config(
            _full_settings(tmp_path, SECONDSIGN_APPROVER_ALLOWLIST="not-a-uri")
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.malformed_principal_entry


def _ca_pem(common_name: str) -> bytes:
    """A real self-signed CA certificate in PEM, for the trust-anchor tests.

    The separation check parses these as certificates now (it compares DER, not
    file bytes), so a fake byte string will not do. `cryptography` is a dev/test
    dependency — never a runtime one — so this lives in the test, not in src.
    """
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestChannelSeparation:
    def _config_with_ca(self, tmp_path: Path, ca_pem: bytes) -> ApproverConfig:
        loaded = load_approver_config(
            _full_settings(
                tmp_path,
                SECONDSIGN_APPROVER_CA=str(_material(tmp_path, "sep-ca.pem", ca_pem)),
            )
        )
        assert isinstance(loaded, ApproverConfig)
        return loaded

    def test_distinct_anchors_and_populations_pass(self, tmp_path) -> None:
        agent_ca = _material(tmp_path, "agent-ca.pem", _ca_pem("agent CA"))
        config = self._config_with_ca(tmp_path, _ca_pem("approver CA"))
        assert (
            check_channel_separation(
                config, agent_client_ca=agent_ca, agent_allowlist=frozenset({AGENT})
            )
            is None
        )

    def test_one_certificate_behind_two_paths_is_one_anchor(self, tmp_path) -> None:
        """The same certificate on both sides, whatever the file bytes."""
        shared = _ca_pem("shared CA")
        agent_ca = _material(tmp_path, "agent-ca.pem", shared)
        config = self._config_with_ca(tmp_path, shared)
        refusal = check_channel_separation(
            config, agent_client_ca=agent_ca, agent_allowlist=frozenset({AGENT})
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.shared_trust_anchor

    def test_the_same_certificate_re_encoded_is_still_one_anchor(self, tmp_path) -> None:
        """A byte comparison would miss this: the same cert with different line
        endings and a comment header is byte-different but the same anchor."""
        cert = _ca_pem("re-encoded CA")
        agent_ca = _material(tmp_path, "agent-ca.pem", cert)
        reencoded = b"# a comment an operator added\r\n" + cert.replace(b"\n", b"\r\n")
        config = self._config_with_ca(tmp_path, reencoded)
        refusal = check_channel_separation(
            config, agent_client_ca=agent_ca, agent_allowlist=frozenset({AGENT})
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.shared_trust_anchor

    def test_a_bundle_containing_the_agent_ca_is_refused(self, tmp_path) -> None:
        """The B6 bypass byte comparison misses. `load_verify_locations` trusts
        every certificate in a file, so an approver CA file that is a bundle
        [approver-CA + agent-CA] makes the agent CA a valid approver issuer —
        byte-inequal, but sharing a trust anchor."""
        agent_pem = _ca_pem("agent CA")
        approver_pem = _ca_pem("approver CA")
        agent_ca = _material(tmp_path, "agent-ca.pem", agent_pem)
        bundle = self._config_with_ca(tmp_path, approver_pem + b"\n" + agent_pem)
        refusal = check_channel_separation(
            bundle, agent_client_ca=agent_ca, agent_allowlist=frozenset({AGENT})
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.shared_trust_anchor

    def test_a_truncated_certificate_block_shares_no_anchor(self, tmp_path) -> None:
        """A PEM with a BEGIN and no END parses to no certificate, so it shares
        no trust anchor — it cannot masquerade as one. (A file that is not a
        loadable CA is refused later, when the listener's context is built.)"""
        agent_ca = _material(tmp_path, "agent-ca.pem", _ca_pem("agent CA"))
        truncated = b"-----BEGIN CERTIFICATE-----\nabc123 no end marker\n"
        config = self._config_with_ca(tmp_path, truncated)
        assert (
            check_channel_separation(
                config, agent_client_ca=agent_ca, agent_allowlist=frozenset({AGENT})
            )
            is None
        )

    def test_a_principal_on_both_allowlists_is_refused(self, tmp_path) -> None:
        agent_ca = _material(tmp_path, "agent-ca.pem", _ca_pem("agent CA"))
        config = self._config_with_ca(tmp_path, _ca_pem("approver CA"))
        refusal = check_channel_separation(
            config, agent_client_ca=agent_ca, agent_allowlist=frozenset({CHECKER, AGENT})
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.principal_on_both_channels

    def test_a_plaintext_agent_channel_still_checks_the_population(self, tmp_path) -> None:
        """On loopback the agent channel has no CA; the disjointness rule does
        not go with it."""
        config = self._config_with_ca(tmp_path, _ca_pem("approver CA"))
        refusal = check_channel_separation(
            config, agent_client_ca=None, agent_allowlist=frozenset({CHECKER})
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.principal_on_both_channels

    def test_an_unreadable_anchor_cannot_pass_the_comparison(self, tmp_path) -> None:
        config = self._config_with_ca(tmp_path, _ca_pem("approver CA"))
        refusal = check_channel_separation(
            config,
            agent_client_ca=tmp_path / "vanished.pem",
            agent_allowlist=frozenset({AGENT}),
        )
        assert isinstance(refusal, ConfigurationRefusal)
        assert refusal.reason is StartupRefusalReason.unreadable_tls_material


class TestWhatACheckerIsShown:
    def test_the_display_is_a_projection_and_nothing_more(self, review_flow_service) -> None:
        """Every field shown is a field held, already redacted upstream."""
        service, request, now = review_flow_service
        outcome = service.authorize(AGENT, request, now=now)
        assert outcome.status.value == "awaiting_review"
        (review,) = service.open_reviews()

        shown = render_review(review)
        assert shown["approval_id"] == review.approval_id
        assert shown["proposal"] == review.approval.proposal.value
        assert shown["amount_minor"] == request.amount_minor
        assert shown["currency"] == request.currency.value
        assert shown["counterparty_ref"] == request.counterparty_ref
        assert shown["principal_ref"] == review.principal_ref
        assert shown["expires_at"] is not None
        assert set(shown) == {
            "approval_id",
            "proposal",
            "action",
            "rail",
            "amount_minor",
            "currency",
            "counterparty_ref",
            "principal_ref",
            "reasons",
            "expires_at",
        }


@pytest.fixture()
def review_flow_service():
    """An in-process service whose limit holds a review band, plus a proposal
    that lands in it. The same construction `tests/gateway/test_review_flow.py`
    uses, rebuilt here so this file states its own preconditions."""
    from secondsign.agent.surface import AuthorizationRequest
    from secondsign.audit import AuditLog, InMemoryAuditSink
    from secondsign.contracts import Currency
    from secondsign.controlplane.fingerprint import FingerprintKey
    from secondsign.controlplane.window import WindowLedger
    from secondsign.decision import DecisionEngine
    from secondsign.gateway.authorization import AuthorizationService
    from secondsign.gateway.execution import ExecutionGateway, InMemoryIdempotencyStore
    from secondsign.policy import AmountLimit, AmountWindowPolicy
    from secondsign.rails.http import HTTPRailExecutor

    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=500_00,
        review_above_minor=200_00,
    )
    service = AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(
            HTTPRailExecutor("http://rail.invalid:9", "k"), InMemoryIdempotencyStore()
        ),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
    )
    request = AuthorizationRequest.model_validate(
        {
            "action": "payment",
            "rail": "card",
            "currency": "USD",
            "amount_minor": 300_00,
            "reversibility": "irreversible",
            "counterparty_ref": "fp:" + "cd" * 32,
            "source_account_ref": "fp:" + "ef" * 32,
            "request_ref": "fp:" + "12" * 32,
        }
    )
    return service, request, datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


class TestAListenerThatLostItsTLS:
    def test_a_plaintext_connection_has_no_checker(self, review_flow_service) -> None:
        """`create_approver_server` always wraps the socket; this stands up the
        raw listener a later refactor might accidentally ship, and proves the
        handler still refuses rather than deriving nothing and serving anyway."""
        service, _, _ = review_flow_service
        raw = _ApproverHTTPServer(("127.0.0.1", 0), frozenset({CHECKER}), service)
        thread = threading.Thread(target=raw.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = raw.server_address[:2]
            for method, path in (("GET", "/reviews"), ("POST", "/reviews/anything")):
                connection = HTTPConnection(str(host), int(port), timeout=5)
                try:
                    connection.request(method, path)
                    response = connection.getresponse()
                    assert response.status == 403
                    assert b"no_identity" in response.read()
                finally:
                    connection.close()
        finally:
            raw.shutdown()
            raw.server_close()
            thread.join(timeout=5)


class TestTheProcessLifecycle:
    def test_a_partial_approver_channel_exits_2(self, capsys, tmp_path) -> None:
        exit_code = main(
            environ={
                "SECONDSIGN_BIND": "127.0.0.1:0",
                "SECONDSIGN_APPROVER_BIND": "127.0.0.1:0",
            }
        )
        captured = capsys.readouterr()
        assert exit_code == 2
        assert "incomplete_approver_channel" in captured.err

    def test_garbage_approver_material_exits_2(self, capsys, tmp_path) -> None:
        """A full approver configuration whose PEM does not parse refuses the
        whole process at bind time, never a gateway without its second door."""
        exit_code = main(
            environ={
                "SECONDSIGN_BIND": "127.0.0.1:0",
                **_full_settings(tmp_path),
            }
        )
        captured = capsys.readouterr()
        assert exit_code == 2
        assert "refusing to start" in captured.err
        assert "unreadable_tls_material" in captured.err

    def test_a_failed_separation_exits_2(self, capsys, monkeypatch, tmp_path) -> None:
        import secondsign.gateway.approver as approver_module

        stub_config = load_approver_config(_full_settings(tmp_path))
        monkeypatch.setattr(approver_module, "load_approver_config", lambda env: stub_config)
        monkeypatch.setattr(
            approver_module,
            "check_channel_separation",
            lambda *a, **k: ConfigurationRefusal(
                reason=StartupRefusalReason.principal_on_both_channels,
                detail="one principal, two doors",
            ),
        )
        exit_code = main(environ={"SECONDSIGN_BIND": "127.0.0.1:0"})
        captured = capsys.readouterr()
        assert exit_code == 2
        assert "principal_on_both_channels" in captured.err

    def test_serves_both_listeners_until_interrupted(self, capsys, monkeypatch, tmp_path) -> None:
        """The dual-listener path of `main`, minus real TLS: the approver
        server is stubbed at the module seam, the agent listener is real."""

        class _StubApprover:
            bound_address = ("127.0.0.1", 65_000)
            stopped = False

            def serve_forever(self) -> None:
                """Runs in the daemon thread `main` starts; returning is enough."""

            def shutdown(self) -> None:
                self.stopped = True

            def close(self) -> None:
                pass

        stub = _StubApprover()
        import secondsign.gateway.approver as approver_module

        stub_config = load_approver_config(_full_settings(tmp_path))
        monkeypatch.setattr(approver_module, "load_approver_config", lambda env: stub_config)
        monkeypatch.setattr(approver_module, "check_channel_separation", lambda *a, **k: None)
        monkeypatch.setattr(
            approver_module, "create_approver_server", lambda config, authorization: stub
        )

        def interrupted(self) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(server_module.GatewayServer, "serve_forever", interrupted)

        exit_code = main(environ={"SECONDSIGN_BIND": "127.0.0.1:0"})
        captured = capsys.readouterr()
        assert exit_code == 130
        assert "approver channel listening" in captured.out
        assert stub.stopped, "main did not shut the approver listener down"
