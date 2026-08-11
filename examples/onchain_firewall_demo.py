#!/usr/bin/env python
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A runnable, local end-to-end demo of the SecondSign AI-wallet firewall.

It deploys a real Safe 1.5.0 and a proxied mock USDC on a local Anvil, wires the
merged co-signer (``LocalSigner`` + the live ``CastChainStateReader``), and runs
four agent proposals through it:

1. a small in-policy transfer — ALLOW, co-signed, and executed 2-of-2 so USDC moves;
2. a large transfer — REVIEW, held for a human, approved, then executed;
3. an unlimited ``approve`` to an un-vouched spender — DENY, no signature;
4. an attempt to remove SecondSign (``setGuard(0)``) — DENY, no signature.

Every verdict, signature and balance change is produced by the actual co-signer,
not mocked — only the ERC-20 token is a local stand-in. It needs the Foundry
tools (``anvil``/``forge``/``cast``) on PATH; keys come from Anvil's own
``--config-out`` at runtime, so no key or mnemonic is written anywhere.

    python examples/onchain_firewall_demo.py --out /tmp/ss-demo
    # writes result.json and firewall_demo.html into that directory

This is a demonstration, not a production deployment: the on-chain production
guard (ONCHAIN-S005), a KMS-held signing key, and a real Base run are still ahead.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

_REPO = pathlib.Path(__file__).resolve().parents[1]
_ONCHAIN = _REPO / "onchain"
_SAFE_PKG = "node_modules/@safe-global/safe-smart-account/contracts"
_ZERO = "0x" + "00" * 20
_USDC = 1_000_000  # one USDC in minor units (6 decimals)
_APPROVAL_CAP = 50 * _USDC
_REVIEW_ABOVE = 5 * _USDC
_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_TOOLS = ("anvil", "forge", "cast")

# Demo counterparties (addresses are arbitrary; nothing is vouched for the deny cases).
_CLOUDFLARE = "0xC10011f1e700000000000000000000000000C101"
_NEW_VENDOR = "0xdEEd00000000000000000000000000000000bEEf"
_ATTACKER = "0xA77Ac0000000000000000000000000000000dEaD"

_from_secondsign = _REPO / "src"
if str(_from_secondsign) not in sys.path:
    sys.path.insert(0, str(_from_secondsign))

from secondsign.approval import CheckerIdentity, CheckerVerdict  # noqa: E402
from secondsign.gateway.onchain_cosigner import (  # noqa: E402
    OnchainCosigner,
    SafeContext,
    safe_transaction_hash,
)
from secondsign.gateway.signer import LocalSigner  # noqa: E402
from secondsign.intent import ProposalDigest  # noqa: E402
from secondsign.onchain.chain_state import ExpectedSafeConfig  # noqa: E402
from secondsign.onchain.effect import SafeCall, SafeOperation  # noqa: E402

_reader_spec = importlib.util.spec_from_file_location(
    "chain_reader", _REPO / "deploy" / "reference" / "chain_reader.py"
)
_reader_mod = importlib.util.module_from_spec(_reader_spec)
_reader_spec.loader.exec_module(_reader_mod)
CastChainStateReader = _reader_mod.CastChainStateReader


class _Chain:
    """A local Anvil with a resolved toolchain; keys read from its config-out."""

    def __init__(self) -> None:
        self.tools = {t: shutil.which(t) for t in _TOOLS}
        missing = [t for t, p in self.tools.items() if p is None]
        if missing:
            raise RuntimeError(f"missing Foundry tools on PATH: {', '.join(missing)}")
        self.port = _free_port()
        self.rpc = f"http://127.0.0.1:{self.port}"
        self._config = pathlib.Path(tempfile.gettempdir()) / f"ss-anvil-{self.port}.json"
        self._proc = subprocess.Popen(  # noqa: S603 — resolved anvil binary, fixed args
            [
                self.tools["anvil"],
                "--port",
                str(self.port),
                "--silent",
                "--config-out",
                str(self._config),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait()
        data = json.loads(self._config.read_text())
        self.accounts = data["available_accounts"]
        self.keys = data["private_keys"]

    def _wait(self, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            probe = subprocess.run(  # noqa: S603 — resolved cast binary, fixed args
                [self.tools["cast"], "chain-id", "--rpc-url", self.rpc],
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0 and self._config.exists():
                return
            time.sleep(0.2)
        raise RuntimeError("anvil did not become reachable")

    def cast(self, *args: str) -> str:
        return subprocess.run(  # noqa: S603 — resolved cast binary, fixed args
            [self.tools["cast"], *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    def send(self, *args: str) -> None:
        # The deployer (account 0) is unlocked by Anvil; no key needed to submit.
        self.cast("send", *args, "--rpc-url", self.rpc, "--from", self.accounts[0], "--unlocked")

    def forge_create(self, contract: str, *ctor: str) -> str:
        cmd = [
            self.tools["forge"],
            "create",
            contract,
            "--rpc-url",
            self.rpc,
            "--from",
            self.accounts[0],
            "--unlocked",
            "--broadcast",
        ]
        if ctor:
            cmd += ["--constructor-args", *ctor]
        out = subprocess.run(  # noqa: S603 — resolved forge binary, fixed args
            cmd, cwd=_ONCHAIN, capture_output=True, text=True, check=True
        ).stdout
        for line in out.splitlines():
            if line.startswith("Deployed to:"):
                return line.split()[-1]
        raise RuntimeError(f"no deployment address:\n{out}")

    def sign(self, key: str, tx_hash: str) -> str:
        return self.cast("wallet", "sign", "--no-hash", tx_hash, "--private-key", key)

    def usdc(self, token: str, who: str) -> int:
        out = self.cast("call", token, "balanceOf(address)(uint256)", who, "--rpc-url", self.rpc)
        return int(out.split()[0])

    def close(self) -> None:
        self._proc.terminate()
        self._proc.wait(timeout=10)
        self._config.unlink(missing_ok=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _execute_2of2(
    chain: _Chain,
    safe: str,
    context: SafeContext,
    call: SafeCall,
    agent_key: str,
    agent_addr: str,
    ss_addr: str,
    cosigner_sig: str,
) -> None:
    """The agent co-signs the same hash; combine 2-of-2 (sorted by owner) and execute."""
    nonce = chain.cast("call", safe, "nonce()(uint256)", "--rpc-url", chain.rpc)
    tx_hash = "0x" + safe_transaction_hash(call, context, int(nonce)).hex()
    agent_sig = chain.sign(agent_key, tx_hash)
    pairs = sorted([(agent_addr.lower(), agent_sig), (ss_addr.lower(), cosigner_sig)])
    signatures = "0x" + "".join(sig.removeprefix("0x") for _, sig in pairs)
    op = "0" if call.operation is SafeOperation.call else "1"
    chain.send(
        safe,
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        call.to,
        str(call.value),
        call.data,
        op,
        "0",
        "0",
        "0",
        _ZERO,
        _ZERO,
        signatures,
    )


def run_demo() -> dict:
    """Run the four-scenario firewall demo on a fresh local Anvil; return the outcomes."""
    chain = _Chain()
    try:
        agent, secondsign = chain.accounts[1], chain.accounts[2]
        agent_key, ss_key = chain.keys[1], chain.keys[2]

        singleton = chain.forge_create(f"{_SAFE_PKG}/Safe.sol:Safe")
        safe = chain.forge_create(f"{_SAFE_PKG}/proxies/SafeProxy.sol:SafeProxy", singleton)
        chain.send(
            safe,
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            f"[{agent},{secondsign}]",
            "2",
            _ZERO,
            "0x",
            _ZERO,
            _ZERO,
            "0",
            _ZERO,
        )
        impl = chain.forge_create("demo/MockUSDC.sol:MockUSDC")
        usdc = chain.forge_create("demo/DemoProxy.sol:DemoProxy", impl)
        chain.send(usdc, "mint(address,uint256)", safe, str(100 * _USDC))

        reader = CastChainStateReader(chain.rpc, cast_bin=chain.tools["cast"])
        state = reader.read_safe(safe)
        context = SafeContext(safe_address=safe, chain_id=state.chain_id)
        expected = ExpectedSafeConfig(
            chain_id=state.chain_id,
            safe_version=state.safe_version,
            owners=frozenset(o.lower() for o in state.owners),
            threshold=state.threshold,
            transaction_guard=state.transaction_guard,
            module_guard=state.module_guard,
            token=usdc,
            token_identity=reader.token_identity(usdc),
        )
        cosigner = OnchainCosigner(
            LocalSigner(bytes.fromhex(ss_key.removeprefix("0x"))),
            context,
            approval_cap=_APPROVAL_CAP,
            reader=reader,
            expected=expected,
            review_above=_REVIEW_ABOVE,
            approve_spender_allowlist=frozenset(),
        )

        def transfer(to: str, amount: int) -> SafeCall:
            data = chain.cast("calldata", "transfer(address,uint256)", to, str(amount))
            return SafeCall(to=usdc, value=0, data=data, operation=SafeOperation.call)

        scenarios = []

        # 1. Small in-policy transfer → ALLOW → executed.
        call = transfer(_CLOUDFLARE, 20_000)
        before = chain.usdc(usdc, safe)
        out = cosigner.cosign(call, proposer=agent, now=_NOW)
        if out.status.value == "signed":
            _execute_2of2(chain, safe, context, call, agent_key, agent, secondsign, out.signature)
        scenarios.append(
            _record(
                "Pay Cloudflare 0.02 USDC",
                "under the 5 USDC auto-approve limit",
                out.status.value,
                out,
                before,
                chain.usdc(usdc, safe),
            )
        )

        # 2. Large transfer → REVIEW → human approves → executed.
        call = transfer(_NEW_VENDOR, 20 * _USDC)
        before = chain.usdc(usdc, safe)
        held = cosigner.cosign(call, proposer=agent, now=_NOW)
        approved = cosigner.resolve(held.approval_id, _human_approval(held.approval_id), now=_NOW)
        if approved.status.value == "signed":
            _execute_2of2(
                chain, safe, context, call, agent_key, agent, secondsign, approved.signature
            )
        scenarios.append(
            _record(
                "Pay a new vendor 20 USDC",
                "over the auto-limit — held for a human, then approved",
                f"{held.status.value} → {approved.status.value}",
                approved,
                before,
                chain.usdc(usdc, safe),
                held_judgement=held.judgement,
            )
        )

        # 3. Unlimited approve to an un-vouched spender → DENY.
        data = chain.cast("calldata", "approve(address,uint256)", _ATTACKER, str(2**256 - 1))
        call = SafeCall(to=usdc, value=0, data=data, operation=SafeOperation.call)
        bal = chain.usdc(usdc, safe)
        out = cosigner.cosign(call, proposer=agent, now=_NOW)
        scenarios.append(
            _record(
                "Grant an attacker an unlimited allowance",
                "the classic drain — no money now, everything later",
                out.status.value,
                out,
                bal,
                bal,
            )
        )

        # 4. Remove SecondSign → DENY.
        data = chain.cast("calldata", "setGuard(address)", _ZERO)
        call = SafeCall(to=safe, value=0, data=data, operation=SafeOperation.call)
        bal = chain.usdc(usdc, safe)
        out = cosigner.cosign(call, proposer=agent, now=_NOW)
        scenarios.append(
            _record(
                "Remove SecondSign (setGuard(0))",
                "reconfigures the account so the second signature is not needed",
                out.status.value,
                out,
                bal,
                bal,
            )
        )

        return {
            "safe": safe,
            "usdc": usdc,
            "usdc_impl": impl,
            "agent": agent,
            "secondsign": secondsign,
            "chain_id": state.chain_id,
            "safe_version": state.safe_version,
            "threshold": state.threshold,
            "safe_balance": chain.usdc(usdc, safe),
            "cloudflare_balance": chain.usdc(usdc, _CLOUDFLARE),
            "vendor_balance": chain.usdc(usdc, _NEW_VENDOR),
            "scenarios": scenarios,
        }
    finally:
        chain.close()


def _human_approval(approval_id: str) -> CheckerVerdict:
    return CheckerVerdict(
        checker=CheckerIdentity(subject="ops-human"),
        approval_id=approval_id,
        proposal=ProposalDigest(value=approval_id),
        approved=True,
    )


def _record(title, detail, status, outcome, before, after, held_judgement=None):
    judgement = held_judgement or outcome.judgement
    return {
        "title": title,
        "detail": detail,
        "status": status,
        "reasons": [r.value for r in (judgement.reasons if judgement else ())],
        "signed": bool(outcome.signature),
        "safe_before": before,
        "safe_after": after,
        "moved": before != after,
    }


def _fmt_usdc(minor: int) -> str:
    return f"{minor / _USDC:,.2f}"


def render_html(payload: dict) -> str:
    """Render the demo outcomes to a single self-contained HTML page."""
    rows = []
    for s in payload["scenarios"]:
        verdict = s["status"].split()[-1]  # 'signed' / 'refused' / after '→'
        held = "held" in s["status"]
        klass = "allow" if verdict == "signed" and not held else ("review" if held else "deny")
        pill = {"allow": "Allow", "review": "Review → approved", "deny": "Deny"}[klass]
        sig = (
            "<span class='chip yes'><b>✓</b> second signature</span>"
            if s["signed"]
            else "<span class='chip no'><b>✕</b> no signature</span>"
        )
        delta = (
            f"Safe {_fmt_usdc(s['safe_before'])} → {_fmt_usdc(s['safe_after'])} USDC"
            if s["moved"]
            else "balance unchanged"
        )
        reason = ", ".join(s["reasons"]) or "no concern raised"
        rows.append(f"""
    <div class="scn {klass}"><div class="stripe"></div>
      <div class="body">
        <p class="propose">{s["title"]}</p>
        <p class="detail">{s["detail"]}</p>
        <span class="why">{reason}</span>
      </div>
      <div class="verdict">
        <span class="pill">{pill}</span>{sig}
        <span class="delta {"moved" if s["moved"] else "still"}">{delta}</span>
      </div>
    </div>""")
    return _PAGE.format(
        safe_balance=_fmt_usdc(payload["safe_balance"]),
        safe=payload["safe"],
        usdc=payload["usdc"],
        agent=payload["agent"],
        secondsign=payload["secondsign"],
        chain_id=payload["chain_id"],
        version=payload["safe_version"],
        rows="".join(rows),
    )


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecondSign — AI Wallet Firewall (local demo)</title>
<style>
:root{{--bg:#eef1f2;--surface:#fff;--surface2:#f6f8f8;--ink:#131a1d;--muted:#566268;--faint:#8b979c;
--hairline:#d9e0e2;--brand:#1c5b78;--allow:#1c8a52;--allow-t:#e6f3ec;--review:#a9760a;--review-t:#f6eed9;
--deny:#b03a30;--deny-t:#f6e5e3;--mono:ui-monospace,"SF Mono",Menlo,monospace;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#0d1215;--surface:#141c20;
--surface2:#101619;--ink:#e6edee;--muted:#94a1a7;--faint:#6c7a80;--hairline:#26312f;--brand:#59b3d6;
--allow:#45c184;--allow-t:#123024;--review:#e0a844;--review-t:#2e2513;--deny:#e0736a;--deny-t:#331d1b;}}}}
:root[data-theme=dark]{{--bg:#0d1215;--surface:#141c20;--surface2:#101619;--ink:#e6edee;--muted:#94a1a7;
--faint:#6c7a80;--hairline:#26312f;--brand:#59b3d6;--allow:#45c184;--allow-t:#123024;--review:#e0a844;
--review-t:#2e2513;--deny:#e0736a;--deny-t:#331d1b;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55}}
.wrap{{max-width:820px;margin:0 auto;padding:clamp(24px,5vw,52px) 20px 64px}}
.eyebrow{{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--brand);margin:0 0 10px}}
h1{{font-size:clamp(26px,5vw,36px);line-height:1.1;margin:0 0 14px;letter-spacing:-.02em;text-wrap:balance}}
.thesis{{font-size:clamp(15px,2.4vw,18px);color:var(--muted);margin:0;max-width:62ch}}
.thesis b{{color:var(--ink)}}
.card{{background:var(--surface);border:1px solid var(--hairline);border-radius:14px;margin-top:26px;overflow:hidden;
box-shadow:0 1px 2px rgba(0,0,0,.05),0 8px 24px rgba(0,0,0,.04)}}
.head{{display:flex;justify-content:space-between;align-items:baseline;gap:12px;padding:15px 20px;
border-bottom:1px solid var(--hairline);background:var(--surface2)}}
.head h2{{font-size:13px;margin:0;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}}
.bal{{font-family:var(--mono);font-size:14px;color:var(--muted)}} .bal b{{color:var(--ink)}}
.wallet{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px;background:var(--hairline)}}
.cell{{background:var(--surface);padding:13px 20px}}
.cell .k{{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--faint)}}
.cell .v{{font-family:var(--mono);font-size:14px;margin-top:4px;word-break:break-all}}
.cell .v.big{{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}}
.scn{{border-top:1px solid var(--hairline);display:grid;grid-template-columns:4px 1fr auto}}
.scn:first-of-type{{border-top:none}}.stripe{{width:4px}}
.scn.allow .stripe{{background:var(--allow)}}.scn.review .stripe{{background:var(--review)}}.scn.deny .stripe{{background:var(--deny)}}
.body{{padding:17px 20px;min-width:0}}.propose{{font-size:16px;font-weight:600;margin:0 0 4px}}
.detail{{color:var(--muted);font-size:14px;margin:0 0 11px}}
.why{{font-family:var(--mono);font-size:12.5px;color:var(--muted);background:var(--surface2);
border:1px solid var(--hairline);border-radius:8px;padding:7px 11px;display:inline-block}}
.verdict{{padding:17px 20px 17px 8px;display:flex;flex-direction:column;align-items:flex-end;gap:8px;text-align:right;white-space:nowrap}}
.pill{{font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:.05em;padding:5px 11px;border-radius:999px;text-transform:uppercase}}
.allow .pill{{background:var(--allow-t);color:var(--allow)}}.review .pill{{background:var(--review-t);color:var(--review)}}.deny .pill{{background:var(--deny-t);color:var(--deny)}}
.chip{{font-family:var(--mono);font-size:11.5px;color:var(--muted)}}.chip.yes b{{color:var(--allow)}}.chip.no b{{color:var(--deny)}}
.delta{{font-family:var(--mono);font-size:12.5px;font-variant-numeric:tabular-nums}}.delta.still{{color:var(--faint)}}
footer{{margin-top:26px;color:var(--faint);font-size:12.5px;font-family:var(--mono)}}
footer .caveat{{margin-top:10px;color:var(--muted);font-family:var(--sans);font-size:13px;max-width:66ch}}
@media (max-width:560px){{.scn{{grid-template-columns:4px 1fr}}.verdict{{grid-column:2;align-items:flex-start;text-align:left;padding:0 20px 17px}}}}
</style></head><body><div class="wrap">
<p class="eyebrow">SecondSign · live local run</p>
<h1>An AI-agent wallet with a financial supervisor it can't remove</h1>
<p class="thesis">The agent can <b>propose</b> spending, but cannot move money on its own. SecondSign checks each transaction and provides the <b>second signature</b> only when it passes — so an unlimited approval, an unknown call, or an attempt to disarm the firewall never gets signed, and the money doesn't move.</p>
<div class="card"><div class="head"><h2>The wallet</h2><span class="bal">Safe balance <b>{safe_balance}</b> USDC</span></div>
<div class="wallet">
<div class="cell"><div class="k">USDC in the Safe</div><div class="v big">{safe_balance}</div></div>
<div class="cell"><div class="k">Owners · threshold</div><div class="v">Agent + SecondSign · 2 of 2</div></div>
<div class="cell"><div class="k">Safe · chain</div><div class="v">v{version} · local Anvil ({chain_id})</div></div>
<div class="cell"><div class="k">Pinned token (USDC proxy)</div><div class="v">{usdc}</div></div>
</div></div>
<div class="card"><div class="head"><h2>What the agent tried</h2><span class="bal">4 proposals</span></div>{rows}
</div>
<footer>real Safe 1.5.0 on local Anvil · real 2-of-2 execution · agent {agent} · SecondSign {secondsign}
<p class="caveat">Every verdict, signature and balance change is produced by the actual co-signer, not mocked (only the ERC-20 is a local stand-in). A demonstration, not a production deployment: the on-chain production guard, a KMS-held key, and a Base run are still ahead.</p></footer>
</div></body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default=".", help="directory for result.json and firewall_demo.html"
    )
    args = parser.parse_args()
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = run_demo()
    (out_dir / "result.json").write_text(json.dumps(payload, indent=2))
    (out_dir / "firewall_demo.html").write_text(render_html(payload))
    for s in payload["scenarios"]:
        print(f"  {s['status']:>16}  {s['title']}")
    print(f"\nSafe USDC balance: {_fmt_usdc(payload['safe_balance'])}")
    print(f"wrote {out_dir / 'result.json'} and {out_dir / 'firewall_demo.html'}")


if __name__ == "__main__":
    main()
