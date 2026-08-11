# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The runnable firewall demo (examples/onchain_firewall_demo.py).

The renderer is covered in the default gate from a canned payload; the full
end-to-end run (a real Safe on a local Anvil, the four scenarios) is an
`onchain_live` test that skips when the Foundry tooling is absent.
"""

import importlib.util
import shutil
from pathlib import Path

import pytest

_DEMO_PATH = Path(__file__).parents[2] / "examples" / "onchain_firewall_demo.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("onchain_firewall_demo", _DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_demo = _load_demo()


def test_render_html_reflects_the_outcomes():
    payload = {
        "safe": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        "usdc": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
        "agent": "0x7099",
        "secondsign": "0x3C44",
        "chain_id": 31337,
        "safe_version": "1.5.0",
        "threshold": 2,
        "safe_balance": 79_980_000,
        "cloudflare_balance": 20_000,
        "vendor_balance": 20_000_000,
        "scenarios": [
            {
                "title": "Pay Cloudflare 0.02 USDC",
                "detail": "small",
                "status": "signed",
                "reasons": [],
                "signed": True,
                "safe_before": 100_000_000,
                "safe_after": 99_980_000,
                "moved": True,
            },
            {
                "title": "Grant an attacker an unlimited allowance",
                "detail": "drain",
                "status": "refused",
                "reasons": ["unbounded_approval"],
                "signed": False,
                "safe_before": 99_980_000,
                "safe_after": 99_980_000,
                "moved": False,
            },
        ],
    }
    html = _demo.render_html(payload)
    assert "<!doctype html>" in html.lower()
    assert "Allow" in html and "Deny" in html
    assert "79.98" in html  # the Safe balance, formatted
    assert "no signature" in html and "second signature" in html
    assert "unbounded_approval" in html


def test_usdc_formatting():
    assert _demo._fmt_usdc(79_980_000) == "79.98"
    assert _demo._fmt_usdc(20_000) == "0.02"


@pytest.mark.onchain_live
def test_the_firewall_demo_runs_end_to_end():
    for tool in ("anvil", "forge", "cast"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not on PATH; the renderer is covered by the default-gate test")
    payload = _demo.run_demo()
    statuses = [s["status"] for s in payload["scenarios"]]
    assert statuses == ["signed", "held → signed", "refused", "refused"]
    # The two allowed transfers moved value; the two denials did not.
    assert payload["safe_balance"] == 100 * _demo._USDC - 20_000 - 20 * _demo._USDC
    assert payload["cloudflare_balance"] == 20_000
    assert payload["vendor_balance"] == 20 * _demo._USDC
    # The agent never obtained a signature for the deny cases.
    assert payload["scenarios"][2]["signed"] is False
    assert payload["scenarios"][3]["signed"] is False
