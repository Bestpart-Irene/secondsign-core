# Example: a third-party policy plugin

A complete, runnable policy plugin that lives **outside** `src/secondsign/` and
imports only the published surface (`secondsign.contracts`) — the shape a third
party's own package would take. It is certified the way every extension is: by
inheriting a conformance suite, not by persuading a maintainer. See
[`docs/EXTENSION_CONTRACTS.md`](../../docs/EXTENSION_CONTRACTS.md) for the
contract this example instantiates.

## What it decides

[`CounterpartyAllowlistPolicy`](counterparty_allowlist.py) pays only
counterparties you have listed. Given the redacted `PolicyView` of an action:

- counterparty fingerprint **on** the configured allow-list → `ABSTAIN`;
- counterparty fingerprint **not** on it → `DENY`, with a single
  `org_policy` finding.

The allow-list is the plugin's own configuration, passed at construction and held
in a private `frozenset`. Core knows nothing about it, and nothing in the
`PolicyView` carries it — a plugin's thresholds travel with the plugin.

## What it *cannot* do — the part worth studying

The value of this example is less what it does than what the contract forbids it
from doing:

- **It cannot grant permission.** `PluginVerdict` has no `ALLOW` member, on
  purpose. An allow-listed counterparty produces `ABSTAIN` — "I raise no
  concern" — never "approved". Permission is the *absence* of any concern across
  every installed plugin; that is a conclusion core draws, not a claim a single
  plugin can make. If your plugin wants to say "yes", the design is wrong, not
  the contract.
- **It never sees an identity.** `view.counterparty_ref` is a keyed fingerprint
  (`fp:` followed by 64 hex characters), never an account number, IBAN, or name.
  An allow-list of fingerprints is all the plugin needs — and all it *can* have,
  because a raw identifier is not representable on the boundary.
- **It writes no prose.** It emits a closed `ReasonCode`; core turns that code
  into the sentence a human reads. A plugin has no free-text field to echo an
  identifier into.
- **It cannot weaken another extension.** Combination is a maximum over
  strictness, so installing this plugin can only ever tighten a decision. The
  conformance suite proves it: this plugin beside an always-deny extension still
  denies.

## Certifying it

The entire integration is one subclass (in
[`test_conformance.py`](test_conformance.py)):

```python
from examples.policy_plugin.counterparty_allowlist import CounterpartyAllowlistPolicy
from secondsign.conformance import PolicyPluginConformance


class TestCounterpartyAllowlistConformance(PolicyPluginConformance):
    plugin = CounterpartyAllowlistPolicy(allowed_counterparties={"fp:" + "cd" * 32})
```

The inherited suite then exercises the plugin across a corpus of edge-case views
and checks the properties above. Because the corpus always presents the same
counterparty, the certified instance is configured *not* to allow it — so the
suite runs the deny path end to end; two unit tests cover the abstain branch.

## Run it

```bash
pip install -e ".[dev]"
pytest examples/policy_plugin/ -v
ruff check . && ruff format --check .
```

The conformance suite is also collected by the project's normal `pytest` run
(`examples/` is on `testpaths`), so this example cannot rot: a change to the
published surface that breaks it fails CI here, not in a stranger's fork.
