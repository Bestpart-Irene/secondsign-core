# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A worked third-party policy plugin: a counterparty allow-list.

This is an *example*. It lives outside ``src/secondsign/`` and imports only the
published surface (:mod:`secondsign.contracts`), exactly as a third party's own
package would — nothing here reaches into a core internal. It is certified by the
conformance suite in ``test_conformance.py``; that subclass is the whole
integration.

The rule is deliberately dull: pay only counterparties you have listed. What is
worth studying is not the logic but the *shape* — what a plugin can and cannot
say:

- **It cannot grant permission.** :class:`~secondsign.contracts.PluginVerdict`
  has no ``ALLOW`` member. An allow-listed counterparty yields ``ABSTAIN`` — "I
  have no concern" — never "approved". Permission is the *absence* of a concern
  across every plugin, a conclusion core draws, not one a plugin can assert.
- **It cannot see an identity.** The plugin is handed a
  :class:`~secondsign.contracts.PolicyView` whose ``counterparty_ref`` is a keyed
  fingerprint (``fp:<64 hex>``), never an account number or a name. An allow-list
  of fingerprints is all it needs, and all it *can* have.
- **It cannot write prose.** It reports a closed
  :class:`~secondsign.contracts.ReasonCode`; core renders the sentence a human
  reads (:func:`secondsign.contracts.render`), so no plugin can put free text on
  the decision path.
"""

from collections.abc import Iterable

from secondsign.contracts import (
    CONTRACT_VERSION,
    Finding,
    PluginJudgement,
    PluginVerdict,
    PolicyView,
    ReasonCode,
)


class CounterpartyAllowlistPolicy:
    """Denies any counterparty whose fingerprint is not on a configured list.

    The allow-list is the plugin's *own* configuration — held privately and
    immutably, not something core knows about. Nothing in the
    :class:`~secondsign.contracts.PolicyView` carries it: a plugin's thresholds
    travel with the plugin, and the view carries only the facts of the action.
    """

    #: The contract version this plugin speaks. A plugin declaring anything else
    #: is refused rather than consulted (INV-1), so this is pinned to the
    #: published constant, never hard-coded to a literal that could drift.
    contract_version: int = CONTRACT_VERSION

    def __init__(self, allowed_counterparties: Iterable[str]) -> None:
        # Copied into a frozenset: the caller cannot mutate the list out from
        # under a running gate, and membership is O(1) on each evaluation.
        self._allowed: frozenset[str] = frozenset(allowed_counterparties)

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        if view.counterparty_ref in self._allowed:
            # No concern raised. This is not approval — see the module docstring.
            return PluginJudgement(verdict=PluginVerdict.ABSTAIN)
        return PluginJudgement(
            verdict=PluginVerdict.DENY,
            findings=(Finding(code=ReasonCode.org_policy),),
        )
