# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suites — how an extension proves it is safe to install.

Inherit the suite for the extension point you implement, name your subclass
``Test...``, and run your own test suite. Passing is what "compatible with
SecondSign" means; it is mechanical on purpose, so nobody has to re-argue the
security principles in review each time a rail or a rule is added.

Available today:

- :class:`PolicyPluginConformance`

Forthcoming, tracked in ``docs/slices/roadmap.yaml``: rail adapters
(``CORE-S008``), approval providers (``CORE-S011``), audit sinks
(``CORE-S013``), compliance providers (``CORE-S012``). Those contracts do not
exist yet, and shipping an empty suite would imply a guarantee that is not
being made.
"""

from secondsign.conformance.policy_plugin import PolicyPluginConformance, conformance_corpus

__all__ = ["PolicyPluginConformance", "conformance_corpus"]
