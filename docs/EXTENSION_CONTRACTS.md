# Extension contracts

SecondSign Core is meant to be extended — new rails, new policy sources, new
approval channels, new audit destinations — **without the security boundary
being re-argued each time.**

That is what the conformance kits are for. You prove your extension is safe by
inheriting a test suite, not by persuading a reviewer.

## How to write a policy plugin

A plugin looks at a redacted view of an action and either raises a concern or
stays quiet.

```python
from secondsign.contracts import (
    CONTRACT_VERSION, PluginJudgement, PluginVerdict, PolicyView,
    ReasonCode, RiskBand,
)


class BlockProhibitedCounterparties:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        if view.counterparty_risk_band is RiskBand.prohibited:
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                reasons=(ReasonCode.counterparty_risk,),
                explanation="Counterparty risk band is prohibited by policy.",
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)
```

Then certify it:

```python
from secondsign.conformance import PolicyPluginConformance


class TestBlockProhibitedCounterparties(PolicyPluginConformance):
    plugin = BlockProhibitedCounterparties()
```

Run your own test suite. That subclass is the entire integration.

## What the suite checks

| Check | Why |
|---|---|
| Declares the supported contract version | A plugin speaking an unknown dialect is never consulted (INV-1) |
| Never trips the runner's failure paths | A crash, a bad return or a version mismatch is a denial, not an answer |
| Never claims approval | INV-6 — there is no vocabulary for it |
| Does not mutate the view | Judging must not change what the next layer sees |
| Is deterministic | INV-13 — same input, same output, same reason ordering |
| Has no side effects across views | State between evaluations makes decisions depend on traffic order |
| Does not echo identifiers it was shown | INV-5 — a fingerprint in an explanation ends up in a receipt |
| Every concern is actionable | A verdict nobody can act on is not a concern |
| Cannot weaken another extension | INV-2 |
| Registration order does not change the outcome | Two operators with the same plugins get the same answer |
| A failing neighbour does not suppress it | One broken extension must not silence a healthy one |

The suite runs your plugin across a corpus of edge-case views — value extremes,
unsettled value bands, every risk band, trust level, action class, rail class,
market session and currency.

## Rules that are not negotiable

**You cannot approve anything.** `PluginVerdict` has `ABSTAIN`, `REVIEW` and
`DENY`. There is no `ALLOW`, so "my plugin cleared this payment" is not an
expressible statement. Extensions raise concerns; permission comes from core
policy alone.

**You get facts, not policy.** `PolicyView` carries what the action *is*. Your
thresholds are your own configuration, passed to your constructor. If you find
yourself wanting a limit in the view, that limit belongs in core policy.

**You get no raw data, and no way to ask for it.** Counterparties and accounts
appear only as keyed fingerprints. There is no metadata mapping, no free-form
field, and no escape hatch — by design (threat A5). If your rule genuinely
needs a fact the view does not carry, that is a core change: open an issue
proposing a new *derived, redacted* dimension, and expect to justify it against
the threat model.

**Failure denies.** If your plugin raises, returns a non-judgement, or declares
an unknown contract version, the action is denied — see
[`INVARIANTS.md`](INVARIANTS.md) for why that is DENY rather than an
escalation. Availability is your responsibility: a plugin that reaches an
external service must have its own timeout and its own answer for that service
being down.

## Available and forthcoming

| Extension point | Suite | Status |
|---|---|---|
| Policy plugin | `PolicyPluginConformance` | Available |
| Rail adapter | `RailAdapterConformance` | Slice `CORE-S008` |
| Approval provider | `ApprovalProviderConformance` | Slice `CORE-S011` |
| Compliance provider | `ComplianceProviderConformance` | Slice `CORE-S012` |
| Audit sink | `AuditSinkConformance` | Slice `CORE-S013` |

Forthcoming suites are not stubbed. Shipping an empty conformance class would
imply a guarantee that is not being made.

## Contract versioning

`CONTRACT_VERSION` is a single integer. It changes when a field, a verdict, or
an enum member is added or removed. A plugin declaring any other version is not
consulted at all — even a well-formed `DENY` from it is discarded, because a
plugin speaking a different dialect may mean something different by it.

Once a contract is frozen (slice `CORE-S005` for policy plugins), the
compatibility policy in this repository governs what may change within a
version.
