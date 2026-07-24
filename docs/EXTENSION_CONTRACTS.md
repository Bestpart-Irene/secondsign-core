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
    CONTRACT_VERSION, Finding, PluginJudgement, PluginVerdict, PolicyView,
    ReasonCode, RiskBand,
)


class BlockProhibitedCounterparties:
    contract_version = CONTRACT_VERSION

    def evaluate(self, view: PolicyView) -> PluginJudgement:
        if view.counterparty_risk_band is RiskBand.prohibited:
            return PluginJudgement(
                verdict=PluginVerdict.DENY,
                findings=(Finding(code=ReasonCode.counterparty_risk),),
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
| Findings stay within the closed vocabulary | INV-5 — quantities are bounded below identifier magnitude, and verified on emission because `model_construct` bypasses validation |
| Every concern is actionable | A verdict nobody can act on is not a concern |
| Registration order gives byte-identical records | INV-13 — reconciling two operators' audit trails must not be manual |
| Cannot weaken another extension | INV-2 |
| Registration order does not change the outcome | Two operators with the same plugins get the same answer |
| A failing neighbour does not suppress it | One broken extension must not silence a healthy one |

The suite runs your plugin across a corpus of edge-case views — value extremes,
unsettled value bands, every risk band, trust level, action class, rail class,
market session and currency.

## Rules that are not negotiable

**You do not write prose.** A finding is a `ReasonCode` plus optional bounded
quantities; core writes the sentence. A bounded, screened text field was tried
and removed — an author who wants to pass a customer name through will
eventually phrase it within the limit. Quantities are capped below the
magnitude of a 13-digit account number, so a number cannot carry an identifier
either. If a condition you need has no reason code, propose one.

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
compatibility policy below governs what may change within a version.

## Compatibility policy

Policy Plugin API **v1** (`CONTRACT_VERSION = 1`) is frozen. Its surface — every
symbol exported from `secondsign.contracts`, every member of every published
enum, and every field of `PolicyView`, `Finding`, and `PluginJudgement` — is
held by [`tests/architecture/test_contract_surface_ratchet.py`](../tests/architecture/test_contract_surface_ratchet.py).
That test is the policy, not a description of it: a change to the surface cannot
merge without changing the test in the same pull request, which makes the change
deliberate and reviewable rather than incidental.

Within a frozen version:

- **Nothing structural changes.** No published symbol, enum member, or model
  field is added, removed, renamed, or retyped. Adding even a new enum member is
  a version change, because a plugin certified against v1 has never seen it and a
  v1 record that now contains it is no longer what v1 promised.
- **Behaviour is not quietly re-specified.** A field keeps its meaning, its
  bounds, and its ordering. Widening what a field accepts is a surface change in
  everything but name.
- **Documentation and internal implementation may change freely**, as long as
  the ratchet and the conformance suite stay green — those are what an extension
  author actually depends on.

Changing the surface means **incrementing `CONTRACT_VERSION`**. A plugin
declaring the old version is then refused rather than consulted (INV-1): a
version it no longer serves is treated as an unknown dialect, which denies,
rather than being run against a surface that shifted underneath it. A removed or
changed symbol is carried through at least one version as a deprecation before
the version that drops it, so an author has a release in which both the old and
the new surface are described.

This policy is itself part of the frozen contract: it changes only through an
ADR, per [`INVARIANTS.md`](INVARIANTS.md) (INV-15).
