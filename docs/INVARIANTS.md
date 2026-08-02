# Architecture invariants

These are the properties SecondSign Core guarantees. They are not style
preferences and they are not decided per pull request: a change that weakens
one is rejected regardless of how useful the feature is.

**Every invariant is enforced by a test, not by review discipline.** The
enforcement column names the test that fails if the invariant is broken. Where
an invariant covers a component that does not exist yet, the enforcing slice is
named instead — those are commitments, and they are tracked in
[`slices/roadmap.yaml`](slices/roadmap.yaml).

Threat references point at [`THREAT_MODEL.md`](THREAT_MODEL.md).

| # | Invariant | Threat | Enforcement |
|---|---|---|---|
| INV-1 | **Uncertainty denies.** Errors, unknown contract versions, invalid returns, missing context and unavailable dependencies all take the strictest path. Nothing proceeds because a check could not be completed. | A4, A9 | `tests/contracts/test_fail_closed.py` |
| INV-2 | **Extensions may only tighten.** Combination is a maximum over strictness. No code path returns a verdict weaker than any of its inputs. | A9 | `tests/contracts/test_combine_laws.py`, `tests/contracts/test_no_downgrade.py` |
| INV-3 | **No free-form data on a boundary.** No published model may carry a mapping, `Any`, `object`, or free-text field. Unknown keys are rejected. Extensions report closed vocabulary plus bounded quantities; core writes any human-readable text. | A5 | `tests/architecture/test_invariants.py`, `tests/contracts/test_structured_findings.py` |
| INV-4 | **Boundary objects are deeply immutable.** Frozen, with immutable containers — shallow freezing is not enough, because an appendable collection lets a caller rewrite the record after the fact. | A5, B1 | `tests/architecture/test_invariants.py`, `tests/contracts/test_immutability.py` |
| INV-5 | **Raw financial and personal data is unrepresentable.** Identifiers appear only as keyed fingerprints. Money is integer minor units. Field names implying a raw value are rejected. | A1, A5 | `tests/architecture/test_invariants.py` |
| INV-6 | **Extensions cannot grant permission.** There is no vocabulary for approval in any extension contract — "the plugin cleared this" is not an expressible statement. | A9 | `tests/contracts/test_no_downgrade.py` |
| INV-7 | **Core never imports enterprise, and contracts import nothing.** The extension surface is a leaf module, so an extension gains no reach into internals. | A2 | `lint-imports` (see `pyproject.toml`) |
| INV-8 | **A rail adapter cannot change the decision layer.** Adding a rail is a new closed payload variant and a new adapter. If it requires touching decision code, the abstraction is wrong. | A6 | `lint-imports`; falsified by slice `CORE-S015` |
| INV-9 | **Decided value equals executed value.** The gateway accepts only the decision-carried intent and re-verifies its digest immediately before dispatch. | B1 | `tests/gateway/test_gateway.py` |
| INV-10 | **Approvals are one-shot, expiring, proposal-bound.** An approval binds to the *proposal digest* — every material field of the intent except its validity window (ADR 0005) — and execution stays bound to the intent digest, so what a human approved and what was dispatched are both checkable by comparison. Never bound to an agent, a session, or an action type. A missing expiry is treated as expired, not as permanent. | B2, B3, B5 | `tests/approval/test_maker_checker.py`, `tests/intent/test_proposal_digest.py`, `tests/gateway/test_review_flow.py` |
| INV-11 | **Audit failure blocks execution.** A receipt that cannot be written is a fail-closed event, not a dropped side effect. Every non-ALLOW path produces a receipt, including error and degraded paths. | A7 | `tests/audit/test_audit_log.py` |
| INV-12 | **The control plane is unreachable.** Limits, approver roster, idempotency store, audit ledger and fingerprint keys are structurally out of reach of the managed agent, and that judgement depends on no configurable policy — no setting is looser than its strictest default without a matching, unexpired, approved record. | A2, A3 | `tests/architecture/test_control_plane_isolation.py`, `tests/architecture/test_shared_side_isolation.py`, `tests/architecture/test_relaxation_is_fail_closed.py`, plus the three `INV-12` import contracts in `pyproject.toml` |
| INV-13 | **Determinism.** Identical inputs produce byte-identical results, including finding order. Extension registration order does not affect the record, not merely the verdict. | A9 | `tests/contracts/test_structured_findings.py`, `tests/contracts/test_combine_laws.py` |
| INV-14 | **Source trust only ever decreases.** No path upgrades an instruction's provenance. Mixed provenance is treated as its least trusted component. | B9 | `tests/adapters/test_stripe_conformance.py`, `tests/adapters/test_alpaca_conformance.py` |
| INV-15 | **The published contract surface is frozen.** Once `CONTRACT_VERSION` is fixed, no published symbol, enum member, or model field is added, removed, or renamed without changing the version. A plugin certified against a version keeps working, or is refused for declaring a version core no longer serves — it never silently faces a surface that shifted underneath it. | A9 | `tests/architecture/test_contract_surface_ratchet.py` |

## Why fail-closed means DENY

INV-1 resolves to `DENY`, not to an escalation.

The tempting alternative is to escalate an unknown to human review: nothing
executes either way, and one crashing extension cannot then halt all payments.
That argument is real, and the availability pressure it describes is itself a
threat (A8 — an operator who cannot ship disables the control).

It is nonetheless rejected. An extension that failed might have been the one
about to deny. Treating "we do not know" as "a human should look" quietly moves
a machine-checkable guarantee into a queue that, under load, gets approved in
bulk. The correct answer to the availability concern is **operator-visible
extension health and a declared degraded state**, not a softer verdict.

## Changing an invariant

An invariant changes only through an accepted ADR in
[`decisions/`](decisions/) that states what replaces the guarantee, plus a
matching change to the enforcing test in the same pull request. A pull request
that removes or loosens an enforcement test without such an ADR is rejected on
that ground alone.
