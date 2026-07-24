# Security Policy

SecondSign Core sits on the execution path before a financial AI agent can move
money. A defect here is not an ordinary bug, so reporting one has its own path,
separate from the public issue tracker.

## What counts as a security report

Report privately — **not** in a public issue — anything that touches:

- a **decision** being wrong in the unsafe direction (an action permitted that
  the policy should have held or denied), or a way to make a decision
  non-monotonic;
- a **credential handle** leaking a real value, or appearing anywhere it must
  not — an intent, a receipt, a plugin input, a log, or an error;
- the **no-bypass** invariant: any path by which a managed agent could reach a
  rail without passing through the decision path;
- **tenant or boundary isolation** — one caller reading or affecting another's
  intents, decisions, or receipts;
- **approval** replay, forgery, or reuse beyond its one-shot, digest-bound TTL;
- **raw financial or customer data** entering a decision record, receipt, or log.

Ordinary functional bugs with no security dimension go in the normal issue
tracker.

## How to report

Preferred: GitHub **private vulnerability reporting** for this repository
(*Security → Report a vulnerability*). It is private to the maintainers and needs
no shared inbox.

Backup channel: `security@<TODO: set a monitored security inbox before public
release>`. Until that inbox is confirmed live, use the private advisory above.

Please include: the invariant or property you believe is broken, the smallest
reproduction you have, the affected version or commit, and the impact as you see
it. If you have not confirmed impact, say so — a credible *possible* break in the
list above is still worth reporting.

Please do not open a public issue, PR, or discussion for a credential-, bypass-,
or decision-class report before it has been triaged and a fix is available.

## What to expect

While the project is pre-v1 and private, there is no formal SLA yet. The intent
is: acknowledge a report quickly, confirm or refute the impact, fix
security-relevant defects in priority order, and credit reporters who want it
once a fix has shipped. This section will be replaced with committed timelines
before the first public release.

## Scope

This policy covers `secondsign-core`. The hosted commercial offering has its own
reporting channel and its own responsibility model; see that product's terms. A
report about self-deployed core is handled under the Apache-2.0 `LICENSE` — see
[`docs/RESPONSIBILITY_MODEL.md`](docs/RESPONSIBILITY_MODEL.md) for how
responsibility is allocated when you run core yourself.
