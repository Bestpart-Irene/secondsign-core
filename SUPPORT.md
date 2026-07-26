# Support

Everything needed to build on or contribute to SecondSign Core is in this
repository. Start here, in order.

## I want to understand what core is

- [`README.md`](README.md) — what it is and the shape of the decision path.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — what core is, and what it
  deliberately is not.
- [`docs/INVARIANTS.md`](docs/INVARIANTS.md) — the guarantees, each bound to the
  test that enforces it.

## I want to build an extension

A rail, policy source, approval channel, or audit destination is an extension —
it should not require changing core. See
[`docs/EXTENSION_CONTRACTS.md`](docs/EXTENSION_CONTRACTS.md): you certify an
extension by inheriting a conformance suite, not by persuading a reviewer.

## I want to contribute a change

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the slice protocol and the quality
  gates.
- [`docs/slices/roadmap.yaml`](docs/slices/roadmap.yaml) — the build queue you
  can pick from.
- [`GOVERNANCE.md`](GOVERNANCE.md) — who decides what, and how little needs
  deciding.

## I have a question

- Open a [Discussion](https://github.com/Bestpart-Irene/secondsign-core/discussions)
  for how-to and design questions.
- Open an [Issue](https://github.com/Bestpart-Irene/secondsign-core/issues) for
  a bug or a proposal — the templates guide what to include.
- Ask in [Discord](https://discord.gg/yQHfJGSmXn) if you would rather type it
  than write it up. Nothing said there is a commitment, and anything worth
  keeping should end up in a Discussion or an Issue.

## I found a security problem

Do not open a public issue. Use the private
[Report a vulnerability](https://github.com/Bestpart-Irene/secondsign-core/security/advisories/new)
form. See [`SECURITY.md`](SECURITY.md) for what is in scope and what to expect.

## What this project does not offer

There is no paid support, SLA, or private help channel here. This is a pre-1.0
open project maintained by a small group; the fastest path to an answer is a
clear, reproducible issue or a well-scoped pull request.
