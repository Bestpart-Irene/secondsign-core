# Example: a third-party audit sink

A complete, runnable audit sink that lives **outside** `src/secondsign/` and
imports only the published surface (`secondsign.audit`, `secondsign.conformance`)
— the shape a third party's own package would take. It is certified the way
every extension is: by inheriting a conformance suite, not by persuading a
maintainer. See [`docs/EXTENSION_CONTRACTS.md`](../../docs/EXTENSION_CONTRACTS.md)
for the contract this example instantiates.

An audit destination is the extension a real deployment needs first: a receipt
that only lands on local disk is not an audit trail anyone will accept.

## What it does

[`JsonlAuditSink`](jsonl_sink.py) appends each `AuditReceipt` as one JSON line
to a file and reads them back on demand. That is the whole protocol — `append`
and `entries`. It is deliberately boring: swap the file for your log pipeline
or WORM store and keep everything else.

## What it must guarantee — the part worth studying

- **A write failure is a failure, and it is never swallowed** (INV-11). Nothing
  in `append` catches `OSError`. A sink that turns a failed write into a
  success code has punched a hole in the audit trail and labelled it green —
  the machinery above this sink is fail-closed precisely so that "the receipt
  could not be written" stops the action, and a sink that hides the failure
  defeats all of it. The test
  `test_a_write_failure_propagates_instead_of_reading_as_success` proves the
  error reaches the caller.
- **Nothing it writes contains a raw identifier.** A receipt is already
  redacted — the digest is a hash, the principal is a keyed fingerprint — and
  this sink *asserts* that shape on every write rather than trusting it in a
  comment: unknown fields are refused, and every reference-carrying position
  must still look like a hash or an `fp:…` fingerprint at the moment of
  writing. Two tests feed it a raw identifier and an extra field and watch it
  refuse.
- **Nothing is dropped, nothing is reordered, nothing is altered.** That is
  what the inherited conformance suite certifies, and
  `test_what_lands_on_disk_is_still_a_verifiable_chain` closes the loop: what
  comes back off disk still passes `verify_chain`.

## Certifying it

The entire integration is one subclass (in
[`test_conformance.py`](test_conformance.py)):

```python
from examples.audit_sink.jsonl_sink import JsonlAuditSink
from secondsign.conformance import AuditSinkConformance


class TestJsonlAuditSinkConformance(AuditSinkConformance):
    sink_factory = staticmethod(_fresh_sink)  # a zero-arg factory → empty sink
    receipt_corpus = _CORPUS  # built via AuditLog, properly chained
```

## Run it

```bash
pip install -e ".[dev]"
pytest examples/audit_sink/ -v
ruff check . && ruff format --check .
```

The conformance suite is also collected by the project's normal `pytest` run
(`examples/` is on `testpaths`), so this example cannot rot: a change to the
published surface that breaks it fails CI here, not in a stranger's fork.
