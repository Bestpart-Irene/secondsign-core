# Example: an agent-side client certified by the wire conformance kit

The smallest client that passes `WireClientConformance` — a socket, a request,
a status back — plus two deliberately broken variants and the failures the kit
reports for them. It lives **outside** `src/secondsign/`, uses the standard
library only, and imports exactly one thing from core: the dialect constants
in `secondsign.agent.wire`, which are declared once and never re-spelled here.

If you are writing a client in a language that is not Python, this kit is the
only executable statement of what the wire requires, and
[`minimal_client.py`](minimal_client.py) is the reference to translate.

## The whole integration is three lines

```python
from secondsign.conformance import WireClientConformance


class TestMinimalWireClient(WireClientConformance):
    def attempt(self, host, port, request):
        return MinimalWireClient(host=host, port=port).authorize(request)
```

Nothing about your client's API is prescribed — `attempt(host, port, request)
-> status` is all the kit asks, because what is certified is the protocol, not
an implementation of it. The kit stands up its own `ProbeGateway` rather than
the real gateway: half of what a client must survive is a *malformed* answer,
and the real gateway cannot be asked to produce one.

## What the kit demands, in one sentence each

- **It asks.** A verdict reached without sending anything is a verdict the
  control plane never made.
- **It sends the closed envelope, unaltered** — `wire_version` and the
  proposal, nothing else, and the proposal is the one it was handed.
- **It carries no identity.** The principal comes from the authenticated peer;
  a principal in the body is refused, not ignored.
- **It refuses rather than guesses.** A foreign dialect, an unparseable
  answer, an unknown status, a gateway that declines or is not there — all of
  it reads `refused`, never a locally computed verdict.
- **It relays what it is told.** Refusing everything is as much an invented
  verdict as completing everything.

## The half worth studying: the clients that fail

[`non_conformant.py`](non_conformant.py) is the minimal client with one check
removed each — which is how real non-conformance happens, because both broken
clients are indistinguishable from the conformant one on the happy path
(there is a test proving exactly that):

- `DialectBlindClient` ignores the answer's `wire_version`. The kit fails it
  with *"a response announcing wire version 2 read as 'completed'; a peer
  speaking a different dialect may mean something different by every word in
  it, including this one."*
- `OptimistClient` treats an unparseable answer as success — `except: pass`
  on the one boundary where it costs money. The kit fails it with *"an
  unparseable answer read as 'completed'; something answered, and what
  answered was demonstrably not this contract."*

## Run it

```bash
pip install -e ".[dev]"
pytest examples/wire_client/ -v
ruff check . && ruff format --check .
```

The conformance suite is also collected by the project's normal `pytest` run
(`examples/` is on `testpaths`), so this example cannot rot: a change to the
wire contract that breaks it fails CI here, not in a stranger's fork.
