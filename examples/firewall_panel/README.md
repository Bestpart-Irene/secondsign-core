# The firewall panel

An interactive view of the on-chain decision path: what the co-signer checks,
in what order, and why a proposal does or does not get a second signature.

```bash
python examples/firewall_panel/server.py     # then open http://127.0.0.1:8099
```

No Foundry, no RPC, no network. Bound to loopback only.

## What is real and what is not

| | |
|---|---|
| **Real** | Every verdict, produced by the shipped `OnchainCosigner`. The policy, the chain re-verification, the maker-checker, the audit receipts, and the ECDSA signatures over genuine Safe transaction hashes. |
| **Simulated** | The chain. The Safe's state and the pinned token's identity come from `StaticChainStateReader` over facts in `world.py`, not from a node. |
| **Rendered, not executed** | The Solidity double guard (station ⑦). This panel runs no EVM, so the four constitutional invariants are shown greyed out. For guards that actually revert, see `onchain/test` and `examples/onchain_firewall_demo.py`. |

Nothing is executed, so no balance ever changes: the panel demonstrates a
**judgement**, which is the thing that happens before money moves.

## The seven stations

① chain re-verification → ② decode → ③ policy → ④ signing boundary →
⑤ human review → ⑥ audit receipt → ⑦ on-chain double guard

Stations ①–③ are recomputed by `trace.py` through the same public API the
co-signer uses, and are labelled `observed`. Stations ④–⑥ are reported by the
co-signer itself and are labelled `cosigner`. The panel never decides anything:
the verdict banner is always `CosignOutcome.status`.

That split has a risk — a recomputation can drift from what the co-signer
actually did — and one control:
`test_trace_never_disagrees_with_the_cosigner` asserts the reconstruction and
the real outcome agree across every scenario and every knob setting. It has
already earned its place by catching a bug on the drift path.

## Three things worth doing in front of someone

1. **Break the account, then propose again.** Remove the transaction guard and
   watch the same routine payment that signed a moment ago get refused at
   station ① — before the call is even decoded.
2. **Break it while a human is deciding.** Propose the 20 USDC payment, let it
   hold, remove the guard, then approve as Ops. A real approval by a real
   second principal, and still no signature: `resolve` re-reads the chain.
   Repair the account and approve again — it signs, because a drift refusal
   does not burn the human's answer.
3. **Approve as the agent.** Answer a held review as the agent that proposed
   it. Refused — the maker cannot be the checker.

## Layout

| File | Holds |
|---|---|
| `world.py` | the simulated account and the six ways to break it |
| `scenarios.py` | the preset proposals, each carrying the verdict its label claims |
| `trace.py` | one judgement → seven stations |
| `session.py` | world + knobs + a real co-signer over both |
| `server.py` | the JSON API and the page |
| `static/` | the page itself |

A demo aid, not a product surface: no login, no users, no persistence, and it
resets on restart.
