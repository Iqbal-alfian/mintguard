# Don't Trust the Agent. Verify the Proof.

*How I built a Proof Gatekeeper for the zkVerify Agent Games — an AI agent whose every decision ships with a zero-knowledge proof — and a wallet guard that screens the contracts it is about to touch. #AgentGames*

---

## The problem with capable agents

An AI agent that can act on its own — move money, approve a payment, sign a transaction — creates an uncomfortable question for whoever relies on it:

**How do you know it did the right thing?**

"Trust me" is not an audit trail. Logs can be edited. Screenshots can be staged. An agent can *claim* it checked the conditions before approving a payment, and you have no way to distinguish a real check from a confident hallucination.

The zkVerify Agent Games turns that problem into a sport. In the **Proof Gatekeeper** track, your agent judges proof-backed payment requests — and every decision it makes must come with a Groth16 zero-knowledge proof that the decision was computed correctly. The platform verifies the proof. Not your word. The proof.

This is the story of building one of those agents, what it actually does, and what running it taught me about verifiable agents. Receipts included.

## Meet the Gatekeeper

My agent is called **alfians**. It lives at a public HTTPS endpoint and plays in the Proof Gatekeeper arena, where rounds run daily (17:30–03:30 my local time) with 8 tasks per agent per round.

- **Endpoint:** https://agent-gatekeeper-alfians.vercel.app/api/agent
- **Code:** https://github.com/Iqbal-alfian/agent-gatekeeper

For every task, the platform sends a signed request envelope describing a payment and the conditions it must satisfy. The agent has 60 seconds to answer with a decision — APPROVE or REJECT — and, for provable tasks, a valid Groth16 proof of that decision. A wrong approval costs more than a wrong rejection (−6 vs −3), a correct decision earns +12, and a missing or invalid proof on a provable task is penalised separately. The scoring is deliberately asymmetric: in payments, a bad "yes" is worse than a bad "no".

### How a decision is made

The order of checks matters, and getting it wrong is exactly what the arena's seven trap varieties are designed to catch:

1. **Verify the envelope first.** The request body is authenticated with HMAC-SHA256 over the *raw* bytes, before any JSON parsing. If the signature doesn't check out, nothing else about the request can be trusted.
2. **Replay check.** If this proof transaction has been seen before, the answer is REJECT — `PROOF_REUSED` — and no new proof is produced. A proof that was valid once must not become a skeleton key.
3. **Key substitution.** If the verification key in the request is not the registered one, reject: `VK_SUBSTITUTION`. This is the trap for agents that verify against whatever key the caller hands them.
4. **Condition checks, in order.** Balance below the required minimum → `THRESHOLD_MISMATCH`. Past the expiry block → `EXPIRED_CONDITION`. Recipient different from the condition's recipient → `RECIPIENT_MISMATCH`. Amount above the maximum transfer → `AMOUNT_OVERFLOW`.
5. **Approve — and prove it.** Only a request that survives every check gets an APPROVE, and the decision is proven with a Groth16 proof (BN128 curve, generated with snarkjs) over the circuit's 13 public signals, then the response itself is signed.

### Receipts, not claims

Everything above would just be another "trust me" story without evidence, so here is the evidence:

- **Health check: PASSED.** After registration, the platform's own health check reported the agent **ACTIVE — 1 registered / 1 healthy / 0 needing attention**.
- **First practice task: PASSED in full.** The trap was an `AMOUNT_OVERFLOW`; the agent rejected it with the matching reason, the platform marked the decision's **proof: VERIFIED**, and the round-trip latency was **925 ms** against a 60-second budget.
- **It runs unattended.** Scored rounds run nightly; the agent answers from its deployment without anyone watching it. That is rather the point of an agent.

## The second build: a guard for the agent's own wallet

Competing in the arena raised a practical question back home: my agents also screen real contracts before any mint or interaction. An agent that verifies proofs for a living should not sign blindly itself.

So for the **Wildcard** track I packaged the screening pipeline I already use into a public agent: **MintGuard**, a BSC contract safety auditor.

- **Demo + endpoint:** https://mintguard-alfians.vercel.app
- **Code:** https://github.com/Iqbal-alfian/mintguard

Paste a BNB Chain contract address and MintGuard returns an explainable verdict — a score from 0–100 and a band (**GO / CAUTION / BLOCK**) with per-check evidence: Is the source verified on Sourcify (checked with a plain lookup, and on the implementation contract when the target is a proxy)? Who is the owner — renounced, an EOA, a contract? Is supply capped on-chain? Does the ABI expose blacklist functions, adjustable taxes, pause switches, rescue/sweep drains?

Two design rules came from expensive lessons:

- **Confirm decisive reads on a second RPC.** Public chain RPCs occasionally return stale or empty results; a verdict that moves money should never rest on one node's word. (Sound familiar? It is the same "don't trust, verify" rule, one layer down.)
- **A failed read is reported as "could not read", never guessed.** An auditor that hallucinates a "safe" is worse than no auditor.

Real verdicts from its first test run:

| Contract | Score | Band | Why |
|---|---|---|---|
| Claf Eye NFT (verified source) | 80 | GO | Exact-match verification, capped supply; points off for a live EOA owner |
| BAGENT mint proxy (unverified implementation) | 70 | CAUTION | Follows the proxy to the code that actually runs; unverified code takes the full penalty |
| A plain wallet address (no code) | 0 | BLOCK | No contract code at the address — nothing to audit, nothing to trust |

One detail from that run is my favourite: the mint site for the first contract advertised a max supply of 9,999, but the contract itself says 18,000. MintGuard reported the chain's number. Marketing copy is not evidence; code is.

## What verification actually buys you

zkVerify's role in the Gatekeeper is easy to state and hard to fake: it makes the agent's claim *checkable by anyone*, without revealing anything beyond the decision itself. That changes the trust model in three concrete ways:

1. **Accountability survives autonomy.** The agent can act alone at 3 a.m.; the proof still lets anyone audit the decision afterwards.
2. **"The agent said so" stops being an answer.** Either the proof verifies or it doesn't. There is no reputation to hide behind.
3. **Verification composes.** A payment gate that proves its decisions can sit in front of other agents — like a wallet guard screening contracts — and each layer's claims stay independently checkable.

Agents are going to keep getting more capable and more autonomous. The question is whether their evidence keeps up. This season, in one small arena, it does — and building for that arena is the most fun I've had making an agent prove it.

---

*Built and operated by alfians for the zkVerify Agent Games (Season 01) — Proof Gatekeeper and Wildcard tracks. #AgentGames*
