# MintGuard — BSC Contract Safety Auditor

**Built for the zkVerify Agent Games — Wildcard track.**

## The problem

Free-mint hunters on BNB Chain sign transactions against contracts they cannot
read. Mint pages routinely show placeholder or truncated addresses, "free"
drops hide owner-controlled traps — blacklist functions that freeze your
wallet, taxes the owner can raise after you buy, uncapped owner minting,
pausable transfers, drainable proceeds — and some drops are outright
honeypots. By the time a hunter finds out, the gas and the mint fee are gone.

MintGuard gives that hunter a 30-second, evidence-based answer before they
sign anything.

## Who it helps

Anyone about to mint, buy, or deposit into a BSC (chain 56) contract —
especially free-mint hunters evaluating drops they found minutes ago. It is
read-only: it never asks for a signature, a wallet connection, or an approval.

## What it does

Submit one contract address (web form, or `GET /api/audit?address=0x…`, or
`POST /api/audit {"address": "0x…"}`) and get back an explainable verdict:

```json
{
  "address": "0x…",
  "chain": 56,
  "verified": { "verified": true, "match": "exact_match", "name": "…" },
  "score": 82,
  "band": "GO",
  "checks": [ { "name": "owner", "status": "warn", "detail": "…" } ],
  "summary": "GO (82/100): …"
}
```

Bands: **GO ≥ 75** · **CAUTION 40–74** · **BLOCK < 40**. An address with no
contract code is a BLOCK verdict with score 0 — there is nothing to mint.

## Checks

1. **Contract code** — `eth_getCode`; empty code means EOA, verdict stops.
2. **RPC confirmation** — decisive reads (code, owner) are made on two
   independent public BSC RPCs, because a single public RPC occasionally
   returns stale or wrong values.
3. **Source verification** — Sourcify plain v2 lookup. Only `exact_match`
   counts as fully verified; a partial-grade match is docked; no source is a
   heavy penalty and the verdict then rests on bytecode-level signals only.
   (The judgement deliberately uses the plain lookup — the
   `?fields=match,abi` variant can falsely report `match: None`.)
4. **Proxy resolution** — EIP-1967 implementation slot. A proxy's own
   bytecode proves nothing, so when a proxy is detected, verification and
   the surface scan follow the **implementation** — the code that actually
   runs — and the proxy itself is docked because its logic can be swapped.
5. **Owner** — `owner()` read live. Zero address = renounced (bonus).
   A live EOA owner is docked most; a contract owner less. An `owner()` call
   that *reverts* is reported as "unknown", never as a renounce.
6. **Supply** — `totalSupply()`, `totalMinted()`, and a supply cap
   (`maxSupply()`, `MAX_SUPPLY()`, or a cap-shaped getter named in the
   verified ABI) where the contract exposes them; a readable cap counts in
   the contract's favour and bounds the mint-surface deduction.
7. **Pause state** — `paused()` right now; a currently-paused contract is
   docked hard.
8. **Risky-function surface** (verified source only) — the ABI is scanned
   for blacklist/bot-list control, owner-adjustable tax/fee setters,
   pause/unpause control, mint functions, withdraw functions, rescue/sweep
   (arbitrary asset extraction), mutable-metadata setters, and upgrade
   functions. These are labelled honestly as *surface signals*: an ABI shows
   function names, not `onlyOwner` modifiers or reachability.

## Scoring rubric (deterministic)

Start at 100, then:

| Signal | Points |
|---|---|
| Source not verified | −35 |
| Source only partially matched | −10 |
| Live owner is an EOA | −15 |
| Live owner is a contract | −5 |
| Owner renounced | +10 (clamped at 100) |
| Transfers currently paused | −15 |
| Blacklist surface (live owner) | −20 (−5 if renounced) |
| Adjustable tax surface (live owner) | −15 (−5 if renounced) |
| Pause/unpause surface (live owner) | −5 |
| Mint surface with live owner | −10, or −5 when a supply cap is readable on-chain (bounded mint) |
| Withdraw surface | −5 |
| Rescue/sweep surface | −10 |
| Mutable metadata surface | −5 |
| EIP-1967 proxy detected | −5 |
| upgradeTo surface in ABI | −5 |

Score is clamped to 0–100. Every check in the response cites the read it
came from; a read that fails is reported as `info / could not read`, never
guessed.

## What it cannot do

- It is a screening aid, **not a guarantee** and not financial advice. A high
  score means "no traps found by these probes", not "safe".
- For unverified contracts it sees bytecode-level signals only (code
  presence, owner, pause state) — it cannot see inside the code.
- ABI surface signals can over- or under-state risk: a listed function may
  be inert, and a trap may hide behind an innocuous name or a proxy
  implementation that was not separately audited here.
- It does not analyse liquidity, holder concentration, or market behaviour.

## Provenance

MintGuard productizes an audit pipeline that already screens real mints in
day-to-day use: the `bsc-contract-audit` skill (verification, privilege
inventory, 0–100 rubric with GO/CAUTION/BLOCK gating) and the
`bsc_free_mint_preflight` skill (recovering the true mint contract behind a
placeholder address, and hard lessons about empty RPC results and
single-source reads). The same checks that gate the author's own wallet
before a mint are the checks in `lib/audit.mjs`.

## Run it

```bash
node server.mjs            # local dev server on :8793 (PORT to override)
# open http://localhost:8793 and paste an address
```

## Deploy (Vercel)

The repo is a zero-dependency Vercel app: `api/audit.mjs` is the function
(30 s max duration, see `vercel.json`), `public/index.html` is served at `/`.

```bash
vercel deploy
```

Requires Node ≥ 18 (uses the global `fetch`). No environment variables, no
API keys: BSC data comes from public RPCs, verification from Sourcify.

## Layout

```
lib/audit.mjs     the audit engine (RPC + Sourcify + rubric)
api/audit.mjs     Vercel function: GET ?address= / POST {address}
public/index.html demo page (paste an address, read the verdict)
server.mjs        local dev server wiring the same handlers
vercel.json       function config
```

Reference only, not investment advice.
