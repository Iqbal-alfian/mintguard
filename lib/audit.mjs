// MintGuard — BSC (chain 56) contract safety audit engine.
//
// Input: one contract address. Output: an explainable verdict
// { address, chain, verified, score, band, checks, summary }.
//
// Every number in the output comes from a live read (BSC RPC or the
// Sourcify plain lookup). A read that fails is reported as a check with
// status 'info' and detail 'could not read' — never guessed.
//
// Evidence rules (from the bsc-contract-audit skill this productizes):
//  - Verification is judged ONLY from the Sourcify plain v2 lookup.
//    The ?fields=match,abi query can falsely return match:None, so it
//    is never used to judge verification (only, as a fallback, to fetch
//    an ABI after verification is already established).
//  - Decisive reads (contract code, owner) are confirmed on a second
//    independent RPC; public BSC RPCs occasionally return stale data.
//  - owner() reverting is NOT a renounce. Only a successful owner()
//    call returning the zero address proves renounced ownership.
//  - A proxy's own bytecode/ABI proves nothing about behaviour: when an
//    EIP-1967 proxy is detected, verification and the surface scan
//    follow the implementation — the code that actually runs.
//  - An ABI function name is a surface signal, not proof of behaviour:
//    the ABI does not show modifiers (onlyOwner) or reachability. An
//    empty ABI is no ABI.

const RPCS = [
  "https://bsc-dataseed.binance.org",
  "https://bsc-dataseed1.defibit.io",
  "https://bsc-dataseed.bnbchain.org",
];

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// Well-known function selectors (see the skill's references/selectors.md).
const SEL = {
  owner: "0x8da5cb5b",
  totalSupply: "0x18160ddd",
  maxSupply: "0xd5abeb01",
  totalMinted: "0xa2309ff8",
  paused: "0x5c975abb",
  name: "0x06fdde03",
  symbol: "0x95d89b41",
};

// EIP-1967 implementation storage slot.
const IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

// ---------------------------------------------------------------------------
// Keccak-256 (pure JS, BigInt lanes) — needed to build function selectors
// for ABI-driven probes such as MAX_SUPPLY(). Not Node's sha3-256: Ethereum
// uses original Keccak padding.
// ---------------------------------------------------------------------------

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_RHO = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const MASK64 = (1n << 64n) - 1n;

function rotl64(x, n) {
  if (n === 0) return x;
  const b = BigInt(n);
  return ((x << b) | (x >> (64n - b))) & MASK64;
}

function keccakF1600(s) {
  for (let round = 0; round < 24; round++) {
    const c = new Array(5);
    const d = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d[x];
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], KECCAK_RHO[x + 5 * y]);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y]);
      }
    }
    s[0] ^= KECCAK_RC[round];
  }
}

export function keccak256(data) {
  const input = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const rate = 136; // 1088-bit rate for Keccak-256
  const s = new Array(25).fill(0n);
  const padded = Buffer.alloc(Math.ceil((input.length + 1) / rate) * rate, 0);
  input.copy(padded, 0);
  padded[input.length] = 0x01; // Keccak pad10*1 (not SHA3's 0x06)
  padded[padded.length - 1] |= 0x80;
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      s[i] ^= lane;
    }
    keccakF1600(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    let lane = s[i];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

export function selector(sig) {
  return "0x" + keccak256(sig).subarray(0, 4).toString("hex");
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

async function fetchJson(url, options = {}, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// One JSON-RPC call against one endpoint.
// Returns { state: 'ok', value } | { state: 'revert' } | { state: 'error', detail }
async function rpcOnce(url, method, params) {
  try {
    const res = await fetchJson(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!res.ok) return { state: "error", detail: `HTTP ${res.status} from ${url}` };
    const body = await res.json();
    if (body.error) {
      if (method === "eth_call") return { state: "revert", detail: body.error.message || "reverted" };
      return { state: "error", detail: body.error.message || "rpc error" };
    }
    return { state: "ok", value: body.result };
  } catch (e) {
    return { state: "error", detail: String(e && e.message ? e.message : e) };
  }
}

// Fallback chain: first RPC that answers wins.
async function rpc(method, params) {
  let last = { state: "error", detail: "no RPC tried" };
  for (const url of RPCS) {
    const r = await rpcOnce(url, method, params);
    if (r.state !== "error") return r;
    last = r;
  }
  return last;
}

// Decisive read: query two independent RPCs and report agreement.
async function rpcConfirmed(method, params) {
  const [a, b] = await Promise.all([
    rpcOnce(RPCS[0], method, params),
    rpcOnce(RPCS[1], method, params),
  ]);
  if (a.state === "ok" && b.state === "ok") {
    return { state: "ok", value: a.value, agree: a.value === b.value, sources: 2 };
  }
  if (a.state === "ok") return { state: "ok", value: a.value, agree: null, sources: 1 };
  if (b.state === "ok") return { state: "ok", value: b.value, agree: null, sources: 1 };
  if (a.state === "revert" || b.state === "revert") return { state: "revert", agree: null, sources: 0 };
  return { state: "error", detail: a.detail || b.detail, agree: null, sources: 0 };
}

async function ethCall(address, data) {
  return rpc("eth_call", [{ to: address, data }, "latest"]);
}

async function ethCallConfirmed(address, data) {
  return rpcConfirmed("eth_call", [{ to: address, data }, "latest"]);
}

// ---------------------------------------------------------------------------
// Decoding helpers (ABI words only — no external libraries)
// ---------------------------------------------------------------------------

function wordToAddress(hex) {
  if (!hex || hex.length < 42) return null;
  return "0x" + hex.slice(-40).toLowerCase();
}

function wordToBigInt(hex) {
  if (!hex || hex === "0x") return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

function wordToBool(hex) {
  const v = wordToBigInt(hex);
  return v === null ? null : v !== 0n;
}

// Decode a dynamic string return (offset + length + bytes).
function wordToString(hex) {
  try {
    if (!hex || hex.length < 130) return null;
    const len = Number(BigInt("0x" + hex.slice(66, 130)));
    const bytesHex = hex.slice(130, 130 + len * 2);
    const bytes = Buffer.from(bytesHex, "hex");
    const s = bytes.toString("utf8").trim();
    return s.length ? s : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Sourcify (plain lookup only for the verification judgement)
// ---------------------------------------------------------------------------

// Map Sourcify's raw match strings onto tiers. The v2 plain lookup reports
// runtimeMatch values 'exact_match', 'partial_match', the weaker legacy
// 'match' (per the audit skill: "match only" is a partial-grade result),
// or null when the contract is unknown.
function matchTier(raw) {
  if (raw === "exact_match") return "exact";
  if (raw === "partial_match" || raw === "match") return "partial";
  return "none";
}

async function sourcifyLookup(address) {
  const url = `https://sourcify.dev/server/v2/contract/56/${address.toLowerCase()}`;
  try {
    const res = await fetchJson(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      // Sourcify answers 404 for contracts it does not know.
      return { tier: "none", raw: null, abi: null, name: null, detail: `Sourcify HTTP ${res.status}` };
    }
    const body = await res.json();
    const raw = body.runtimeMatch ?? body.match ?? null;
    const tier = matchTier(raw);
    let abi = Array.isArray(body.abi) && body.abi.some((e) => e && e.type === "function") ? body.abi : null;
    const name = body?.compilation?.name ?? body?.name ?? null;
    if (!abi && tier !== "none") {
      // Verification is already decided from the plain lookup above;
      // this second call only fetches the ABI for the surface scan.
      try {
        const r2 = await fetchJson(`${url}?fields=abi`, { headers: { accept: "application/json" } });
        if (r2.ok) {
          const b2 = await r2.json();
          if (Array.isArray(b2.abi) && b2.abi.some((e) => e && e.type === "function")) abi = b2.abi;
        }
      } catch {
        /* ABI stays null; surface scan degrades to info */
      }
    }
    return { tier, raw, abi, name, detail: null };
  } catch (e) {
    return { tier: "none", raw: null, abi: null, name: null, detail: `could not read (${e.message || e})` };
  }
}

// ---------------------------------------------------------------------------
// Risky-surface scan over ABI function names (surface signals, honestly
// labelled — an ABI shows names, not modifiers or reachability)
// ---------------------------------------------------------------------------

const SURFACE_RULES = [
  {
    key: "blacklist",
    label: "blacklist / bot-list control",
    test: (n) => /blacklist|blocklist|setbots|botblacklist/i.test(n),
  },
  {
    key: "tax",
    label: "owner-adjustable tax / fees",
    test: (n) => /^set(tax|taxes|fee|fees)\b/i.test(n) || /set\w*(tax|fee)/i.test(n),
  },
  {
    key: "pause_control",
    label: "pause / unpause control",
    test: (n) => /^(pause|unpause)$/i.test(n),
  },
  {
    key: "mint",
    label: "mint function",
    // Only state-changing mint entry points count; view getters such as
    // mintedBy() or MINT_SITE() are not mint surface.
    test: (n, e) => /^mint/i.test(n) && (e.stateMutability === "payable" || e.stateMutability === "nonpayable"),
  },
  {
    key: "withdraw",
    label: "withdraw function",
    test: (n) => /^(withdraw|emergencywithdraw)/i.test(n),
  },
  {
    key: "rescue",
    label: "rescue / sweep (arbitrary asset extraction)",
    test: (n) => /rescue|sweep/i.test(n),
  },
  {
    key: "metadata",
    label: "mutable metadata (setBaseURI-style)",
    test: (n) => /^set(baseuri|basetokenuri|uri)/i.test(n),
  },
  {
    key: "upgrade",
    label: "upgrade function (upgradeTo-style)",
    test: (n) => /^upgrade(to|toandcall)/i.test(n),
  },
];

function scanSurface(abi) {
  const fns = (abi || []).filter((e) => e && e.type === "function" && typeof e.name === "string");
  const hits = {};
  for (const rule of SURFACE_RULES) {
    const matched = fns.filter((e) => rule.test(e.name, e)).map((e) => e.name);
    if (matched.length) hits[rule.key] = { label: rule.label, functions: [...new Set(matched)] };
  }
  return { hits };
}

// ---------------------------------------------------------------------------
// Scoring rubric (deterministic; documented in README.md)
//
// Start at 100. Deductions (verification and surface follow the code that
// actually runs — the implementation, when the address is a proxy):
//   running code not verified ............ -35
//   running code only partially matched .. -10
//   live owner that is an EOA ............ -15
//   live owner that is a contract ........  -5
//   owner renounced ...................... +10 (bonus, clamped at 100)
//   transfers currently paused ........... -15
//   blacklist surface (live owner) ....... -20   (-5 if owner renounced)
//   adjustable tax surface (live owner) .. -15   (-5 if owner renounced)
//   pause/unpause surface (live owner) ...  -5
//   mint surface, owner live ............. -10, or -5 when a supply cap is
//                                          readable on-chain (bounded mint)
//   withdraw surface .....................  -5
//   rescue/sweep surface ................. -10
//   mutable metadata surface .............  -5
//   EIP-1967 proxy detected ..............  -5
//   upgradeTo surface in ABI .............  -5
// Bands: GO >= 75 · CAUTION 40-74 · BLOCK < 40. Score clamped to 0..100.
// ---------------------------------------------------------------------------

function bandFor(score) {
  if (score >= 75) return "GO";
  if (score >= 40) return "CAUTION";
  return "BLOCK";
}

export async function audit(rawAddress) {
  const checks = [];
  const add = (name, status, detail) => checks.push({ name, status, detail });

  if (typeof rawAddress !== "string" || !ADDRESS_RE.test(rawAddress.trim())) {
    const err = new Error("invalid address: expected 0x followed by 40 hex characters");
    err.code = "BAD_ADDRESS";
    throw err;
  }
  const address = rawAddress.trim();

  // --- Gate: is there contract code? (confirmed on two RPCs) ---------------
  const codeRes = await rpcConfirmed("eth_getCode", [address, "latest"]);
  if (codeRes.state !== "ok") {
    add("contract_code", "info", "could not read contract code from any RPC");
    return finish(address, { verified: false, match: null }, 0, checks,
      "BLOCK: could not read this address from any BSC RPC — no verdict possible.");
  }
  const code = codeRes.value;
  if (!code || code === "0x") {
    add("contract_code", "fail",
      "no contract code at this address (empty eth_getCode on two independent RPCs) — this is an externally owned account (EOA) or an unused address, not a contract");
    return finish(address, { verified: false, match: null }, 0, checks,
      "BLOCK: no contract code at this address — there is nothing to mint from or audit.");
  }
  const codeBytes = (code.length - 2) / 2;
  add("contract_code", "pass", `contract code present, ${codeBytes} bytes of runtime bytecode`);
  add("rpc_confirmation", codeRes.agree === false ? "warn" : "info",
    codeRes.agree === false
      ? "two independent BSC RPCs disagreed on eth_getCode; the verdict uses the non-empty result and should be re-run"
      : `decisive reads confirmed on ${codeRes.sources} independent BSC RPCs`);

  let score = 100;

  // --- Proxy resolution (EIP-1967): audit the code that actually runs -------
  let implAddress = null;
  const slotRes = await rpc("eth_getStorageAt", [address, IMPL_SLOT, "latest"]);
  if (slotRes.state === "ok") {
    const impl = wordToAddress(slotRes.value);
    if (impl && impl !== ZERO_ADDRESS) implAddress = impl;
  }
  const isProxy = implAddress !== null;
  if (isProxy) {
    score -= 5;
    add("proxy", "warn",
      `EIP-1967 proxy: implementation slot points to ${implAddress}. Verification and the function-surface scan below follow the implementation — the code that actually runs — and a proxy admin may be able to swap it`);
  } else if (slotRes.state === "ok") {
    add("proxy", "info", "no EIP-1967 implementation found (not a standard proxy)");
  } else {
    add("proxy", "info", "could not read the EIP-1967 implementation slot");
  }

  // --- Verification (Sourcify plain lookup, on the running code) ------------
  const target = implAddress || address;
  const sc = await sourcifyLookup(target);
  const verified = {
    verified: sc.tier !== "none",
    match: sc.tier === "exact" ? "exact_match" : sc.tier === "partial" ? "partial_match" : null,
    name: sc.name,
  };
  if (isProxy) verified.viaProxy = implAddress;
  if (sc.tier === "exact") {
    add("source_verification", "pass",
      `source of the running code verified on Sourcify with exact_match${sc.name ? ` (contract: ${sc.name})` : ""}${isProxy ? ` — implementation ${implAddress}` : ""}`);
  } else if (sc.tier === "partial") {
    score -= 10;
    add("source_verification", "warn",
      `source of the running code only partially matched on Sourcify (raw match: ${sc.raw})${isProxy ? ` — implementation ${implAddress}` : ""} — the deployed bytecode is not fully accounted for by the published source`);
  } else {
    score -= 35;
    add("source_verification", "fail",
      sc.detail && sc.detail.startsWith("could not read")
        ? `could not read Sourcify (${sc.detail}); running code treated as unverified`
        : `no verified source on Sourcify for the running code${isProxy ? ` (implementation ${implAddress})` : ""} (plain v2 lookup) — behaviour cannot be reviewed, score is based on bytecode-level signals only`);
  }

  // --- Owner (confirmed on two RPCs). A revert is NOT a renounce. -----------
  const ownerRes = await ethCallConfirmed(address, SEL.owner);
  let ownerState = "unknown"; // 'renounced' | 'eoa' | 'contract' | 'unknown'
  if (ownerRes.state === "ok") {
    const ownerAddr = wordToAddress(ownerRes.value);
    if (!ownerAddr || ownerAddr === ZERO_ADDRESS) {
      ownerState = "renounced";
      score += 10;
      add("owner", "pass", "owner() returns the zero address — ownership renounced, onlyOwner functions are inert (role-based access beyond owner() is not probed)");
    } else {
      const oc = await rpc("eth_getCode", [ownerAddr, "latest"]);
      if (oc.state === "ok" && (!oc.value || oc.value === "0x")) {
        ownerState = "eoa";
        score -= 15;
        add("owner", "warn", `live owner ${ownerAddr} is an externally owned account (single private key controls every onlyOwner function)`);
      } else if (oc.state === "ok") {
        ownerState = "contract";
        score -= 5;
        add("owner", "warn", `live owner ${ownerAddr} is a contract (could be a multisig, timelock, or another program — not probed further)`);
      } else {
        ownerState = "eoa";
        score -= 15;
        add("owner", "warn", `live owner ${ownerAddr}; could not read the owner's code to classify it, treated as an EOA`);
      }
    }
  } else if (ownerRes.state === "revert") {
    add("owner", "info", "no readable owner() function (call reverts) — that is not a renounce; ownership state is unknown");
  } else {
    add("owner", "info", "could not read owner() from any RPC");
  }
  const ownerLive = ownerState === "eoa" || ownerState === "contract";

  // --- Identity + supply reads ------------------------------------------------
  const [nameR, symR, supplyR, mintedR] = await Promise.all([
    ethCall(address, SEL.name),
    ethCall(address, SEL.symbol),
    ethCall(address, SEL.totalSupply),
    ethCall(address, SEL.totalMinted),
  ]);
  const cName = nameR.state === "ok" ? wordToString(nameR.value) : null;
  const cSym = symR.state === "ok" ? wordToString(symR.value) : null;
  if (cName || cSym) {
    add("identity", "info", `name/symbol read on-chain: ${cName ?? "?"} (${cSym ?? "?"})`);
  }
  const totalSupply = supplyR.state === "ok" ? wordToBigInt(supplyR.value) : null;
  const totalMinted = mintedR.state === "ok" ? wordToBigInt(mintedR.value) : null;

  // Supply cap: try maxSupply() and MAX_SUPPLY() selectors, then any
  // zero-argument cap-shaped getter named in the verified ABI.
  let cap = null;
  let capVia = null;
  const capCandidates = [
    ["maxSupply()", SEL.maxSupply],
    ["MAX_SUPPLY()", selector("MAX_SUPPLY()")],
  ];
  if (sc.abi) {
    for (const e of sc.abi) {
      if (e && e.type === "function" && (e.inputs || []).length === 0 &&
          /^(max_?supply|maxmintsupply|collection_?size|max_?mint)$/i.test(e.name || "")) {
        const sig = `${e.name}()`;
        if (!capCandidates.some(([s]) => s === sig)) capCandidates.push([sig, selector(sig)]);
      }
    }
  }
  for (const [sig, sel] of capCandidates) {
    const r = await ethCall(address, sel);
    if (r.state === "ok") {
      const v = wordToBigInt(r.value);
      if (v !== null && v > 0n) {
        cap = v;
        capVia = sig;
        break;
      }
    }
  }
  const supplyParts = [];
  if (totalSupply !== null) supplyParts.push(`totalSupply ${totalSupply.toString()}`);
  if (totalMinted !== null) supplyParts.push(`totalMinted ${totalMinted.toString()}`);
  if (cap !== null) supplyParts.push(`supply cap ${cap.toString()} read via ${capVia} (minting is bounded)`);
  if (supplyParts.length) {
    add("supply", cap !== null ? "pass" : "info", supplyParts.join("; "));
  } else if (supplyR.state === "error") {
    add("supply", "info", "could not read supply figures from any RPC");
  } else {
    add("supply", "info", "no readable totalSupply() or supply cap — supply figures unavailable");
  }

  // --- Pause state --------------------------------------------------------------
  const pausedR = await ethCall(address, SEL.paused);
  if (pausedR.state === "ok") {
    const p = wordToBool(pausedR.value);
    if (p === true) {
      score -= 15;
      add("pause_state", "fail", "paused() returns true right now — transfers are frozen at this moment");
    } else if (p === false) {
      add("pause_state", "pass", "paused() returns false — the contract is not paused right now");
    } else {
      add("pause_state", "info", "could not decode the paused() result");
    }
  } else {
    add("pause_state", "info", "no readable paused() function");
  }

  // --- Risky-function surface (ABI of the running code) -------------------------
  if (sc.abi) {
    const { hits } = scanSurface(sc.abi);
    const has = (k) => hits[k];

    if (has("blacklist")) {
      if (ownerState === "renounced") {
        score -= 5;
        add("surface_blacklist", "warn",
          `blacklist surface present (${hits.blacklist.functions.join(", ")}) but the owner is renounced; role-based access beyond owner() was not probed`);
      } else {
        score -= 20;
        add("surface_blacklist", "fail",
          `blacklist surface present in the ABI: ${hits.blacklist.functions.join(", ")} — the controller can freeze individual wallets (surface signal: names only, modifiers not visible in an ABI)`);
      }
    } else {
      add("surface_blacklist", "pass", "no blacklist-style function in the verified ABI of the running code");
    }

    if (has("tax")) {
      if (ownerState === "renounced") {
        score -= 5;
        add("surface_tax", "warn",
          `tax/fee setter present (${hits.tax.functions.join(", ")}) but the owner is renounced; role-based access beyond owner() was not probed`);
      } else {
        score -= 15;
        add("surface_tax", "fail",
          `owner-adjustable tax/fee surface in the ABI: ${hits.tax.functions.join(", ")} — fees can be raised after you buy (surface signal: names only)`);
      }
    } else {
      add("surface_tax", "pass", "no owner tax/fee setter in the verified ABI of the running code");
    }

    if (has("pause_control")) {
      if (ownerLive) {
        score -= 5;
        add("surface_pause_control", "warn",
          `pause control present (${hits.pause_control.functions.join(", ")}) with a live owner — transfers can be frozen by the controller`);
      } else {
        add("surface_pause_control", "info",
          `pause control present (${hits.pause_control.functions.join(", ")}) but no live owner was found, so it appears inert`);
      }
    }

    if (has("mint")) {
      if (ownerLive) {
        if (cap !== null) {
          score -= 5;
          add("surface_mint", "warn",
            `state-changing mint function in the ABI (${hits.mint.functions.join(", ")}) with a live owner, but minting is bounded by an on-chain supply cap of ${cap.toString()} read via ${capVia} — access control is not visible from the ABI alone, treat as a surface signal`);
        } else {
          score -= 10;
          add("surface_mint", "warn",
            `state-changing mint function in the ABI (${hits.mint.functions.join(", ")}) with a live owner and no supply cap readable on-chain, so the mint surface looks uncapped — access control is not visible from the ABI alone, treat as a surface signal`);
        }
      } else {
        add("surface_mint", "info",
          `state-changing mint function in the ABI (${hits.mint.functions.join(", ")}); no live owner found${cap !== null ? `; supply cap ${cap.toString()} read via ${capVia}` : ""}`);
      }
    }

    if (has("withdraw") || has("rescue")) {
      const parts = [];
      if (has("withdraw")) { score -= 5; parts.push(`withdraw surface: ${hits.withdraw.functions.join(", ")} (normal for collecting mint proceeds, still an owner extraction path)`); }
      if (has("rescue")) { score -= 10; parts.push(`rescue/sweep surface: ${hits.rescue.functions.join(", ")} (can pull arbitrary assets out of the contract)`); }
      add("surface_funds", has("rescue") ? "fail" : "warn", parts.join("; "));
    } else {
      add("surface_funds", "pass", "no withdraw/rescue function in the verified ABI of the running code");
    }

    if (has("metadata")) {
      score -= 5;
      add("surface_metadata", "warn",
        `metadata can be re-pointed after the fact (${hits.metadata.functions.join(", ")}) — NFT art/metadata is not frozen`);
    }

    if (has("upgrade")) {
      score -= 5;
      add("surface_upgrade", "warn",
        `upgrade function in the ABI (${hits.upgrade.functions.join(", ")}) — the logic behind this address can be replaced`);
    }
  } else {
    add("function_surface", "info",
      "function surface unknown — no verified ABI for the running code, so blacklist/tax/mint/withdraw surfaces cannot be scanned; this verdict rests on bytecode-level signals (code presence, owner, pause state) only");
  }

  score = Math.max(0, Math.min(100, score));
  const band = bandFor(score);
  const top = checks.filter((c) => c.status === "fail" || c.status === "warn").slice(0, 3);
  const summary = top.length
    ? `${band} (${score}/100): ${top.map((c) => c.detail.split(" — ")[0]).join("; ")}`
    : `${band} (${score}/100): no failing or warning checks among the probes run`;
  return finish(address, verified, score, checks, summary);
}

function finish(address, verified, score, checks, summary) {
  return {
    address,
    chain: 56,
    verified,
    score,
    band: bandFor(score),
    checks,
    summary,
  };
}
