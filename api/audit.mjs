// MintGuard — Vercel function.
//   POST /api/audit  { "address": "0x..." }   -> JSON verdict
//   GET  /api/audit?address=0x...             -> JSON verdict
// Malformed address -> 400 with a clear error object.
// A well-formed address with no contract code is a 200 verdict
// (band BLOCK, score 0, explicit 'no contract code' check), not a 500.

import { audit } from "../lib/audit.mjs";

function sendJson(res, status, obj) {
  const out = JSON.stringify(obj);
  if (typeof res.status === "function" && typeof res.json === "function") {
    return res.status(status).json(obj);
  }
  res.writeHead(status, { "content-type": "application/json" });
  res.end(out);
}

async function readBody(req) {
  if (req.body) {
    return typeof req.body === "string" ? safeParse(req.body) : req.body;
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return null;
  return safeParse(Buffer.concat(chunks).toString("utf8"));
}

function safeParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  try {
    let address = null;
    const url = new URL(req.url || "", "http://localhost");
    address = url.searchParams.get("address");
    if (!address && req.method === "POST") {
      const body = await readBody(req);
      if (body && typeof body.address === "string") address = body.address;
    }
    if (!address) {
      return sendJson(res, 400, {
        error: "missing_address",
        detail: "provide an address as JSON body {\"address\": \"0x...\"} or as ?address=0x...",
      });
    }
    const verdict = await audit(address);
    return sendJson(res, 200, verdict);
  } catch (e) {
    if (e && e.code === "BAD_ADDRESS") {
      return sendJson(res, 400, { error: "invalid_address", detail: e.message });
    }
    return sendJson(res, 500, { error: "audit_failed", detail: String(e && e.message ? e.message : e) });
  }
}
