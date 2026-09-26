// The local model call: prompt, request and answer parsing.
// Port of pipeline/llm_client.py (the MVP's BEC-aware JSON prompt, decision D5).
//
// Settings that matter for evaluation: temperature 0 and a fixed seed (the same email
// gives the same answer), a num_predict cap (bounds the repetition loops small models
// fall into), and format=json (Ollama constrains the output to valid JSON).

import { cpSlice } from "./py.js";

export const OLLAMA_HOST = "http://localhost:11434";
export const MODEL = "llama3.2:3b";
export const KEEP_ALIVE = "30m";
export const BODY_CHARS = 1500;

export const SYSTEM =
  "You are an email security analyst. You judge whether an email is a phishing "
  + "or Business Email Compromise (BEC) attempt. BEC emails often contain no links "
  + "or attachments at all: they impersonate a colleague or supplier and ask for a "
  + "payment, a bank-detail change, gift cards, or an urgent confidential favour. "
  + "Answer with JSON only.";

export function buildPrompt(e) {
  const sender = cpSlice(e.from, 200) || "(none)";
  const replyTo = cpSlice(e.reply_to, 200) || "(none)";
  const subject = cpSlice(e.subject, 200) || "(none)";
  const links = cpSlice(e.links.slice(0, 8).join(", "), 400) || "(none)";
  const attachments = e.attachments.slice(0, 5).join(", ") || "(none)";
  const body = cpSlice(e.body, BODY_CHARS) || "(empty)";
  return `${SYSTEM}

From: ${sender}
Reply-To: ${replyTo}
Subject: ${subject}
Links in body: ${links}
Attachments: ${attachments}

Body (truncated):
"""
${body}
"""

Reply with exactly this JSON and nothing else:
{"phishing_probability": <number between 0.0 and 1.0>, "reason": "<one short sentence>"}

phishing_probability is how likely this email is a phishing or BEC attempt.
0.0 means certainly a normal legitimate email. 1.0 means certainly an attack.
Use the middle of the range when you are unsure.
`;
}

/** The body of the POST to Ollama's /api/generate. */
export function ollamaRequest(email, { model = MODEL, seed = 42, numPredict = 200 } = {}) {
  return {
    model,
    prompt: buildPrompt(email),
    stream: false,
    format: "json",
    keep_alive: KEEP_ALIVE,
    options: { temperature: 0, seed, num_predict: numPredict },
  };
}

// Python's float(): numbers, or strings that look like numbers.
function pyFloat(v) {
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string" && /^\s*[+-]?(\d+\.?\d*(e[+-]?\d+)?|\.\d+(e[+-]?\d+)?|inf(inity)?|nan)\s*$/i.test(v)) return Number(v.trim().replace(/^([+-]?)inf(inity)?$/i, "$1Infinity"));
  throw new TypeError("not a number");
}
// str() of a JSON value as Python prints it (for the reason field)
function pyStr(v) {
  if (v === null) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  return typeof v === "string" ? v : JSON.stringify(v);
}
const clamp01 = (x) => Math.min(Math.max(x, 0.0), 1.0);
const round4 = (x) => Number(x.toFixed(4));

/**
 * Parse Ollama's generate response ({response: "..."}) into
 * {verdict, phishing_probability, reason, error}, as llm_client.classify() does.
 */
export function parseModelAnswer(raw) {
  const text = String(raw?.response ?? "").trim();
  let obj;
  try { obj = JSON.parse(text); } catch {
    return { verdict: null, phishing_probability: null, reason: cpSlice(text, 200), error: "unparsable JSON" };
  }
  // Python would raise on a JSON value that is not an object; treat it as an empty answer.
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) obj = {};
  const p = "phishing_probability" in obj ? obj.phishing_probability : obj.probability;
  let prob = null;
  try { prob = clamp01(pyFloat(p)); } catch { prob = null; }
  if (prob === null || Number.isNaN(prob)) {
    // tolerate a model that answered in the older verdict/confidence shape
    const v = String(obj.verdict ?? "").trim().toLowerCase();
    let c;
    try { c = clamp01(pyFloat(obj.confidence)); } catch { c = 0.7; }
    if (v.includes("phish") || ["malicious", "suspicious", "bec"].includes(v)) prob = c;
    else if (["legitimate", "legit", "safe", "normal", "benign"].includes(v)) prob = 1.0 - c;
    else return { verdict: null, phishing_probability: null, reason: cpSlice(text, 200), error: "no probability field" };
  }
  return { verdict: prob >= 0.5 ? "phishing" : "legitimate", phishing_probability: round4(prob),
    reason: cpSlice(pyStr("reason" in obj ? obj.reason : ""), 300), error: "" };
}

/** Ask the local Ollama. Only localhost is contacted (NFR-1). */
export async function classify(email, { fetchImpl = fetch, timeoutMs = 120000, ...opts } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const t0 = Date.now();
  try {
    const res = await fetchImpl(`${OLLAMA_HOST}/api/generate`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ollamaRequest(email, opts)), signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { ...parseModelAnswer(await res.json()), latency_s: (Date.now() - t0) / 1000 };
  } catch (exc) {
    return { verdict: null, phishing_probability: null, reason: "", error: String(exc.message || exc), latency_s: (Date.now() - t0) / 1000 };
  } finally {
    clearTimeout(timer);
  }
}
