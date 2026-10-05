// Checking one message in Outlook (MVP-PRD FR-1-FR-4, FR-9). Shared by the task pane and
// the one-click toolbar command (D17).
//
// The message is read as raw MIME (getAsFileAsync, Mailbox 1.14) so the detection core
// parses exactly what the evaluation parsed. Nothing leaves this page except the model
// request, which the core sends to Ollama on localhost only (NFR-1).

import { parseEmail, runRules, authenticatedSender, addressOf, latestArcResults, decide, alert, pendingAlert, classify, cpSlice } from "./core/index.js";
import { UNCONFIRMED, keyLabel } from "./view.js";

export class CheckError extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.code = code;
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The open message as RFC 822 bytes. Throws CheckError("unreadable"). */
export function readMessage(item) {
  return new Promise((resolve, reject) => {
    if (!item) return reject(new CheckError("no_message"));
    if (typeof item.getAsFileAsync !== "function") {
      return reject(new CheckError("unreadable", "This version of Outlook cannot give add-ins the full message."));
    }
    item.getAsFileAsync((r) => {
      if (r.status === Office.AsyncResultStatus.Succeeded && r.value) resolve(base64ToBytes(r.value));
      else reject(new CheckError("unreadable", r.error && r.error.message));
    });
  });
}

// What went wrong with the model call, for the "basic check only" state (FR-9, S5).
// The browser hides most reasons: a stopped Ollama, a refused origin and a blocked
// local-network request can all look like "Failed to fetch".
export function modelProblem(error) {
  const e = String(error || "");
  if (/HTTP 404/.test(e)) return "model_missing";
  if (/HTTP 403/.test(e)) return "origin_refused";
  if (/abort/i.test(e)) return "timeout";
  if (/^HTTP /.test(e)) return "model_error";
  return "not_reachable";
}

// After this long without an answer the user is told the browser may be waiting for them
// to allow local-network access (R8): until they do, the request to Ollama just waits.
export const SLOW_MS = 8000;

/**
 * Check an email. `trusted` is the user's trust list (store.js). `onUpdate` receives the
 * intermediate "checking" result while the model runs, again with `slow: true` if the
 * model has not answered after SLOW_MS. Returns {subject, from, senderKey, alert, rules,
 * model}, where model is null when the model was not needed, or {probability,
 * latency_s, error, problem}.
 */
export async function checkBytes(bytes, { onUpdate = () => {}, classifyImpl = classify, trusted = new Set(), timeoutMs } = {}) {
  const email = parseEmail(bytes);
  const rules = runRules(email);
  // who the mail server confirmed sent it (D20), and whether the user trusts them (FR-6)
  const senderKey = authenticatedSender(email);
  // A sender the mail server could not confirm can still be trusted by the user, per exact
  // address and marked as unconfirmed; strong rules still warn about it.
  const address = (addressOf(email.from) || "").toLowerCase();
  const looseKey = address ? UNCONFIRMED + address : null;
  const knownKey = senderKey && trusted.has(senderKey) ? senderKey : looseKey && trusted.has(looseKey) ? looseKey : null;
  const known = knownKey ? "trusted" : null;
  // the receiving server's and the gateway's verdicts, for the technical details
  const verdicts = [(/compauth=[a-z]+(?:\s+reason=\w+)?/i.exec(email.auth_results) || ["compauth: none"])[0]];
  const arc = latestArcResults(email);
  if (arc) {
    const serv = (arc.split(";")[1] || "").trim();
    const dmarc = (/dmarc=[a-z]+/i.exec(arc) || ["dmarc: none"])[0];
    const hf = (/header\.from=[^\s;]+/i.exec(arc) || [""])[0];
    verdicts.push(`gateway ${serv}: ${dmarc} ${hf}`.trim());
  }
  const base = { subject: email.subject, from: email.from, senderKey, rules, auth: verdicts };
  const show = (decision, reason = "") => {
    const a = alert(email, rules, decision, reason, 3, senderKey);
    if (a.known_sender) a.known_sender.key = knownKey;
    // a warning raised by the AI alone can be overruled for an unconfirmed sender too
    if (a.kind === "danger" && a.ai === "used" && !a.trust_offer && looseKey) a.trust_offer = looseKey;
    return a;
  };
  if (rules.strong.length || known) return { ...base, alert: show(decide(rules, null, known)), model: null };

  const pending = { ...base, alert: pendingAlert(email, rules), model: null };
  onUpdate(pending);
  const slow = setTimeout(() => onUpdate({ ...pending, slow: true }), SLOW_MS);
  let m;
  try {
    m = await classifyImpl(email, timeoutMs ? { timeoutMs } : {});
  } finally {
    clearTimeout(slow);
  }
  if (m.error) {
    const model = { probability: null, latency_s: m.latency_s, error: m.error, problem: modelProblem(m.error) };
    return { ...base, alert: show(decide(rules, null)), model };
  }
  const model = { probability: m.phishing_probability, latency_s: m.latency_s, error: "", problem: null };
  return { ...base, alert: show(decide(rules, m.phishing_probability), m.reason), model };
}

export async function checkItem(item, options) {
  return checkBytes(await readMessage(item), options);
}

// ---- The notification bar on the message (D16) ----

const BAR_KEY = "lpa";
const BAR_MAX = 150;   // Outlook's limit for notification text

const clip = (s) => (s.length > BAR_MAX ? cpSlice(s, BAR_MAX - 1) + "…" : s);

/** The bar for a result, a "checking" update, or a CheckError. */
export function barFor(result) {
  const T = Office.MailboxEnums.ItemNotificationMessageType;
  const info = (message) => ({ type: T.InformationalMessage, message: clip(message), icon: "Icon.16", persistent: false });
  if (result instanceof Error) {
    return info(result.code === "unreadable" ? "Local Phish Alert could not read this email, so it was not checked."
      : "Local Phish Alert could not check this email.");
  }
  const a = result.alert;
  if (a.kind === "checking") {
    return { type: T.ProgressIndicator, message: result.slow
      ? "Still checking. If your browser asks to allow access to apps on this computer, choose Allow."
      : "Local Phish Alert is checking this email on your computer…" };
  }
  if (a.kind === "danger") return { type: T.ErrorMessage, message: clip(`Likely phishing or scam. ${a.reasons[0] || ""}`.trim()) };
  if (a.kind === "safe") {
    if (a.known_sender) return info(`No warning signs found. You trust ${keyLabel(a.known_sender.key)}, so the local AI was not asked.`);
    return info(a.tip ? "No warning signs found. Before you act on a payment or phone request, check with the sender another way."
      : "Local Phish Alert found no warning signs (checked on this computer).");
  }
  return info("Only a basic check was done: the local AI is not available. Open Local Phish Alert to see why.");
}

export function showBar(item, result) {
  return new Promise((resolve) => {
    if (!item || !item.notificationMessages) return resolve(false);
    item.notificationMessages.replaceAsync(BAR_KEY, barFor(result), (r) => resolve(r.status === Office.AsyncResultStatus.Succeeded));
  });
}
