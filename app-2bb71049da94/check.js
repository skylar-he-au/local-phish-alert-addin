// Checking one message in Outlook (MVP-PRD FR-1-FR-4, FR-9). Shared by the task pane and
// the one-click toolbar command (D17).
//
// The message is read as raw MIME (getAsFileAsync, Mailbox 1.14) so the detection core
// parses exactly what the evaluation parsed. Nothing leaves this page except the model
// request, which the core sends to Ollama on localhost only (NFR-1).

import { parseEmail, runRules, decide, alert, pendingAlert, classify, cpSlice } from "./core/index.js";

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

/**
 * Check an email. `onUpdate` receives the intermediate "checking" result while the model
 * runs. Returns {subject, from, alert, rules, model}, where model is null when the model
 * was not needed, or {probability, latency_s, error, problem}.
 */
export async function checkBytes(bytes, { onUpdate = () => {}, classifyImpl = classify } = {}) {
  const email = parseEmail(bytes);
  const rules = runRules(email);
  const base = { subject: email.subject, from: email.from, rules };
  if (rules.strong.length) {
    return { ...base, alert: alert(email, rules, decide(rules, null)), model: null };
  }
  onUpdate({ ...base, alert: pendingAlert(email, rules), model: null });
  const m = await classifyImpl(email);
  if (m.error) {
    const model = { probability: null, latency_s: m.latency_s, error: m.error, problem: modelProblem(m.error) };
    return { ...base, alert: alert(email, rules, decide(rules, null)), model };
  }
  const model = { probability: m.phishing_probability, latency_s: m.latency_s, error: "", problem: null };
  return { ...base, alert: alert(email, rules, decide(rules, m.phishing_probability), m.reason), model };
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
  if (a.kind === "checking") return { type: T.ProgressIndicator, message: "Local Phish Alert is checking this email on your computer…" };
  if (a.kind === "danger") return { type: T.ErrorMessage, message: clip(`Likely phishing or scam. ${a.reasons[0] || ""}`.trim()) };
  if (a.kind === "safe") {
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
