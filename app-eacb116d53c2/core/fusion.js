// Decision policy (MVP-PRD §7.3, decisions D6-D8, D11) and the plain-language text
// shown to users (FR-5). Port of pipeline/fusion.py.
//
// The user sees one of two outcomes, never a "maybe":
//   DANGER  if a strong rule fires (the model is skipped) or the model says phishing (>= 0.5)
//   SAFE    otherwise
// and, only when the model could not run and no strong rule fired:
//   UNCHECKED  "only a basic check was done", never shown as SAFE.
//
// Weak rule hits never change the outcome; they appear only on UNCHECKED. A
// verification tip is attached to SAFE/UNCHECKED emails that ask for a payment, a
// bank-detail change, or a switch to the phone.

import { strip, stripChars, cpSlice } from "./py.js";
import { brandImpersonation, urgencyPhrases, riskyAttachments, paymentPhrases, PAYMENT, domainOf,
  registrable, addressOf } from "./rules.js";

export const T_MODEL = 0.5;

// Requests to leave email for a phone channel, or an unexplained urgent task.
export const CONTACT = ["cell number", "cell #", "cell phone number", "mobile number", "personal number",
  "your number", "whatsapp", "text me", "urgent task", "quick task",
  "are you at your desk", "are you available", "quick favour", "quick favor"];

/**
 * rules: output of runRules(). modelProbability: number in [0, 1], or null if the model
 * did not run. knownSender: null, or why the sender is known ('trusted' | 'verified').
 */
export function decide(rules, modelProbability = null, knownSender = null) {
  if (rules.strong.length) return { kind: "danger", verdict: "phishing", ai: "skipped" };
  if (knownSender) return { kind: "safe", verdict: "legitimate", ai: "skipped", known_sender: knownSender };
  if (modelProbability === null || modelProbability === undefined) return { kind: "unchecked", verdict: null, ai: "not_run" };
  if (modelProbability >= T_MODEL) return { kind: "danger", verdict: "phishing", ai: "used" };
  return { kind: "safe", verdict: "legitimate", ai: "used" };
}

export function contactPhrases(email) {
  const blob = (email.subject + " " + cpSlice(email.body, 4000)).toLowerCase();
  return CONTACT.filter((p) => blob.includes(p));
}

export function verifyTip(email) {
  if (paymentPhrases(email).length)
    return "This email is about a payment or bank details. Before paying or changing "
      + "anything, confirm with the sender by phone, using a number you already have.";
  if (contactPhrases(email).length)
    return "This email asks you to switch to your phone or do an urgent task. Scams often "
      + "start this way - check it is really them, using contact details you already have.";
  return null;
}

// str.capitalize()
const capitalize = (s) => { const [f = "", ...r] = s; return f.toUpperCase() + r.join("").toLowerCase(); };

function ruleSentence(name, email) {
  if (name === "auth") return "This email failed the check that confirms who really sent it.";
  if (name === "brand") {
    const imp = brandImpersonation(email);
    if (imp) return `The sender calls itself ${capitalize(imp[0])}, but the email was sent `
      + `from ${imp[1] || "an unrelated address"}.`;
    return null;
  }
  if (name === "attachment") {
    const bad = riskyAttachments(email);
    return bad.length ? `It has an attachment that can run code on your computer (${bad[0]}).`
      : "It has an attachment type that is often used to spread malware.";
  }
  if (name === "sender") {
    const fd = registrable(domainOf(email.from));
    const rtd = registrable(domainOf(email.reply_to));
    if (rtd && rtd !== fd) return `Replies would go to ${rtd}, not to the sender's own address (${fd}).`;
    return "The sender's address details do not match each other.";
  }
  if (name === "links") return "A link looks like it goes to one website but actually goes somewhere else.";
  if (name === "urgency") {
    const hits = urgencyPhrases(email);
    const pressure = hits.filter((h) => !PAYMENT.includes(h));
    if (hits.length && !pressure.length) return `It asks about a payment or bank details ("${hits[0]}").`;
    const quote = pressure.length ? ` ("${pressure[0]}")` : "";
    return `It pressures you to act quickly or secretly${quote}.`;
  }
  if (name === "obfuscation") return "Parts of the email are disguised in a way normal senders rarely use.";
  return null;
}

/** Strong-rule sentences first, then the other rule hits, without repeats. */
function ruleSentences(email, rules) {
  const out = [];
  for (const name of rules.strong) {
    const s = ruleSentence(name, email);
    if (s) out.push(s);
  }
  const covered = new Set(["auth", "attachment"].filter((x) => rules.strong.includes(x)));
  for (const [name, hit] of Object.entries(rules.rule_hits)) {
    if (!hit || covered.has(name)) continue;
    const s = ruleSentence(name, email);
    // a sender hit caused only by brand impersonation is already explained
    if (name === "sender" && rules.strong.includes("brand") && !s.startsWith("Replies")) continue;
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}

// Model reasons that dispute who sent the email; not shown when the mail server
// confirmed the sender. Claims of impersonation are kept.
const SENDER_DOUBT = /spoof|forged|fake (?:sender|address|domain)|(?:suspicious|unknown|unverified|untrusted) (?:sender|domain|address)/i;
const W = "[\\p{L}\\p{N}_]";
const SPLIT_AND = new RegExp(`(?<!${W})and(?!${W})|,|;`, "u");

/** The model's one-line reason, labelled as an opinion, or null. */
export function modelView(reason, senderConfirmed) {
  reason = stripChars(strip(reason || ""), ".", false, true);
  if (!reason) return null;
  if (senderConfirmed && SENDER_DOUBT.test(reason)) {
    const parts = reason.split(SPLIT_AND).map((p) => strip(p)).filter((p) => p);
    const kept = parts.filter((p) => !SENDER_DOUBT.test(p));
    if (!kept.length) return null;
    reason = kept.join(" and ");
    const [f, ...r] = reason;
    reason = f.toUpperCase() + r.join("");
  }
  return "The local AI's view: " + reason + ".";
}

/** Facts about the sender the user can check for themselves. */
export function senderFacts(email, senderKey) {
  return { domain: registrable(domainOf(email.from)), address: addressOf(email.from), confirmed: Boolean(senderKey) };
}

/**
 * What the add-in shows. `reasons` appear on a warning; `details` (weak rule hits) sit
 * behind an expander, on UNCHECKED only. `trust_offer` is offered only on an AI-only
 * warning for a sender the organisation's server authenticated.
 */
export function alert(email, rules, decision, modelReason = "", limit = 3, senderKey = null) {
  const sentences = ruleSentences(email, rules);
  const facts = senderFacts(email, senderKey);
  if (decision.kind === "danger") {
    const reasons = sentences.filter((s) => s).slice(0, rules.strong.length);
    if (decision.ai === "used") {
      const view = modelView(modelReason, facts.confirmed);
      reasons.push(view || "The local AI rated this email as likely phishing but gave no specific reason.");
    }
    reasons.push(...sentences.filter((s) => !reasons.includes(s)));
    const offer = senderKey && !rules.strong.length ? senderKey : null;
    return { kind: "danger", reasons: reasons.slice(0, limit), details: [], tip: null,
      ai: decision.ai, known_sender: null, trust_offer: offer, sender: facts };
  }
  const known = decision.known_sender;
  const details = decision.kind === "unchecked" ? sentences : [];
  return { kind: decision.kind, reasons: [], details, tip: verifyTip(email), ai: decision.ai,
    known_sender: known ? { how: known, key: senderKey } : null, trust_offer: null, sender: facts };
}

/** Shown while the model is still working (no strong rule fired). */
export function pendingAlert(email, rules) {
  return { kind: "checking", reasons: [], details: [], fallback_details: ruleSentences(email, rules),
    tip: verifyTip(email), ai: "running", known_sender: null, trust_offer: null, sender: senderFacts(email, null) };
}
