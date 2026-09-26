// Six independent heuristic checks. Each returns [hit, weight, reason].
// Port of pipeline/rules.py; names, lists, weights and reason texts are the same, except
// that the product reads Microsoft's compauth verdict when present (R9; policy "legacy"
// reproduces the pipeline exactly).
//
// Authentication checks are tri-state: an email with no SPF/DKIM headers is
// 'unknown' and carries no penalty, because the legitimate corpora predate those
// standards.

import { WS, strip, stripChars, cpSlice, urlNetloc } from "./py.js";

export const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"]);
export const RISKY_EXT = [".exe", ".scr", ".js", ".vbs", ".jar", ".iso", ".img", ".lnk",
  ".bat", ".cmd", ".ps1", ".docm", ".xlsm", ".pptm", ".htm", ".html"];
export const BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "netflix", "google",
  "docusign", "dropbox", "linkedin", "facebook", "chase", "wellsfargo", "hsbc",
  "coindesk", "binance", "dhl", "fedex", "ups", "irs", "ato", "myGov"];
// BEC-oriented language, not only generic phishing urgency
export const URGENCY = ["urgent", "immediately", "as soon as possible", "asap", "right away",
  "action required", "final notice", "expires today", "within 24 hours",
  "verify your account", "confirm your identity", "account suspended",
  "unusual activity", "click here to", "update your payment",
  "wire transfer", "bank details", "change of bank", "remittance",
  "outstanding invoice", "payment overdue", "gift card", "purchase order",
  "are you available", "quick favour", "quick favor", "in a meeting",
  "keep this confidential", "do not tell", "handle this discreetly"];
// Requests to move money or change where money goes. Used for the "verify by phone"
// tip on emails that are NOT flagged: BEC often carries no other signal.
export const PAYMENT = ["wire transfer", "bank transfer", "bank details", "bank account", "change of bank",
  "new account details", "updated account details", "account number", "routing number",
  "iban", "swift", "sort code", "remittance", "outstanding invoice", "overdue invoice",
  "payment overdue", "make a payment", "process a payment", "process the payment",
  "gift card", "itunes card", "google play card", "purchase order", "payroll", "direct deposit"];

// Two-label public suffixes: under these, the registrable domain is the last THREE labels.
export const MULTI_SUFFIX = new Set([
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
  "co.nz", "org.nz", "govt.nz", "ac.nz", "net.nz",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "org.hk", "edu.hk", "gov.hk",
  "com.tw", "org.tw", "edu.tw", "com.sg", "edu.sg", "gov.sg", "com.my", "co.jp", "ne.jp",
  "or.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in", "ac.in", "com.br",
  "com.mx", "com.ar", "co.za", "org.za", "com.tr", "com.vn", "com.ph", "co.id", "co.th",
]);

// Free mailbox providers: anyone can get an address, so trust is per address.
export const FREEMAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
  "yahoo.com", "yahoo.com.au", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
  "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
  "qq.com", "163.com", "126.com", "sina.com", "foxmail.com", "bigpond.com", "optusnet.com.au",
]);

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Python's \b and \w are Unicode-aware; JavaScript's are ASCII-only.
const W = "[\\p{L}\\p{N}_]";
// Every PAYMENT phrase starts and ends with a letter, so \bphrase\b is a lookaround.
const PAYMENT_RE = PAYMENT.map((p) => [p, new RegExp(`(?<!${W})${escapeRe(p)}(?!${W})`, "u")]);

export function domainOf(addrOrUrl) {
  let s = strip(addrOrUrl || "").toLowerCase();
  if (s.includes("@") && !s.includes("://")) {
    s = strip(stripChars(s.slice(s.lastIndexOf("@") + 1), ">"));
  } else {
    try {
      const netloc = urlNetloc(s);
      s = netloc.slice(netloc.lastIndexOf("@") + 1);
    } catch {
      return "";
    }
  }
  return stripChars(s.split(":")[0], "<>[] ");
}

export function registrable(d) {
  const parts = (d || "").split(".");
  if (parts.length >= 3 && MULTI_SUFFIX.has(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : d;
}

const ADDR_ANGLE = new RegExp(`<([^<>@${WS}]+@[^<>${WS}]+)>`, "u");
const ADDR_BARE = new RegExp(`([^${WS}<>"']+@[^${WS}<>"']+)`, "u");

export function addressOf(frm) {
  const m = ADDR_ANGLE.exec(frm || "") || ADDR_BARE.exec(frm || "");
  return m ? stripChars(m[1].toLowerCase(), ".") : "";
}

// Which receiving servers' Authentication-Results are believed. Only the user's OWN
// receiving server can be trusted; an organisation sets its own here (MVP-PRD §7.4, R9).
export const TRUSTED_AUTHSERV = new Set(["mx.google.com"]);

/**
 * Trust key for the sender if the user's own receiving mail server confirmed who sent
 * it, else null: the topmost Authentication-Results from a trusted authserv-id, DMARC
 * pass, aligned with From. The key is the registrable domain, or the full address for
 * free mailbox providers.
 */
export function authenticatedSender(e, trustedAuthserv = TRUSTED_AUTHSERV) {
  const a = strip(e.auth_results || "").toLowerCase();
  const semi = a.indexOf(";");
  const authserv = strip(semi < 0 ? a : a.slice(0, semi));
  if (!trustedAuthserv.has(authserv) || !a.includes("dmarc=pass")) return null;
  const fd = registrable(domainOf(e.from));
  const m = /header\.from=([a-z0-9.-]+)/.exec(a);
  if (!fd || (m && registrable(m[1]) !== fd)) return null;
  if (FREEMAIL.has(fd)) return addressOf(e.from) || null;
  return fd;
}

// Microsoft's composite authentication verdict (R9, decision D19). Exchange Online and
// Outlook.com add an Authentication-Results header with compauth= on top of every
// message. Unlike raw SPF/DKIM/DMARC it takes forwarding gateways into account (for
// example through their ARC records), which make those raw checks fail on genuine mail.
// Only the topmost Authentication-Results is read (parseEmail keeps the first one), so
// a compauth= that a sender writes further down is ignored.
const COMPAUTH = /(?:^|[\s;])compauth=([a-z]+)(?:\s+reason=([0-9a-z]+))?/;

/** Authentication policies: the product's ("compauth") and the evaluated pipeline's ("legacy"). */
export const AUTH_POLICIES = ["compauth", "legacy"];

export function rAuth(e, policy = "compauth") {
  const blob = [e.auth_results, e.received_spf].join(" ").toLowerCase();
  const hasDkim = Boolean(e.dkim_signature);
  if (!blob && !hasDkim) return [false, 0.0, "auth: absent (old corpus, not penalised)"];
  const fails = ["spf=fail", "spf=softfail", "dkim=fail", "dmarc=fail"].filter((k) => blob.includes(k));
  const ca = policy === "compauth" ? COMPAUTH.exec((e.auth_results || "").toLowerCase()) : null;
  if (ca) {
    // the receiving server's own verdict decides; raw failures are kept as facts
    const verdict = `compauth=${ca[1]}${ca[2] ? ` reason=${ca[2]}` : ""}`;
    if (ca[1] === "fail") return [true, 0.25, `auth: ${verdict}`];
    return [false, 0.0, `auth: ${verdict}${fails.length ? ` (raw ${fails.join(",")})` : ""}`];
  }
  if (fails.length) return [true, 0.25, "auth: " + fails.join(",")];
  return [false, 0.0, "auth: pass/neutral"];
}

/** [brand, sending domain] if the display name claims a brand the domain does not back. */
export function brandImpersonation(e) {
  const fd = registrable(domainOf(e.from));
  const disp = e.from.split("<")[0].toLowerCase();
  for (const b of BRANDS) {
    const bl = b.toLowerCase();
    // whole-word match: short brands ("ato", "ups", "irs") otherwise hit inside names
    if (new RegExp(`(?<![a-z])${escapeRe(bl)}(?![a-z])`).test(disp) && !fd.includes(bl)) return [b, fd];
  }
  return null;
}

const blobOf = (e) => (e.subject + " " + cpSlice(e.body, 4000)).toLowerCase();

export function urgencyPhrases(e) {
  const blob = blobOf(e);
  return URGENCY.filter((p) => blob.includes(p));
}

export function paymentPhrases(e) {
  const blob = blobOf(e);
  return PAYMENT_RE.filter(([, re]) => re.test(blob)).map(([p]) => p);
}

export function riskyAttachments(e) {
  return e.attachments.filter((a) => RISKY_EXT.some((x) => a.toLowerCase().endsWith(x)));
}

export function rSender(e) {
  const fd = registrable(domainOf(e.from));
  const reasons = [];
  let w = 0.0;
  const imp = brandImpersonation(e);
  if (imp) { reasons.push(`display name claims '${imp[0]}' but domain is ${imp[1]}`); w += 0.25; }
  const rtd = registrable(domainOf(e.reply_to));
  if (rtd && rtd !== fd) { reasons.push(`reply-to ${rtd} != from ${fd}`); w += 0.15; }
  const rpd = registrable(domainOf(e.return_path));
  if (rpd && rpd !== fd) { reasons.push(`return-path ${rpd} != from ${fd} (weak: normal for lists)`); w += 0.05; }
  return [w >= 0.15, Math.min(w, 0.3), "sender: " + (reasons.join("; ") || "consistent")];
}

const DOMAIN_IN_LABEL = /([a-z0-9-]+\.[a-z]{2,})/;
const RAW_IP = /^\p{Nd}{1,3}(\.\p{Nd}{1,3}){3}$/u;

export function rLinks(e) {
  const reasons = [];
  for (const [label, href] of e.anchors) {
    const m = DOMAIN_IN_LABEL.exec((label || "").toLowerCase());
    const hd = registrable(domainOf(href));
    if (m && hd && registrable(m[1]) !== hd) { reasons.push(`anchor says ${m[1]} but links to ${hd}`); break; }
  }
  for (const url of e.links) {
    const d = domainOf(url);
    if (RAW_IP.test(d)) { reasons.push(`raw IP link ${d}`); break; }
    if (SHORTENERS.has(registrable(d))) { reasons.push(`shortener ${d}`); break; }
  }
  return [reasons.length > 0, reasons.length ? 0.2 : 0.0, "links: " + (reasons.join("; ") || "no mismatch")];
}

export function rUrgency(e) {
  const hits = urgencyPhrases(e);
  const w = Math.min(0.2, 0.07 * hits.length);
  return [hits.length > 0, w, "urgency: " + (hits.slice(0, 4).join(", ") || "none")];
}

export function rAttachment(e) {
  const bad = riskyAttachments(e);
  return [bad.length > 0, bad.length ? 0.2 : 0.0, "attachment: " + (bad.slice(0, 3).join(", ") || "none risky")];
}

export function rObfuscation(e) {
  const reasons = [];
  if ((e.raw_html.match(/&#\p{Nd}{2,3};/gu) || []).length > 20) reasons.push("heavy HTML-entity encoding");
  if (/[​-‏⁠­﻿]/.test(e.raw_html)) reasons.push("invisible unicode characters");
  for (const url of e.links) {
    const d = domainOf(url);
    if (d && [...d].some((c) => c.codePointAt(0) > 127)) { reasons.push(`non-ascii link domain ${d}`); break; }
    if (d.startsWith("xn--")) { reasons.push(`punycode domain ${d}`); break; }
  }
  return [reasons.length > 0, reasons.length ? 0.2 : 0.0, "obfuscation: " + (reasons.join("; ") || "none")];
}

export const CHECKS = [["auth", rAuth], ["sender", rSender], ["links", rLinks],
  ["urgency", rUrgency], ["attachment", rAttachment], ["obfuscation", rObfuscation]];

/**
 * Signals that are hard to produce legitimately; any one is enough to call the email
 * phishing on its own (MVP-PRD §7.3): an authentication failure, a display name
 * impersonating a brand, or a risky attachment.
 */
export function strongSignals(email, hits) {
  const strong = [];
  if (hits.auth) strong.push("auth");
  try { if (brandImpersonation(email)) strong.push("brand"); } catch { /* as in Python */ }
  if (hits.attachment) strong.push("attachment");
  return strong;
}

const round4 = (x) => Number(x.toFixed(4));

/**
 * Run the six checks. options.auth picks the authentication policy: "compauth" (the
 * product) or "legacy" (pipeline/rules.py as evaluated, used by the parity test).
 */
export function runRules(email, { auth = "compauth" } = {}) {
  if (!AUTH_POLICIES.includes(auth)) throw new RangeError(`unknown auth policy ${auth}`);
  const hits = {}, reasons = [];
  let score = 0.0;
  for (const [name, fn] of CHECKS) {
    let hit, w, why;
    try { [hit, w, why] = name === "auth" ? fn(email, auth) : fn(email); }
    catch (exc) { [hit, w, why] = [false, 0.0, `${name}: error ${exc.message}`]; }
    hits[name] = hit ? 1 : 0;
    score += w;
    reasons.push(why);
  }
  return { rule_score: round4(Math.min(score, 1.0)), rule_hits: hits, rule_reasons: reasons,
    strong: strongSignals(email, hits) };
}
