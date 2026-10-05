// Drawing a check result (MVP-PRD FR-4, FR-5, FR-9). Shared by the task pane and the demo
// page. Everything is built with textContent, never innerHTML: reasons contain text taken
// from the email, and an email must not be able to inject markup into the page.

import { MODEL } from "./core/index.js";

const KINDS = {
  danger: {
    look: "danger", title: "Likely phishing or scam",
    advice: "Don't click links, open attachments or send money. Check with the sender another way.",
  },
  safe: { look: "safe", title: "No warning signs found", advice: "" },
  unchecked: {
    look: "neutral", title: "Only a basic check was done",
    advice: "The local AI could not check this email, so it was not fully checked.",
  },
  checking: { look: "neutral", title: "Checking this email on your computer…", advice: "" },
};

// Why the local AI did not answer (FR-9, S5), and what to do about it.
const NOT_REACHABLE = "The local AI could not be reached. Check that Ollama is running on this computer, "
  + "that it allows this add-in, and that the browser may connect to apps on this computer.";
const PROBLEMS = {
  not_reachable: NOT_REACHABLE,
  origin_refused: NOT_REACHABLE,
  model_missing: `Ollama is running, but the model ${MODEL} is not downloaded. You can download it in Settings.`,
  timeout: "The local AI did not answer in time. If your browser asked to allow access to apps on this "
    + "computer, choose Allow and check again.",
  model_error: "The local AI reported an error.",
};

const PROVIDER = "Your mail server";

// Trust keys: a registrable domain (or a free-mail address) the mail server confirmed, or,
// with this prefix, an exact address the user trusted although it was not confirmed.
export const UNCONFIRMED = "unconfirmed:";
export const isUnconfirmed = (key) => key.startsWith(UNCONFIRMED);
export const keyLabel = (key) => (isUnconfirmed(key) ? key.slice(UNCONFIRMED.length) : key);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function button(text, onClick, cls = "") {
  const b = el("button", cls, text);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function list(items, cls) {
  const ul = el("ul", cls);
  for (const s of items) ul.append(el("li", "", s));
  return ul;
}

function expander(summary, body) {
  const d = el("details");
  d.append(el("summary", "", summary), body);
  return d;
}

// An inline "are you sure?" box: Outlook does not allow window.confirm in add-ins.
function confirmBox(text, yesLabel, onYes, onNo) {
  const box = el("div", "confirm");
  box.append(el("p", "", text));
  const row = el("div", "row");
  row.append(button(yesLabel, onYes, "primary"), button("Cancel", onNo));
  box.append(row);
  return box;
}

// ---- the check result ----

function drawCard({ look, title, advice }, extra = []) {
  const card = el("section", `card ${look}`);
  card.setAttribute("role", look === "danger" ? "alert" : "status");
  const h = el("h1", "title");
  h.append(el("span", "dot"), el("span", "", title));
  card.append(h);
  if (advice) card.append(el("p", "advice", advice));
  card.append(...extra);
  return card;
}

function drawWhich(subject) {
  const p = el("p", "which");
  p.append(el("span", "label", "Checked: "), el("span", "", subject || "(no subject)"));
  return p;
}

// FR-5: on a warning, the sender facts come first.
function senderLine(sender) {
  const p = el("p", "sender");
  p.append(el("span", "label", "Sent from "), el("strong", "", sender.address), document.createTextNode(". "));
  p.append(document.createTextNode(sender.confirmed
    ? `${PROVIDER} confirmed it really comes from ${sender.domain}. Do you know them and expect this email?`
    : `${PROVIDER} could not confirm who really sent it.`));
  return p;
}

// FR-6: offered only on a warning raised by the AI alone. For a sender the mail server
// confirmed, the whole domain is trusted; otherwise only the exact address, with a warning
// that the address could be faked.
function trustOffer(key, onTrust) {
  const row = el("div", "trust");
  const who = keyLabel(key);
  const text = isUnconfirmed(key)
    ? `${PROVIDER} could not confirm that this email really comes from ${who}, so a scammer could be using `
      + `that address. Only trust it if you are sure the email is genuine. Future emails from exactly ${who} will `
      + "no longer be flagged by the local AI alone. Clear warning signs, like a failed sender check or dangerous "
      + "attachments, are still shown. You can undo this in Settings."
    : `Only do this if you know ${who} and expected this email. Future emails that ${PROVIDER.toLowerCase()} `
      + `confirms really come from ${who} will no longer be flagged by the local AI alone. Clear warning signs, `
      + "like dangerous attachments, are still shown. You can undo this in Settings.";
  const ask = () => row.replaceChildren(confirmBox(
    text,
    isUnconfirmed(key) ? "Trust this address anyway" : `Trust ${who}`,
    async () => {
      try {
        await onTrust(key);
      } catch (e) {
        row.replaceChildren(el("p", "problem", `Could not save: ${e.message}`));
      }
    },
    () => row.replaceChildren(offer())));
  const offer = () => {
    const p = el("p");
    p.append(el("span", "label", "Not a scam? "), button(`I know ${who}`, ask, "link"));
    return p;
  };
  row.append(offer());
  return row;
}

function knownLine(known, onUntrust) {
  const p = el("p", "known");
  p.append(document.createTextNode(isUnconfirmed(known.key)
    ? `You trust ${keyLabel(known.key)}, so the local AI was not asked. ${PROVIDER} did not confirm this sender. `
    : `You trust ${known.key}, so the local AI was not asked. `));
  if (onUntrust) p.append(button("Stop trusting", () => onUntrust(known.key), "link"));
  return p;
}

/** The result card. `actions` ({onTrust, onUntrust}) enable the trust controls (FR-6). */
function drawResult(r, actions = {}) {
  const a = r.alert;
  const k = KINDS[a.kind] || { look: "neutral", title: `Result: ${a.kind}`, advice: "" };
  const extra = [];
  if (a.kind === "danger" && a.sender && a.sender.address) extra.push(senderLine(a.sender));
  if (a.reasons.length) extra.push(list(a.reasons, "reasons"));
  if (a.trust_offer && actions.onTrust) extra.push(trustOffer(a.trust_offer, actions.onTrust));
  if (a.known_sender) extra.push(knownLine(a.known_sender, actions.onUntrust));
  if (a.kind === "unchecked" && r.model && r.model.problem) extra.push(el("p", "problem", PROBLEMS[r.model.problem] || r.model.error));
  if (a.tip) {
    const tip = el("p", "tip");
    tip.append(el("strong", "", "Before you act: "), document.createTextNode(a.tip));
    extra.push(tip);
  }
  if (a.details.length) extra.push(expander(`What the quick check noticed (${a.details.length})`, list(a.details)));
  if (a.kind === "checking") {
    const n = el("p", "note");
    n.append(el("span", "spin"), el("span", "", "Asking the local AI on this computer…"));
    extra.push(n);
    if (r.slow) extra.push(el("p", "problem", "This is taking longer than usual. If your browser asks to allow "
      + "access to apps on this computer, choose Allow."));
  }
  return drawCard(k, extra);
}

function aiStatus(r) {
  if (r.alert.kind === "checking") return "";
  if (r.alert.known_sender) return "";
  if (!r.model) return "A clear warning sign was found, so the local AI was not needed.";
  if (r.model.problem) return "Local AI: not available.";
  return `Local AI: ${MODEL}, answered in ${r.model.latency_s.toFixed(1)} s.`;
}

function technical(r) {
  const items = [...r.rules.rule_reasons];
  items.push(`strong signals: ${r.rules.strong.join(", ") || "none"}`);
  if (r.auth) items.push(`authentication: ${r.auth.join("; ")}`);
  items.push(`sender confirmed by the mail server: ${r.senderKey || "no"}`);
  if (r.model) {
    items.push(r.model.problem ? `model error: ${r.model.error}`
      : `model probability of phishing: ${r.model.probability}`);
  }
  return expander("Technical details", list(items, "mono"));
}

export { KINDS, NOT_REACHABLE, PROBLEMS, PROVIDER, el, button, list, expander, confirmBox, drawCard, drawWhich,
  drawResult, aiStatus, technical };
