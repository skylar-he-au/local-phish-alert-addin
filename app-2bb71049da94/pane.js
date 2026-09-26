// The task pane (MVP-PRD FR-1, FR-4, FR-5, FR-9; D16, D17). It checks the open message,
// puts the verdict in the message's notification bar, and shows the details here: the
// outcome first, then sender facts, reasons and the verification tip; the rest is behind
// expanders. When the pane is pinned it follows the selected message (spike R5).
//
// Everything is drawn with textContent, never innerHTML: reasons contain text taken from
// the email, and an email must not be able to inject markup into the pane.

import { checkItem, showBar, CheckError } from "./check.js";
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
const PROBLEMS = {
  not_reachable: "The local AI could not be reached. Check that Ollama is running on this computer, "
    + "that it allows this add-in, and that the browser may connect to apps on this computer.",
  origin_refused: `Ollama is running but refused this add-in. Allow ${location.origin} in Ollama's `
    + "OLLAMA_ORIGINS setting and restart Ollama.",
  model_missing: `Ollama is running, but the model ${MODEL} is not downloaded.`,
  timeout: "The local AI did not answer in time.",
  model_error: "The local AI reported an error.",
};

const ERRORS = {
  no_message: ["Select an email to check it", ""],
  unreadable: ["Couldn't read this email", "Outlook did not give the add-in the full message, so it was not checked."],
  failed: ["Check failed", "Something went wrong while checking this email."],
};

const app = () => document.getElementById("app");

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
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

// ---- drawing ----

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

function drawResult(r) {
  const a = r.alert;
  const k = KINDS[a.kind] || { look: "neutral", title: `Result: ${a.kind}`, advice: "" };
  const extra = [];
  if (a.kind === "danger" && a.sender && a.sender.address) {
    const p = el("p", "sender");
    p.append(el("span", "label", "Sent from "), el("strong", "", a.sender.address));
    extra.push(p);
  }
  if (a.reasons.length) extra.push(list(a.reasons, "reasons"));
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
  }
  return drawCard(k, extra);
}

function aiStatus(r) {
  if (r.alert.kind === "checking") return "";
  if (!r.model) return "A clear warning sign was found, so the local AI was not needed.";
  if (r.model.problem) return "Local AI: not available.";
  return `Local AI: ${MODEL}, answered in ${r.model.latency_s.toFixed(1)} s.`;
}

function technical(r) {
  const items = [...r.rules.rule_reasons];
  items.push(`strong signals: ${r.rules.strong.join(", ") || "none"}`);
  if (r.model) {
    items.push(r.model.problem ? `model error: ${r.model.error}`
      : `model probability of phishing: ${r.model.probability}`);
  }
  return expander("Technical details", list(items, "mono"));
}

function render(parts) {
  app().replaceChildren(...parts.filter(Boolean));
}

function againButton() {
  const b = el("button", "again", "Check again");
  b.type = "button";
  b.addEventListener("click", () => run({ fresh: true }));
  return b;
}

function showResult(r) {
  const final = r.alert.kind !== "checking";
  render([drawWhich(r.subject), drawResult(r), el("p", "status", aiStatus(r)),
    final ? againButton() : null, final ? technical(r) : null]);
}

function showError(err, subject) {
  const [title, advice] = ERRORS[err.code] || ERRORS.failed;
  const detail = err.code === "unreadable" && err.message !== "unreadable" ? el("p", "problem", err.message) : null;
  render([subject ? drawWhich(subject) : null,
    drawCard({ look: "neutral", title, advice }, detail ? [detail] : []),
    err.code === "no_message" ? null : againButton()]);
}

// ---- following the selected message ----

let generation = 0;
const results = new Map();   // itemId -> final result; in memory only, gone when the pane closes

async function run({ fresh = false } = {}) {
  const gen = ++generation;
  const item = Office.context.mailbox.item;
  if (!item) return showError(new CheckError("no_message"));
  const id = item.itemId || null;
  if (!fresh && id && results.has(id)) {
    const r = results.get(id);
    showResult(r);
    showBar(item, r);
    return;
  }
  render([drawWhich(item.subject), drawCard(KINDS.checking)]);
  showBar(item, { alert: { kind: "checking" } });
  try {
    const r = await checkItem(item, {
      onUpdate: (u) => {
        if (gen !== generation) return;
        showResult(u);
      },
    });
    // a basic-check-only result is not kept, so the email is checked again once the AI is back
    if (id && !(r.model && r.model.problem)) results.set(id, r);
    // The bar belongs to its message, so it is set even if the user has moved on.
    showBar(item, r);
    if (gen === generation) showResult(r);
  } catch (err) {
    const e = err instanceof CheckError ? err : new CheckError("failed", String(err && err.message));
    showBar(item, e);
    if (gen === generation) showError(e, item.subject);
  }
}

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) {
    render([drawCard({ look: "neutral", title: "Open this pane from an email in Outlook", advice: "" })]);
    return;
  }
  run();
  Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => run());
});
