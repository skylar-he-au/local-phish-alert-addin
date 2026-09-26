// The task pane (MVP-PRD FR-1, FR-4-FR-7, FR-9; D16, D17). It checks the open message,
// puts the verdict in the message's notification bar, and shows the details here: the
// outcome first, then sender facts, reasons and the verification tip; the rest is behind
// expanders. When the pane is pinned it follows the selected message (spike R5). A
// settings view shows the local AI's status, manages the model and the trust list, and
// removes the add-in's data.
//
// Everything is drawn with textContent, never innerHTML: reasons contain text taken from
// the email, and an email must not be able to inject markup into the pane.

import { checkItem, showBar, CheckError } from "./check.js";
import { trusted, trust, untrust, removeAll } from "./store.js";
import { status, pullModel, deleteModel } from "./ollama.js";
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

const ERRORS = {
  no_message: ["Select an email to check it", ""],
  unreadable: ["Couldn't read this email", "Outlook did not give the add-in the full message, so it was not checked."],
  failed: ["Check failed", "Something went wrong while checking this email."],
};

const PROVIDER = "Your mail server";
const BUILD = new URL(import.meta.url).pathname.split("/").slice(-2, -1)[0];

const app = () => document.getElementById("app");

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

function render(parts) {
  app().replaceChildren(...parts.filter(Boolean));
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

// FR-6: offered only on a warning raised by the AI alone, for a sender the mail server confirmed.
function trustOffer(r) {
  const key = r.alert.trust_offer;
  const row = el("div", "trust");
  const ask = () => row.replaceChildren(confirmBox(
    `Only do this if you know ${key} and expected this email. Future emails that ${PROVIDER.toLowerCase()} `
    + `confirms really come from ${key} will no longer be flagged by the local AI alone. Clear warning signs, `
    + "like dangerous attachments, are still shown. You can undo this in Settings.",
    `Trust ${key}`,
    async () => {
      try {
        await trust(key);
        run({ fresh: true });
      } catch (e) {
        row.replaceChildren(el("p", "problem", `Could not save: ${e.message}`));
      }
    },
    () => row.replaceChildren(offer())));
  const offer = () => {
    const p = el("p");
    p.append(el("span", "label", "Not a scam? "), button(`I know ${key}`, ask, "link"));
    return p;
  };
  row.append(offer());
  return row;
}

function knownLine(known) {
  const p = el("p", "known");
  p.append(document.createTextNode(`You trust ${known.key}, so the local AI was not asked. `));
  p.append(button("Stop trusting", async () => {
    await untrust(known.key);
    run({ fresh: true });
  }, "link"));
  return p;
}

function drawResult(r) {
  const a = r.alert;
  const k = KINDS[a.kind] || { look: "neutral", title: `Result: ${a.kind}`, advice: "" };
  const extra = [];
  if (a.kind === "danger" && a.sender && a.sender.address) extra.push(senderLine(a.sender));
  if (a.reasons.length) extra.push(list(a.reasons, "reasons"));
  if (a.trust_offer) extra.push(trustOffer(r));
  if (a.known_sender) extra.push(knownLine(a.known_sender));
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
  items.push(`sender confirmed by the mail server: ${r.senderKey || "no"}`);
  if (r.model) {
    items.push(r.model.problem ? `model error: ${r.model.error}`
      : `model probability of phishing: ${r.model.probability}`);
  }
  return expander("Technical details", list(items, "mono"));
}

function footerLinks() {
  const p = el("p", "links");
  p.append(button("Settings", () => showSettings(), "link"));
  return p;
}

function showResult(r) {
  if (view !== "main") return;
  const final = r.alert.kind !== "checking";
  render([drawWhich(r.subject), drawResult(r), el("p", "status", aiStatus(r)),
    final ? button("Check again", () => run({ fresh: true }), "again") : null,
    final ? technical(r) : null, footerLinks()]);
}

function showError(err, subject) {
  if (view !== "main") return;
  const [title, advice] = ERRORS[err.code] || ERRORS.failed;
  const detail = err.code === "unreadable" && err.message !== "unreadable" ? el("p", "problem", err.message) : null;
  render([subject ? drawWhich(subject) : null,
    drawCard({ look: "neutral", title, advice }, detail ? [detail] : []),
    err.code === "no_message" ? null : button("Check again", () => run({ fresh: true }), "again"), footerLinks()]);
}

// ---- following the selected message ----

let view = "main";
let generation = 0;
const results = new Map();   // itemId -> final result; in memory only, gone when the pane closes

async function run({ fresh = false } = {}) {
  const gen = ++generation;
  const item = Office.context.mailbox.item;
  if (!item) return showError(new CheckError("no_message"));
  const id = item.itemId || null;
  if (fresh) results.clear();   // the trust list may have changed
  if (id && results.has(id)) {
    const r = results.get(id);
    showResult(r);
    showBar(item, r);
    return;
  }
  if (view === "main") render([drawWhich(item.subject), drawCard(KINDS.checking), footerLinks()]);
  showBar(item, { alert: { kind: "checking" } });
  try {
    const r = await checkItem(item, {
      trusted: trusted(),
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

// ---- settings (FR-6, FR-7, R6) ----

function section(title, ...parts) {
  const s = el("section", "set");
  s.append(el("h2", "", title), ...parts.filter(Boolean));
  return s;
}

function aiSection() {
  const box = el("div");
  const draw = async () => {
    box.replaceChildren(el("p", "status", "Checking…"));
    const st = await status();
    const parts = [];
    if (!st.reachable) {
      parts.push(el("p", "bad", "Ollama: not reachable"), el("p", "problem", NOT_REACHABLE));
    } else {
      parts.push(el("p", "ok", `Ollama: running (version ${st.version})`));
      parts.push(el("p", st.hasModel ? "ok" : "bad", `Model ${MODEL}: ${st.hasModel ? "downloaded" : "not downloaded"}`));
      parts.push(st.hasModel ? deleteRow() : downloadRow());
    }
    parts.push(button("Check again", draw, "again"));
    box.replaceChildren(...parts);
  };
  const downloadRow = () => {
    const row = el("div");
    row.append(button(`Download ${MODEL} (about 2 GB)`, async () => {
      const bar = el("progress");
      const label = el("p", "status", "Starting…");
      row.replaceChildren(label, bar);
      try {
        await pullModel((m) => {
          label.textContent = m.status;
          if (m.total) { bar.max = m.total; bar.value = m.completed || 0; }
        });
        draw();
      } catch (e) {
        row.replaceChildren(el("p", "problem", `Download failed: ${e.message}`), downloadRow());
      }
    }, "primary"));
    return row;
  };
  const deleteRow = () => {
    const row = el("div");
    const ask = () => row.replaceChildren(confirmBox(
      `Delete ${MODEL} from this computer? This frees about 2 GB. Until you download it again, emails get only a basic check.`,
      "Delete model",
      async () => {
        try {
          await deleteModel();
          draw();
        } catch (e) {
          row.replaceChildren(el("p", "problem", `Could not delete: ${e.message}`));
        }
      },
      () => row.replaceChildren(button("Delete model", ask))));
    row.append(button("Delete model", ask));
    return row;
  };
  draw();
  return box;
}

function trustSection() {
  const box = el("div");
  const draw = () => {
    const keys = [...trusted()].sort();
    if (!keys.length) {
      box.replaceChildren(el("p", "status", "None yet. You can trust a sender from a warning that only the local AI "
        + "raised, if your mail server confirmed who sent it."));
      return;
    }
    const ul = el("ul", "trusted");
    for (const k of keys) {
      const li = el("li");
      li.append(el("span", "", k), button("Remove", async () => {
        await untrust(k);
        results.clear();
        draw();
      }, "link"));
      ul.append(li);
    }
    box.replaceChildren(el("p", "status", "The local AI does not warn on its own about emails your mail server "
      + "confirms come from these senders. Clear warning signs are still shown."), ul);
  };
  draw();
  box.redraw = draw;
  return box;
}

function dataSection(onRemoved) {
  const box = el("div");
  const draw = () => {
    box.replaceChildren(
      el("p", "status", "This add-in stores only your trusted senders, in your own mailbox. No email content is stored "
        + "or sent anywhere except to the local AI on this computer. Removing the add-in does not delete this list, "
        + "so remove your data first."),
      button("Remove all my data", () => box.replaceChildren(confirmBox(
        "Delete your trusted senders? This cannot be undone.", "Remove all my data",
        async () => {
          try {
            await removeAll();
            results.clear();
            onRemoved();
            box.replaceChildren(el("p", "ok", "Your data was removed."));
          } catch (e) {
            box.replaceChildren(el("p", "problem", `Could not remove: ${e.message}`));
          }
        }, draw))));
  };
  draw();
  return box;
}

function showSettings() {
  view = "settings";
  const trustBox = trustSection();
  render([
    button("‹ Back to the email", () => { view = "main"; run(); }, "link back"),
    el("h1", "page", "Settings"),
    section("Local AI", aiSection()),
    section("Trusted senders", trustBox),
    section("Your data", dataSection(() => trustBox.redraw())),
    section("About", el("p", "status", `Local Phish Alert, build ${BUILD}. Checks run on this computer; `
      + "the add-in's files come from GitHub Pages, which never receives email content.")),
  ]);
}

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) {
    render([drawCard({ look: "neutral", title: "Open this pane from an email in Outlook", advice: "" })]);
    return;
  }
  run();
  Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => run());
});
