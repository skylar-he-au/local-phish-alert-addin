// The task pane (MVP-PRD FR-1, FR-4-FR-7, FR-9; D16, D17). It checks the open message,
// puts the verdict in the message's notification bar, and shows the details here: the
// outcome first, then sender facts, reasons and the verification tip; the rest is behind
// expanders. When the pane is pinned it follows the selected message (spike R5). A
// settings view shows the local AI's status, manages the model and the trust list, and
// removes the add-in's data.
// Drawing is in view.js.

import { checkItem, showBar, CheckError } from "./check.js";
import { trusted, trust, untrust, removeAll } from "./store.js";
import { status, pullModel, deleteModel } from "./ollama.js";
import { NOT_REACHABLE, KINDS, el, button, confirmBox, drawCard, drawWhich, drawResult, aiStatus, technical } from "./view.js";
import { MODEL } from "./core/index.js";

const ERRORS = {
  no_message: ["Select an email to check it", ""],
  unreadable: ["Couldn't read this email", "Outlook did not give the add-in the full message, so it was not checked."],
  failed: ["Check failed", "Something went wrong while checking this email."],
};

const BUILD = new URL(import.meta.url).pathname.split("/").slice(-2, -1)[0];

const app = () => document.getElementById("app");

function render(parts) {
  app().replaceChildren(...parts.filter(Boolean));
}

function footerLinks() {
  const p = el("p", "links");
  p.append(button("Settings", () => showSettings(), "link"));
  return p;
}

function showResult(r) {
  if (view !== "main") return;
  const final = r.alert.kind !== "checking";
  const actions = {
    onTrust: async (key) => { await trust(key); run({ fresh: true }); },
    onUntrust: async (key) => { await untrust(key); run({ fresh: true }); },
  };
  render([drawWhich(r.subject), drawResult(r, actions), el("p", "status", aiStatus(r)),
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

// The demo inbox and saved-email check (FR-8) open in a large Outlook dialog, or a new
// window where dialogs are unavailable.
function openDemo() {
  const url = new URL("demo.html", document.baseURI).href;
  const ui = Office.context.ui;
  if (!ui || !ui.displayDialogAsync) return window.open(url, "_blank");
  ui.displayDialogAsync(url, { height: 85, width: 80, displayInIframe: true }, (r) => {
    if (r.status !== Office.AsyncResultStatus.Succeeded) window.open(url, "_blank");
  });
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
    section("Demo inbox and saved emails", el("p", "status", "Check the demo samples or any saved .eml file, with "
      + "links and images removed. Files are read on this computer only."), button("Open the demo inbox", openDemo)),
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
