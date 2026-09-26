// The demo inbox and the saved-email check (MVP-PRD FR-8, M7, S6b). The user picks the
// demo folder (demo/emails in the project) or any saved .eml files; each email is checked
// with the same code as in Outlook and shown with links and images removed. Files are read
// in the browser and never uploaded; as everywhere, only Ollama on localhost is contacted.
//
// The page works on its own in a browser and as a dialog opened from the pane's Settings
// (demo.html loads Office.js for that). It has no access to the mailbox, so the trust list
// does not apply here.

import { checkBytes } from "./check.js";
import { safeHtml, FRAME_HEAD } from "./sanitize.js";
import { el, drawResult, drawWhich, aiStatus, technical, button } from "./view.js";
import { parseEmail } from "./core/index.js";

const $ = (id) => document.getElementById(id);
let emails = [];      // {name, bytes, shown, note, result}
let notes = {};
let current = null;
let generation = 0;

// The team's BEC files end each line with CR CR LF, so their headers stop after the first
// line. They are checked as they are, as in the evaluation, but displayed from a copy with
// normal line ends so that the subject and sender show.
function displayCopy(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 13 && bytes[i + 2] === 10) { out.push(10); i += 2; } else out.push(bytes[i]);
  }
  return parseEmail(Uint8Array.from(out));
}

async function load(files) {
  const list = [...files];
  const notesFile = list.find((f) => f.name === "notes.json");
  if (notesFile) {
    try { notes = JSON.parse(await notesFile.text()); } catch { notes = {}; }
  }
  const emlFiles = list.filter((f) => /\.eml$/i.test(f.name)).sort((a, b) => a.name.localeCompare(b.name));
  for (const f of emlFiles) {
    const bytes = new Uint8Array(await f.arrayBuffer());
    emails = emails.filter((e) => e.name !== f.name);
    emails.push({ name: f.name, bytes, shown: displayCopy(bytes), note: notes[f.name] || null, result: null });
  }
  $("hint").textContent = emlFiles.length ? "" : "No .eml files were found there.";
  renderList();
  if (emlFiles.length) open(emails.find((e) => e.name === emlFiles[0].name));
}

function senderName(from) {
  return (from.split("<")[0].replace(/"/g, "").trim() || from || "(unknown sender)");
}

function renderList() {
  const ul = $("list");
  ul.replaceChildren();
  for (const e of emails) {
    const li = el("li");
    li.classList.toggle("sel", e === current);
    const b = button("", () => open(e));
    b.append(el("div", "from", senderName(e.shown.from)), el("div", "subj", e.shown.subject || "(no subject)"),
      el("div", "prev", e.shown.body.replace(/\s+/g, " ").trim().slice(0, 110)));
    if (e.result && e.result.alert.kind !== "checking") b.append(el("div", `tag ${e.result.alert.kind}`, {
      danger: "Warning", safe: "No warning signs", unchecked: "Basic check only" }[e.result.alert.kind] || ""));
    li.append(b);
    ul.append(li);
  }
  $("empty").hidden = emails.length > 0 && current !== null;
}

function showResult(e) {
  const r = e.result;
  const final = r.alert.kind !== "checking";
  $("result").replaceChildren(drawResult(r), el("p", "status", aiStatus(r)),
    final ? button("Check again", () => { e.result = null; open(e); }, "again") : "", final ? technical(r) : "");
}

async function open(e) {
  const gen = ++generation;
  current = e;
  renderList();
  $("msg").hidden = false;
  $("subject").textContent = e.shown.subject || "(no subject)";
  $("from").textContent = e.shown.from;
  $("note").hidden = !e.note;
  if (e.note) $("note").textContent = `What this shows: ${e.note.note} Expected: ${e.note.expected}. Source: ${e.note.source}.`;
  $("body").srcdoc = FRAME_HEAD + safeHtml(e.shown.raw_html, e.shown.body);
  // a basic-check-only result is not kept, so the email is checked again once the AI is back
  const r = e.result;
  if (r && r.alert.kind !== "checking" && !(r.model && r.model.problem)) return showResult(e);
  $("result").replaceChildren(drawWhich(e.shown.subject));
  try {
    e.result = await checkBytes(e.bytes, {
      onUpdate: (u) => { e.result = u; if (gen === generation) showResult(e); },
    });
  } catch (err) {
    e.result = null;
    if (gen === generation) $("result").replaceChildren(el("p", "problem", `Could not check this email: ${err.message}`));
    return;
  }
  if (gen === generation) showResult(e);
  renderList();
}

$("folder").addEventListener("change", (ev) => load(ev.target.files));
$("files").addEventListener("change", (ev) => load(ev.target.files));
$("presenter").addEventListener("change", (ev) => document.body.classList.toggle("presenter", ev.target.checked));
for (const t of ["dragover", "drop"]) {
  document.addEventListener(t, (ev) => {
    ev.preventDefault();
    if (t === "drop") load(ev.dataTransfer.files);
  });
}
