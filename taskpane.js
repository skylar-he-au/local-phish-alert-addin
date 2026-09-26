// Spike task pane (MVP-PRD §11). It answers R1 (does the add-in load, and in which client),
// R4 (which message APIs work), R5 (does the pane follow the selected message), the
// notification-bar banner (FR-4) and R3 (can this page reach Ollama on localhost).
// Nothing leaves this page except the Ollama request, which goes to localhost only.
"use strict";

const OLLAMA = "http://localhost:11434";

function row(table, label, value, cls) {
  const tr = document.createElement("tr");
  const a = document.createElement("td");
  const b = document.createElement("td");
  a.textContent = label;
  b.textContent = value;
  if (cls) b.className = cls;
  tr.append(a, b);
  document.getElementById(table).append(tr);
}

function clear(table) {
  document.getElementById(table).replaceChildren();
}

function asPromise(call) {
  return new Promise((resolve) => call((r) => resolve(r)));
}

function showClient() {
  clear("client");
  const d = Office.context.diagnostics || {};
  row("client", "Host", d.host || "?");
  row("client", "Platform", d.platform || "?");
  row("client", "Version", d.version || "?");
  const supported = [];
  for (let v = 1; v <= 15; v++) {
    if (Office.context.requirements.isSetSupported("Mailbox", `1.${v}`)) supported.push(`1.${v}`);
  }
  row("client", "Mailbox API", supported.length ? `up to ${supported[supported.length - 1]}` : "none");
}

// R5 evidence: how the pane learned that the selected message changed.
const follow = { events: 0, polls: 0, ticks: 0, handler: "registering…", lastId: null, lastVia: "first load" };
// Each check gets a number; a check that finishes after a newer one has started drops its
// results, so the table never mixes two messages.
let generation = 0;

function showFollow() {
  clear("follow");
  row("follow", "ItemChanged handler", follow.handler, follow.handler === "registered" ? "ok" : "bad");
  row("follow", "ItemChanged events", String(follow.events));
  row("follow", "Changes found by polling", String(follow.polls), follow.polls ? "bad" : "");
  row("follow", "Last update", `${follow.lastVia} at ${follow.lastAt || "?"}`);
  row("follow", "Pane heartbeat", `${follow.ticks} checks (keeps rising while the pane runs)`);
}

function currentId(item) {
  return item ? item.itemId || item.internetMessageId || item.subject || "?" : null;
}

// The banner on the message itself (FR-4 notification bar). Replaced, not added, so a
// message never collects duplicates.
function showBanner(item, gen) {
  if (!item || !item.notificationMessages) {
    row("message", "Banner on message", "API not available", "bad");
    return;
  }
  item.notificationMessages.replaceAsync("lpa", {
    type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
    message: "Local Phish Alert (spike) read this email on this computer. No verdict yet.",
    icon: "Icon.16",
    persistent: false,
  }, (r) => {
    if (gen !== generation) return;
    row("message", "Banner on message", r.status === Office.AsyncResultStatus.Succeeded
      ? "shown (look above the email)" : `failed: ${r.error && r.error.message}`,
      r.status === Office.AsyncResultStatus.Succeeded ? "ok" : "bad");
  });
}

// R9: the authentication headers in full, and nothing else from the message.
const AUTH_HEADERS = /^(Authentication-Results|ARC-Authentication-Results|Received-SPF|X-MS-Exchange-Organization-AuthAs|X-MS-Exchange-Organization-AuthSource):.*(?:\r?\n[ \t].*)*/gim;

function showAuthHeaders(headers) {
  let box = document.getElementById("auth");
  if (!box) {
    // taskpane.html may still be the cached copy without this section
    const h = document.createElement("h2");
    h.textContent = "Authentication headers (R9)";
    box = document.createElement("div");
    box.id = "auth";
    document.getElementById("showing").after(h, box);
  }
  box.replaceChildren();
  const add = (tag, text, bold) => {
    const el = document.createElement(tag);
    el.textContent = text;
    el.style.cssText = "margin:4px 0;white-space:pre-wrap;word-break:break-all;font-size:12px;"
      + (bold ? "font-weight:600;" : "font-family:ui-monospace,Menlo,monospace;");
    box.append(el);
  };
  const compauth = [...headers.matchAll(/compauth=(\w+)(?:\s+reason=(\w+))?/gi)].map((m) => m[1] + (m[2] ? ` reason=${m[2]}` : ""));
  add("p", `compauth: ${compauth.join("; ") || "(none)"}`, true);
  (headers.match(AUTH_HEADERS) || []).forEach((h, i) => {
    const text = h.replace(/\s+/g, " ");
    const name = text.slice(0, text.indexOf(":"));
    add("p", `${i + 1}. ${name}`, true);
    add("pre", text.slice(name.length + 1).trim());
  });
}

async function showMessage(via) {
  const gen = ++generation;
  clear("message");
  const item = Office.context.mailbox.item;
  follow.lastId = currentId(item);
  follow.lastVia = typeof via === "string" ? via : "ItemChanged event";
  follow.lastAt = new Date().toLocaleTimeString();
  showFollow();
  const showing = document.getElementById("showing");
  if (!item) {
    showing.textContent = "No message selected.";
    row("message", "Message", "no message selected", "bad");
    return;
  }
  showing.textContent = `Checking: ${item.subject || "(no subject)"}`;
  const from = item.from || {};
  row("message", "From", `${from.displayName || ""} <${from.emailAddress || "?"}>`);
  row("message", "Subject", item.subject || "(none)");
  showBanner(item, gen);

  // Full headers are what the rules need (SPF/DKIM/DMARC, Reply-To, Received).
  if (typeof item.getAllInternetHeadersAsync === "function") {
    const r = await asPromise((cb) => item.getAllInternetHeadersAsync(cb));
    if (gen !== generation) return;
    if (r.status === Office.AsyncResultStatus.Succeeded) {
      const headers = r.value || "";
      const auth = headers.match(/^Authentication-Results:.*(?:\r?\n[ \t].*)*/gim) || [];
      row("message", "All headers", `yes (${headers.length} characters)`, "ok");
      row("message", "Authentication-Results", `${auth.length} header(s)`);
      if (auth.length) row("message", "Topmost", auth[0].replace(/\s+/g, " ").slice(0, 300));
      showAuthHeaders(headers);
    } else {
      row("message", "All headers", `failed: ${r.error && r.error.message}`, "bad");
    }
  } else {
    row("message", "All headers", "API not available", "bad");
  }

  // Raw MIME (Mailbox 1.14) would let the core reuse the evaluated parser unchanged.
  if (typeof item.getAsFileAsync === "function") {
    const r = await asPromise((cb) => item.getAsFileAsync(cb));
    if (gen !== generation) return;
    if (r.status === Office.AsyncResultStatus.Succeeded) {
      row("message", "Raw MIME", `yes (${(r.value || "").length} base64 characters)`, "ok");
    } else {
      row("message", "Raw MIME", `failed: ${r.error && r.error.message}`, "bad");
    }
  } else {
    row("message", "Raw MIME", "API not available", "bad");
  }
}

async function checkOllama() {
  clear("ollamaResult");
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await fetch(`${OLLAMA}/api/tags`, { signal: ctl.signal });
    const body = await res.json();
    const names = (body.models || []).map((m) => m.name);
    row("ollamaResult", "Reachable", `yes (HTTP ${res.status})`, "ok");
    row("ollamaResult", "Models", names.length ? names.join(", ") : "none installed");
  } catch (e) {
    // The browser hides the reason: Ollama not running, CORS refusal and mixed-content
    // blocking all look the same here. The browser console says which one it was.
    row("ollamaResult", "Reachable", `no (${e.name}: ${e.message})`, "bad");
  } finally {
    clearTimeout(timer);
  }
}

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) {
    document.getElementById("status").textContent = "Not running inside Outlook. Open this pane from an email in Outlook.";
    return;
  }
  document.getElementById("status").textContent = `Loaded in ${info.host} on ${info.platform || "?"}.`;
  document.getElementById("ollama").addEventListener("click", checkOllama);
  showClient();
  showMessage("first load");
  // R5: ItemChanged fires when a pinned pane moves to another message (needs pinning in
  // the manifest). The poll is a spike-only check that shows whether the pane can be
  // left showing a message other than the selected one when the event does not fire.
  Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => {
    follow.events++;
    showMessage("ItemChanged event");
  }, (r) => {
    follow.handler = r.status === Office.AsyncResultStatus.Succeeded
      ? "registered" : `refused: ${r.error && (r.error.code + " " + r.error.message)}`;
    showFollow();
  });
  setInterval(() => {
    follow.ticks++;
    showFollow();
    const id = currentId(Office.context.mailbox.item);
    if (id !== follow.lastId) {
      follow.polls++;
      showMessage("polling");
    }
  }, 1500);
});
