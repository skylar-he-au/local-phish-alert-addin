// Spike task pane (MVP-PRD §11). It answers R1 (does the add-in load, and in which client),
// R4 (which message APIs work) and R3 (can this page reach Ollama on localhost).
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

async function showMessage() {
  clear("message");
  const item = Office.context.mailbox.item;
  if (!item) {
    row("message", "Message", "no message selected", "bad");
    return;
  }
  const from = item.from || {};
  row("message", "From", `${from.displayName || ""} <${from.emailAddress || "?"}>`);
  row("message", "Subject", item.subject || "(none)");

  // Full headers are what the rules need (SPF/DKIM/DMARC, Reply-To, Received).
  if (typeof item.getAllInternetHeadersAsync === "function") {
    const r = await asPromise((cb) => item.getAllInternetHeadersAsync(cb));
    if (r.status === Office.AsyncResultStatus.Succeeded) {
      const headers = r.value || "";
      const auth = headers.match(/^Authentication-Results:.*(?:\r?\n[ \t].*)*/gim) || [];
      row("message", "All headers", `yes (${headers.length} characters)`, "ok");
      row("message", "Authentication-Results", `${auth.length} header(s)`);
      if (auth.length) row("message", "Topmost", auth[0].replace(/\s+/g, " ").slice(0, 300));
    } else {
      row("message", "All headers", `failed: ${r.error && r.error.message}`, "bad");
    }
  } else {
    row("message", "All headers", "API not available", "bad");
  }

  // Raw MIME (Mailbox 1.14) would let the core reuse the evaluated parser unchanged.
  if (typeof item.getAsFileAsync === "function") {
    const r = await asPromise((cb) => item.getAsFileAsync(cb));
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
  showMessage();
  // R5: fires when a pinned pane moves to another message (needs pinning in the manifest).
  if (Office.context.mailbox.addHandlerAsync) {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, showMessage);
  }
});
