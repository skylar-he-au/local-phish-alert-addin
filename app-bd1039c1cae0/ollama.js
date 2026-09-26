// Status and model management for the settings view (FR-7), through Ollama's own API on
// localhost (NFR-1). Nothing here loads or runs the model: /api/version and /api/tags
// only answer questions, /api/pull downloads the model, /api/delete removes it.

import { OLLAMA_HOST, MODEL } from "./core/index.js";

async function call(path, { method = "GET", body, timeoutMs = 5000, signal } = {}) {
  const ctl = new AbortController();
  const timer = timeoutMs ? setTimeout(() => ctl.abort(), timeoutMs) : null;
  if (signal) signal.addEventListener("abort", () => ctl.abort());
  try {
    return await fetch(`${OLLAMA_HOST}${path}`, {
      method, signal: ctl.signal,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * {reachable, version, hasModel}. The browser hides why a request failed: Ollama not
 * running, Ollama refusing this add-in's origin, and a blocked local-network request
 * all look the same, so they are reported together as not reachable.
 */
export async function status() {
  try {
    const v = await call("/api/version");
    if (!v.ok) return { reachable: false, version: null, hasModel: false };
    const { version } = await v.json();
    const t = await call("/api/tags");
    const { models = [] } = t.ok ? await t.json() : {};
    const hasModel = models.some((m) => m.name === MODEL || m.model === MODEL);
    return { reachable: true, version: version || "?", hasModel };
  } catch {
    return { reachable: false, version: null, hasModel: false };
  }
}

/** Download the model, reporting {status, completed, total}. Resolves when done. */
export async function pullModel(onProgress, signal) {
  const res = await call("/api/pull", { method: "POST", body: { model: MODEL, stream: true }, timeoutMs: 0, signal });
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      if (msg.error) throw new Error(msg.error);
      onProgress(msg);
      if (msg.status === "success") return;
    }
  }
  throw new Error("the download stopped before it finished");
}

/** Delete the model from this computer (for removal, FR-7). */
export async function deleteModel() {
  const res = await call("/api/delete", { method: "DELETE", body: { model: MODEL } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}
