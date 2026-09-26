// Local Phish Alert detection core (MVP-PRD §7, decision D3).
//
// One JavaScript implementation, used by the Outlook add-in in the browser and by the
// evaluation under Node.js, so the reported accuracy is the product's accuracy.
// It has no dependencies and makes no network calls except classify(), which talks to
// Ollama on localhost only.

export { parseEmail, clean } from "./parse.js";
export { runRules, rAuth, AUTH_POLICIES, authenticatedSender, brandImpersonation, TRUSTED_AUTHSERV } from "./rules.js";
export { decide, alert, pendingAlert, verifyTip, modelView, T_MODEL } from "./fusion.js";
export { buildPrompt, ollamaRequest, parseModelAnswer, classify, MODEL, OLLAMA_HOST } from "./prompt.js";
// Code-point string helpers the add-in needs (Python slicing semantics).
export { cpSlice, cpLen } from "./py.js";
