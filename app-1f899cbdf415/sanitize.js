// Displaying an email safely (NFR-7, D12): real phishing emails are shown in the demo page
// and when a saved .eml is checked. The HTML is rebuilt from an allow-list: no scripts,
// forms, frames or remote resources, and every link is removed; its text stays, with the
// real destination named in a tooltip. Images become a label. The result is then shown in
// a sandboxed iframe (no scripts) under a Content-Security-Policy that blocks all network
// access, so a mistake here still cannot load anything.
//
// DOMParser builds an inert document: nothing in it runs or loads while it is parsed.

const ALLOWED_TAGS = new Set(["b", "strong", "i", "em", "u", "s", "small", "big", "sub", "sup", "br", "hr", "p",
  "div", "span", "font", "center", "blockquote", "pre", "code", "ul", "ol", "li", "dl", "dt", "dd", "h1", "h2",
  "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "col", "colgroup"]);
const DROP_WITH_CONTENT = new Set(["script", "style", "title", "iframe", "object", "embed", "noscript", "template",
  "svg", "math", "form", "select", "textarea", "button", "head", "link", "meta", "base", "frameset", "frame"]);
const ALLOWED_ATTRS = new Set(["align", "valign", "width", "height", "colspan", "rowspan", "bgcolor", "color",
  "border", "cellpadding", "cellspacing", "face", "size", "dir", "style"]);
const BAD_CSS = /url\s*\(|expression\s*\(|@import|behavior\s*:|-moz-binding|image-set\s*\(/i;

export const FRAME_HEAD = `<!doctype html><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  body { font: 14px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif; color: #202124; margin: 16px; overflow-wrap: anywhere; }
  .plain { white-space: pre-wrap; font: inherit; margin: 0; }
  .defanged-link { color: #1a57c9; text-decoration: underline dotted; cursor: help; }
  .blocked-img { color: #80868b; font-size: 12px; }
  table { max-width: 100%; }
</style>`;

function hostOf(href) {
  try {
    return new URL(href).host || href.slice(0, 60);
  } catch {
    return href.slice(0, 60);
  }
}

function copy(node, out, doc) {
  for (const child of node.childNodes) {
    if (child.nodeType === Node.TEXT_NODE) {
      out.append(doc.createTextNode(child.textContent));
      continue;
    }
    if (child.nodeType !== Node.ELEMENT_NODE) continue;
    const tag = child.localName;
    if (DROP_WITH_CONTENT.has(tag)) continue;
    if (tag === "img") {
      const label = doc.createElement("span");
      label.className = "blocked-img";
      label.textContent = `[${(child.getAttribute("alt") || "image").slice(0, 40)}]`;
      out.append(label);
      continue;
    }
    let el;
    if (tag === "a") {
      el = doc.createElement("span");
      el.className = "defanged-link";
      const host = hostOf(child.getAttribute("href") || "");
      el.title = host ? `Link removed. It pointed to: ${host}` : "Link removed";
    } else if (ALLOWED_TAGS.has(tag)) {
      el = doc.createElement(tag);
      for (const { name, value } of child.attributes) {
        if (ALLOWED_ATTRS.has(name) && !(name === "style" && BAD_CSS.test(value))) el.setAttribute(name, value);
      }
    } else {
      copy(child, out, doc);   // unknown wrapper (html, body, custom tags): keep its content only
      continue;
    }
    copy(child, el, doc);
    out.append(el);
  }
}

/** Safe HTML for an email: from its HTML part if it has one, else its plain text. */
export function safeHtml(rawHtml, text) {
  const doc = document.implementation.createHTMLDocument("");
  const box = doc.createElement("div");
  if (rawHtml && rawHtml.trim()) {
    copy(new DOMParser().parseFromString(rawHtml, "text/html"), box, doc);
  } else {
    const pre = doc.createElement("pre");
    pre.className = "plain";
    pre.textContent = text || "";
    box.append(pre);
  }
  return box.innerHTML;
}
