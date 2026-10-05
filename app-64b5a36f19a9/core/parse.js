// Parse a raw email into the fields the rules and the model use.
// Port of pipeline/parser.py; the field names are the same.

import { WS, htmlUnescape, decode, strip } from "./py.js";
import { parseMessage } from "./mime.js";

const ZERO_WIDTH = /[​‌‍‎‏﻿⁠­]/g;
const TAG_RE = /<[^>]+>/g;
const HREF_RE = new RegExp(`href[${WS}]*=[${WS}]*["']([^"']+)["']`, "giu");
const URL_RE = new RegExp(`https?://[^${WS}<>"')]+`, "giu");
const ANCHOR_RE = new RegExp(`<a(?![\\p{L}\\p{N}_])[^>]*href[${WS}]*=[${WS}]*["']([^"']+)["'][^>]*>(.*?)</a>`, "gisu");

/** Undo the evasion tricks that break both keyword rules and the model (parser._clean). */
export function clean(text) {
  if (!text) return "";
  text = htmlUnescape(text);
  text = text.replace(ZERO_WIDTH, "");
  text = text.normalize("NFKC");
  return strip(text.replace(/[ \t]+/g, " "));
}

function decodeText(payload, charset) {
  return decode(payload, charset || "utf-8", "replace");
}

/** Prefer text/plain; fall back to text/html with tags stripped (parser._body). */
function body(msg) {
  const plain = [], htm = [];
  if (msg.isMultipart()) {
    for (const part of msg.walk()) {
      if (part.getContentMaintype() === "multipart") continue;
      if (part.getFilename()) continue;
      const ct = part.getContentType();
      let txt;
      try {
        const payload = part.getPayloadBytes();
        if (payload === null) continue;
        txt = decodeText(payload, part.getContentCharset());
      } catch {
        continue;
      }
      if (ct === "text/plain") plain.push(txt);
      else if (ct === "text/html") htm.push(txt);
    }
  } else {
    let txt;
    try {
      const payload = msg.getPayloadBytes();
      txt = payload && payload.length ? decodeText(payload, msg.getContentCharset()) : "";
    } catch {
      txt = "";
    }
    (msg.getContentType() === "text/html" ? htm : plain).push(txt);
  }
  const rawHtml = htm.join("\n");
  const text = plain.join("\n") || rawHtml.replace(TAG_RE, " ");
  return [clean(text), rawHtml];
}

function attachments(msg) {
  const out = [];
  if (msg.isMultipart()) {
    for (const part of msg.walk()) {
      const fn = part.getFilename();
      if (fn) out.push(clean(fn));
    }
  }
  return out;
}

/**
 * Parse raw RFC 822 bytes (a Uint8Array) into the fields used by the rules and the
 * prompt. Same result as pipeline/parser.py parse_bytes() for the same bytes.
 */
export function parseEmail(bytes, path = "") {
  const msg = parseMessage(bytes);
  const hdr = (name) => {
    try { return clean(msg.get(name) || ""); } catch { return ""; }
  };
  // every value of a header, top first (for headers that a message carries several times)
  const all = (name) => msg.headers.filter(([k]) => k.toLowerCase() === name.toLowerCase())
    .map(([, v]) => { try { return clean(String(v)); } catch { return ""; } });
  const [text, rawHtml] = body(msg);
  const links = [...text.matchAll(URL_RE)].map((m) => m[0]).concat([...rawHtml.matchAll(HREF_RE)].map((m) => m[1]));
  const anchors = [...rawHtml.matchAll(ANCHOR_RE)].map((m) => [clean(m[2].replace(TAG_RE, "")), m[1]]);
  return {
    path: String(path),
    subject: hdr("Subject"),
    from: hdr("From"),
    reply_to: hdr("Reply-To"),
    return_path: hdr("Return-Path"),
    auth_results: hdr("Authentication-Results"),
    received_spf: hdr("Received-SPF"),
    dkim_signature: hdr("DKIM-Signature"),
    // product only (not in the Python pipeline): the organisation gateway's sealed checks (D25)
    arc_auth_results: all("ARC-Authentication-Results"),
    body: text,
    raw_html: rawHtml,
    links: [...new Set(links)].slice(0, 50),
    anchors: anchors.slice(0, 50),
    attachments: attachments(msg),
  };
}
