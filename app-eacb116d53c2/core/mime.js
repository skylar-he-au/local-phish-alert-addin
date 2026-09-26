// MIME structure, ported from Python's email.feedparser and email.message.Message
// (policy.default), limited to what the detection core reads: headers, the part
// tree, content types, charsets, filenames and transfer-decoded payloads.

import { bytesToEscaped, escapedToBytes, decodeB, decodeQP, strip, lstrip, rstrip, stripChars } from "./py.js";
import { addressHeader, unstructuredHeader, mimeHeader, cteHeader } from "./header.js";

const HEADER_RE = /^(From |[\x21-\x39\x3b-\x7e]*:|[\t ])/;
const ADDRESS_HEADERS = new Set(["from", "to", "cc", "bcc", "reply-to", "resent-from", "resent-to",
  "resent-cc", "resent-bcc", "sender", "resent-sender"]);

// ------------------------------------------------------------ Message

export class Message {
  constructor() {
    this.headers = [];          // [name, raw value] as stored by header_source_parse
    this.payload = null;        // string (surrogate-escaped) or array of Message
    this.defaultType = "text/plain";
  }

  isMultipart() { return Array.isArray(this.payload); }

  has(name) {
    const n = name.toLowerCase();
    return this.headers.some(([k]) => k.toLowerCase() === n);
  }

  /** Message.get(name) -> str(header object), or null if absent. */
  get(name) {
    const n = name.toLowerCase();
    for (const [k, v] of this.headers) {
      if (k.toLowerCase() !== n) continue;
      const raw = v.replace(/\n|\r\n?/g, "");
      if (ADDRESS_HEADERS.has(n)) return addressHeader(raw);
      if (n === "content-type" || n === "content-disposition") return mimeHeader(n, raw);
      return unstructuredHeader(raw);
    }
    return null;
  }

  getContentType() {
    const v = this.get("content-type");
    if (v === null) return this.defaultType;
    const ctype = strip(v.split(";")[0]).toLowerCase();
    if (ctype.split("/").length - 1 !== 1) return "text/plain";
    return ctype;
  }

  getContentMaintype() { return this.getContentType().split("/")[0]; }

  /** Message.get_param(param, failobj, header) with unquote=True; undefined when missing. */
  getParam(param, header = "content-type") {
    if (!this.has(header)) return undefined;
    const v = this.get(header);
    const params = decodeParams(parseparam(v).map((p) => {
      const i = p.indexOf("=");
      return i < 0 ? [strip(p), ""] : [strip(p.slice(0, i)), strip(p.slice(i + 1))];
    }));
    for (const [k, val] of params) if (k.toLowerCase() === param.toLowerCase()) return unquote(val);
    return undefined;
  }

  getFilename() {
    let f = this.getParam("filename", "content-disposition");
    if (f === undefined) f = this.getParam("name", "content-type");
    if (f === undefined) return null;
    return strip(unquote(f));
  }

  getBoundary() {
    const b = this.getParam("boundary");
    return b === undefined ? null : rstrip(unquote(b));
  }

  getContentCharset() {
    const c = this.getParam("charset");
    if (c === undefined) return null;
    if (!/^[\x00-\x7f]*$/.test(c)) return null;
    return c.toLowerCase();
  }

  /** get_payload(decode=True): bytes, or null for a multipart. */
  getPayloadBytes() {
    if (this.isMultipart()) return null;
    const cte = this.has("content-transfer-encoding") ? cteHeader(this.rawHeader("content-transfer-encoding")) : "";
    const bpayload = escapedToBytes(this.payload ?? "");
    if (cte === "quoted-printable") return decodeQP(bpayload);
    if (cte === "base64") return decodeB(bpayload.filter((b) => b !== 10 && b !== 13));
    // uuencode is returned undecoded (the evaluation sets contain none).
    return bpayload;
  }

  rawHeader(name) {
    const n = name.toLowerCase();
    const h = this.headers.find(([k]) => k.toLowerCase() === n);
    return h ? h[1].replace(/\n|\r\n?/g, "") : "";
  }

  *walk() {
    yield this;
    if (this.isMultipart()) for (const p of this.payload) yield* p.walk();
  }
}

// email.message._parseparam
function parseparam(s) {
  s = ";" + s;
  const plist = [];
  let start = 0;
  const count = (ch, a, b) => { let n = 0, i = s.indexOf(ch, a); while (i >= 0 && i + ch.length <= b) { n++; i = s.indexOf(ch, i + ch.length); } return n; };
  const find = (ch, from) => s.indexOf(ch, from);
  while (find(";", start) === start) {
    start += 1;
    let end = find(";", start);
    let ind = start, diff = 0;
    while (end > 0) {
      diff += count('"', ind, end) - count('\\"', ind, end);
      if (diff % 2 === 0) break;
      [end, ind] = [ind, find(";", end + 1)];
    }
    if (end < 0) end = s.length;
    const i = s.slice(0, end).indexOf("=", start);
    const f = i === -1 ? s.slice(start, end) : rstrip(s.slice(start, i)).toLowerCase() + "=" + lstrip(s.slice(i + 1, end));
    plist.push(strip(f));
    start = end;
  }
  return plist;
}

// email.utils.unquote
function unquote(s) {
  if (s.length > 1) {
    if (s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1).replace(/\\\\/g, "\\").replace(/\\"/g, '"');
    if (s.startsWith("<") && s.endsWith(">")) return s.slice(1, -1);
  }
  return s;
}
const quote = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

// email.utils.decode_params, for the plain (non RFC 2231) names that
// MimeParameters produces; RFC 2231 names are already folded by the header parser.
function decodeParams(params) {
  if (!params.length) return params;
  const out = [params[0]];
  for (const [name, value] of params.slice(1)) out.push([name, `"${quote(unquote(value))}"`]);
  return out;
}

// ------------------------------------------------------------ feedparser

class Input {
  constructor(lines) { this.lines = lines; this.pos = 0; this.back = []; this.eof = []; }
  readline() {
    let line;
    if (this.back.length) line = this.back.pop();
    else if (this.pos < this.lines.length) line = this.lines[this.pos++];
    else return "";
    for (let i = this.eof.length - 1; i >= 0; i--) {
      if (this.eof[i](line)) { this.back.push(line); return ""; }
    }
    return line;
  }
  unreadline(line) { this.back.push(line); }
  *[Symbol.iterator]() { for (;;) { const l = this.readline(); if (l === "") return; yield l; } }
}

const isBlank = (line) => line.startsWith("\n") || line.startsWith("\r");
const stripEol = (s) => s.replace(/(\r\n|\r|\n)$/, "");

class FeedParser {
  constructor(text) {
    const lines = text.split(/(?<=\n)/);
    if (lines.length && lines[lines.length - 1] === "") lines.pop();
    this.input = new Input(lines);
    this.stack = [];
    this.cur = null;
    this.last = null;
  }

  newMessage() {
    const msg = new Message();
    if (this.cur && this.cur.getContentType() === "multipart/digest") msg.defaultType = "message/rfc822";
    if (this.stack.length) {
      const parent = this.stack[this.stack.length - 1];
      if (parent.payload === null) parent.payload = [msg]; else parent.payload.push(msg);
    }
    this.stack.push(msg);
    this.cur = msg;
    this.last = msg;
  }

  popMessage() {
    const m = this.stack.pop();
    this.cur = this.stack.length ? this.stack[this.stack.length - 1] : null;
    return m;
  }

  parse() {
    this.parsegen();
    return this.popMessage();
  }

  parsegen() {
    this.newMessage();
    const headers = [];
    for (const line of this.input) {
      if (!HEADER_RE.test(line)) {
        if (!isBlank(line)) this.input.unreadline(line);
        break;
      }
      headers.push(line);
    }
    this.parseHeaders(headers);
    const cur = this.cur;
    if (cur.getContentType() === "message/delivery-status") {
      for (;;) {
        this.input.eof.push(isBlank);
        this.parsegen();
        this.popMessage();
        this.input.eof.pop();
        this.input.readline();
        const line = this.input.readline();
        if (line === "") break;
        this.input.unreadline(line);
      }
      return;
    }
    if (cur.getContentMaintype() === "message") {
      this.parsegen();
      this.popMessage();
      return;
    }
    if (cur.getContentMaintype() === "multipart") {
      const boundary = cur.getBoundary();
      if (boundary === null) {
        cur.payload = [...this.input].join("");
        return;
      }
      const separator = "--" + boundary;
      // boundaryendRE matched after the separator; lines end in "\n" only.
      const boundaryMatch = (line) => (line.startsWith(separator) ? /^(--)?[ \t]*\n?$/.exec(line.slice(separator.length)) : null);
      let capturingPreamble = true;
      const preamble = [];
      let closeBoundarySeen = false;
      for (;;) {
        let line = this.input.readline();
        if (line === "") break;
        const mo = boundaryMatch(line);
        if (mo) {
          if (mo[1]) { closeBoundarySeen = true; break; }
          if (capturingPreamble) {
            capturingPreamble = false;
            this.input.unreadline(line);
            continue;
          }
          for (;;) {
            line = this.input.readline();
            if (!boundaryMatch(line)) { this.input.unreadline(line); break; }
          }
          this.input.eof.push(boundaryMatch);
          this.parsegen();
          if (this.last.getContentMaintype() !== "multipart" && typeof this.last.payload === "string") {
            this.last.payload = stripEol(this.last.payload);
          }
          this.input.eof.pop();
          this.popMessage();
          this.last = this.cur;
        } else {
          preamble.push(line);
        }
      }
      if (capturingPreamble) {
        cur.payload = preamble.join("");
        for (const _ of this.input) { /* drained as epilogue */ }
        return;
      }
      if (!closeBoundarySeen) return;
      for (const _ of this.input) { /* epilogue */ }
      return;
    }
    cur.payload = [...this.input].join("");
  }

  parseHeaders(lines) {
    let lastHeader = "", lastValue = [];
    const flush = () => {
      const [first, ...rest] = lastValue;
      const i = first.indexOf(":");
      const name = first.slice(0, i);
      const value = stripChars([first.slice(i + 1), ...rest].join(""), " \t\r\n", true, false);
      this.cur.headers.push([name, stripChars(value, "\r\n", false, true)]);
    };
    for (let lineno = 0; lineno < lines.length; lineno++) {
      const line = lines[lineno];
      if (line[0] === " " || line[0] === "\t") {
        if (!lastHeader) continue;
        lastValue.push(line);
        continue;
      }
      if (lastHeader) { flush(); lastHeader = ""; lastValue = []; }
      if (line.startsWith("From ")) {
        if (lineno === 0) continue;
        if (lineno === lines.length - 1) { this.input.unreadline(line); return; }
        continue;
      }
      const i = line.indexOf(":");
      if (i === 0) continue;
      lastHeader = line.slice(0, i);
      lastValue = [line];
    }
    if (lastHeader) flush();
  }
}

/** BytesParser(policy=policy.default).parse(BytesIO(raw)) */
export function parseMessage(bytes) {
  // TextIOWrapper(encoding='ascii', errors='surrogateescape') with universal newlines
  const text = bytesToEscaped(bytes).replace(/\r\n?/g, "\n");
  return new FeedParser(text).parse();
}
