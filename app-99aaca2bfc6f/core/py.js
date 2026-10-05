// Python-compatible building blocks for the detection core.
//
// The core must treat every email exactly as the evaluated Python pipeline did
// (MVP-PRD step 2, parity), so these helpers reproduce the Python standard-library
// behaviour the pipeline relies on: string whitespace and slicing rules, codecs,
// base64 / quoted-printable decoding, html.unescape and urllib.parse.urlsplit.
// Each function names the Python function it mirrors.
//
// Text read from an email is kept the way Python's email package keeps it: bytes
// 0x00-0x7F as characters, and bytes 0x80-0xFF as the lone surrogates U+DC80-U+DCFF
// ("surrogateescape"). Such strings behave like Python strings under the regular
// expressions and slicing used here.

import PY from "./pydata.js";

// ---------------------------------------------------------------- strings

// str.isspace() characters, which is also what Python's \s matches in str patterns.
export const WS = "\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const WS_RE = new RegExp(`[${WS}]`);
const LSTRIP_RE = new RegExp(`^[${WS}]+`);
const RSTRIP_RE = new RegExp(`[${WS}]+$`);
const WS_ALL_RE = new RegExp(`[${WS}]+`, "g");

export const isSpace = (c) => WS_RE.test(c);
export const lstrip = (s) => s.replace(LSTRIP_RE, "");
export const rstrip = (s) => s.replace(RSTRIP_RE, "");
export const strip = (s) => lstrip(rstrip(s));
/** ''.join(s.split()) */
export const removeWhitespace = (s) => s.replace(WS_ALL_RE, "");

/** str.strip(chars) / lstrip(chars) / rstrip(chars) with an explicit character set. */
export function stripChars(s, chars, left = true, right = true) {
  let a = 0, b = s.length;
  if (left) while (a < b && chars.includes(s[a])) a++;
  if (right) while (b > a && chars.includes(s[b - 1])) b--;
  return s.slice(a, b);
}

/** Python code-point length (a surrogate pair is one character; a lone surrogate is one). */
export function cpLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++, n++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
  }
  return n;
}

/** s[:n] with Python code-point indexing. */
export function cpSlice(s, n) {
  if (s.length <= n) return s;
  let i = 0;
  for (let k = 0; k < n && i < s.length; k++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      i += d >= 0xdc00 && d <= 0xdfff ? 2 : 1;
    } else i += 1;
  }
  return s.slice(0, i);
}

/** True if s holds a lone surrogate, i.e. Python's s.encode() would fail. */
export function hasSurrogates(s) {
  return /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
}

// ---------------------------------------------------------------- bytes <-> text

/** bytes.decode('ascii', 'surrogateescape') */
export function bytesToEscaped(bytes) {
  let out = "";
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const part = bytes.subarray(i, i + CHUNK);
    const codes = new Array(part.length);
    for (let j = 0; j < part.length; j++) codes[j] = part[j] < 0x80 ? part[j] : 0xdc00 + part[j];
    out += String.fromCharCode.apply(null, codes);
  }
  return out;
}

export class UnicodeEncodeError extends Error {}
export class UnicodeDecodeError extends Error {}
export class LookupError extends Error {}

/** str.encode('ascii', 'surrogateescape') */
export function escapedToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) out[i] = c;
    else if (c >= 0xdc80 && c <= 0xdcff) out[i] = c - 0xdc00;
    else throw new UnicodeEncodeError("not ASCII");
  }
  return out;
}

/** str.encode('utf-8', 'surrogateescape') */
function utf8EncodeEscaped(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c >= 0xdc80 && c <= 0xdcff) out.push(c - 0xdc00);
    else if (c >= 0xd800 && c <= 0xdfff) throw new UnicodeEncodeError("surrogate");
    else if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

/** email.utils._sanitize: surrogate-escaped bytes are re-read as UTF-8 with replacement. */
export function sanitize(s) {
  if (!hasSurrogates(s)) return s;
  return decode(utf8EncodeEscaped(s), "utf-8", "replace");
}

// ---------------------------------------------------------------- codecs

/** encodings.normalize_encoding */
function normalizeEncoding(name) {
  const chars = [];
  let punct = false;
  for (const c of name) {
    if (/[A-Za-z0-9]/.test(c) || c === ".") {
      if (punct && chars.length) chars.push("_");
      chars.push(c);
      punct = false;
    } else punct = true;
  }
  return chars.join("");
}

/** codecs.lookup(name).name, restricted to the codecs this core implements. */
export function lookupCodec(name) {
  const norm = normalizeEncoding(String(name).toLowerCase());
  const hit = PY.aliases[norm] || PY.aliases[norm.replace(/\./g, "_")];
  if (!hit) throw new LookupError(`unknown encoding: ${name}`);
  return hit;
}

function onError(errors, bytes, start, end, out) {
  if (errors === "strict") throw new UnicodeDecodeError(`cannot decode byte 0x${bytes[start].toString(16)}`);
  if (errors === "replace") out.push("�");
  else if (errors === "surrogateescape") {
    for (let k = start; k < end; k++) {
      if (bytes[k] < 0x80) throw new UnicodeDecodeError("surrogateescape cannot escape ASCII");
      out.push(String.fromCharCode(0xdc00 + bytes[k]));
    }
  } else throw new Error(`unsupported error handler ${errors}`);
}

// UTF-8 per the WHATWG / Unicode "maximal subpart" rule, which CPython also follows:
// each invalid sequence is one error covering the bytes consumed so far.
function decodeUtf8(bytes, errors) {
  const out = [];
  let i = 0;
  const n = bytes.length;
  while (i < n) {
    const b = bytes[i];
    if (b < 0x80) { out.push(String.fromCharCode(b)); i++; continue; }
    let need, lo = 0x80, hi = 0xbf, cp;
    if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; }
    else if (b >= 0xe0 && b <= 0xef) {
      need = 2; cp = b & 0x0f;
      if (b === 0xe0) lo = 0xa0; else if (b === 0xed) hi = 0x9f;
    } else if (b >= 0xf0 && b <= 0xf4) {
      need = 3; cp = b & 0x07;
      if (b === 0xf0) lo = 0x90; else if (b === 0xf4) hi = 0x8f;
    } else { onError(errors, bytes, i, i + 1, out); i++; continue; }
    const start = i;
    i++;
    let ok = true;
    for (let k = 0; k < need; k++) {
      if (i >= n || bytes[i] < lo || bytes[i] > hi) { ok = false; break; }
      cp = (cp << 6) | (bytes[i] & 0x3f);
      lo = 0x80; hi = 0xbf;
      i++;
    }
    if (!ok) { onError(errors, bytes, start, i, out); continue; }
    out.push(String.fromCodePoint(cp));
  }
  return out.join("");
}

function decodeSingleByte(bytes, table, errors) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const ch = table[bytes[i]];
    if (ch === null) onError(errors, bytes, i, i + 1, out);
    else out.push(ch);
  }
  return out.join("");
}

/** bytes.decode(charset, errors) */
export function decode(bytes, charset, errors = "strict") {
  const codec = lookupCodec(charset);
  if (codec === "utf_8") return decodeUtf8(bytes, errors);
  if (PY.singleByte[codec]) return decodeSingleByte(bytes, PY.singleByte[codec], errors);
  const label = PY.multiByte[codec];
  // Approximation: WHATWG decoders; surrogateescape falls back to replacement.
  let dec;
  try { dec = new TextDecoder(label, { fatal: errors === "strict" }); }
  catch { throw new LookupError(label); }
  try { return dec.decode(bytes); }
  catch (e) { throw new UnicodeDecodeError(e.message); }
}

// ---------------------------------------------------------------- base64 / quoted-printable

const B64 = (() => {
  const t = new Int16Array(256).fill(-1);
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < 64; i++) t[a.charCodeAt(i)] = i;
  return t;
})();

class BinasciiError extends Error {}

/** binascii.a2b_base64(data, strict_mode=strict), as in CPython 3.14 Modules/binascii.c */
function a2bBase64(data, strict) {
  const out = [];
  let quad = 0, left = 0, pads = 0;
  for (let i = 0; i < data.length; i++) {
    const ch = data[i];
    if (ch === 61) { // '='
      pads++;
      if (quad >= 2 && quad + pads <= 4) continue;
      if (!strict) continue; // RFC 4648 3.3: pad characters before the end may be ignored
      if (quad === 1) break;
      throw new BinasciiError("Excess padding not allowed");
    }
    const v = B64[ch];
    if (v < 0) {
      if (strict) throw new BinasciiError("Only base64 data is allowed");
      continue;
    }
    if (pads && strict) throw new BinasciiError("Excess data after padding");
    pads = 0;
    switch (quad) {
      case 0: quad = 1; left = v; break;
      case 1: quad = 2; out.push(((left << 2) | (v >> 4)) & 0xff); left = v & 0x0f; break;
      case 2: quad = 3; out.push(((left << 4) | (v >> 2)) & 0xff); left = v & 0x03; break;
      case 3: quad = 0; out.push(((left << 6) | v) & 0xff); left = 0; break;
    }
  }
  if (quad === 1) throw new BinasciiError("Invalid length");
  if (quad !== 0 && quad + pads < 4) throw new BinasciiError("Incorrect padding");
  return Uint8Array.from(out);
}

const concat = (a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a); r.set(b, a.length); return r; };
const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));

/** email._encoded_words.decode_b (bytes in, bytes out) */
export function decodeB(encoded) {
  const padErr = encoded.length % 4;
  const missing = padErr ? ascii("===".slice(0, 4 - padErr)) : new Uint8Array(0);
  try { return a2bBase64(concat(encoded, missing), true); } catch (e) { if (!(e instanceof BinasciiError)) throw e; }
  try { return a2bBase64(encoded, false); } catch (e) { if (!(e instanceof BinasciiError)) throw e; }
  try { return a2bBase64(concat(encoded, ascii("==")), false); } catch (e) { if (!(e instanceof BinasciiError)) throw e; }
  return encoded;
}

const isHex = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
const hexVal = (c) => (c <= 57 ? c - 48 : (c | 0x20) - 87);

/** binascii.a2b_qp(data, header=False), which quopri.decodestring uses. */
export function decodeQP(data) {
  const out = [];
  let i = 0;
  const n = data.length;
  while (i < n) {
    if (data[i] === 61) { // '='
      i++;
      if (i >= n) break;
      if (data[i] === 10 || data[i] === 13) { // soft line break
        if (data[i] !== 10) while (i < n && data[i] !== 10) i++;
        if (i < n) i++;
      } else if (data[i] === 61) { out.push(61); i++; }
      else if (i + 1 < n && isHex(data[i]) && isHex(data[i + 1])) {
        out.push((hexVal(data[i]) << 4) | hexVal(data[i + 1])); i += 2;
      } else out.push(61);
    } else { out.push(data[i]); i++; }
  }
  return Uint8Array.from(out);
}

/** The Q decoding of RFC 2047 encoded words (email._encoded_words.decode_q). */
export function decodeQ(encoded) {
  const out = [];
  for (let i = 0; i < encoded.length; i++) {
    const c = encoded[i] === 95 ? 32 : encoded[i];
    if (c === 61 && i + 2 < encoded.length && isHex(encoded[i + 1]) && isHex(encoded[i + 2])) {
      out.push((hexVal(encoded[i + 1]) << 4) | hexVal(encoded[i + 2]));
      i += 2;
    } else out.push(c);
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- html.unescape

const INVALID_CODEPOINTS = new Set(PY.invalidCodepoints);
const CHARREF = /&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)/gu;

function replaceCharref(_, s) {
  if (s[0] === "#") {
    const num = s[1] === "x" || s[1] === "X" ? parseInt(s.slice(2).replace(/;$/, ""), 16)
      : parseInt(s.slice(1).replace(/;$/, ""), 10);
    if (Object.prototype.hasOwnProperty.call(PY.invalidCharrefs, String(num))) return PY.invalidCharrefs[String(num)];
    if ((num >= 0xd800 && num <= 0xdfff) || num > 0x10ffff || !Number.isFinite(num)) return "�";
    if (INVALID_CODEPOINTS.has(num)) return "";
    return String.fromCodePoint(num);
  }
  if (Object.prototype.hasOwnProperty.call(PY.html5, s)) return PY.html5[s];
  const cps = Array.from(s);
  for (let x = cps.length - 1; x > 1; x--) {
    const head = cps.slice(0, x).join("");
    if (Object.prototype.hasOwnProperty.call(PY.html5, head)) return PY.html5[head] + cps.slice(x).join("");
  }
  return "&" + s;
}

/** html.unescape */
export function htmlUnescape(s) {
  if (!s.includes("&")) return s;
  return s.replace(CHARREF, replaceCharref);
}

// ---------------------------------------------------------------- urllib.parse

const C0_OR_SPACE = Array.from({ length: 33 }, (_, i) => String.fromCharCode(i)).join("");
const SCHEME_CHARS = /^[A-Za-z0-9+\-.]*$/;

export class ValueError extends Error {}

function isIPv4(s) {
  const parts = s.split(".");
  return parts.length === 4 && parts.every((p) => /^[0-9]{1,3}$/.test(p) && Number(p) <= 255 && !(p.length > 1 && p[0] === "0"));
}

function isIPv6(s) {
  if (s.includes("%")) s = s.slice(0, s.indexOf("%"));
  if (!/^[0-9A-Fa-f:.]+$/.test(s) || !s.includes(":")) return false;
  const lastGroup = s.slice(s.lastIndexOf(":") + 1);
  if (lastGroup.includes(".")) { if (!isIPv4(lastGroup)) return false; s = s.slice(0, s.lastIndexOf(":") + 1) + "0:0"; }
  const dbl = s.split("::");
  if (dbl.length > 2) return false;
  const groups = (x) => (x === "" ? [] : x.split(":"));
  const g = dbl.length === 2 ? [...groups(dbl[0]), ...groups(dbl[1])] : groups(s);
  if (!g.every((x) => /^[0-9A-Fa-f]{1,4}$/.test(x))) return false;
  return dbl.length === 2 ? g.length < 8 : g.length === 8;
}

function checkBracketedHost(host) {
  if (host.startsWith("v") || host.startsWith("V")) {
    if (!/^[vV][a-fA-F0-9]+\..+$/s.test(host)) throw new ValueError("IPvFuture address is invalid");
  } else {
    if (isIPv4(host)) throw new ValueError("An IPv4 address cannot be in brackets");
    if (!isIPv6(host)) throw new ValueError("not an IP address");
  }
}

function checkBracketedNetloc(netloc) {
  const hp = netloc.slice(netloc.lastIndexOf("@") + 1);
  const ob = hp.indexOf("[");
  let host, port;
  if (ob >= 0) {
    if (ob > 0) throw new ValueError("Invalid IPv6 URL");
    const br = hp.slice(ob + 1);
    const cb = br.indexOf("]");
    host = cb >= 0 ? br.slice(0, cb) : br;
    port = cb >= 0 ? br.slice(cb + 1) : "";
    if (port && !port.startsWith(":")) throw new ValueError("Invalid IPv6 URL");
  } else {
    const c = hp.indexOf(":");
    host = c >= 0 ? hp.slice(0, c) : hp;
  }
  checkBracketedHost(host);
}

function checkNetloc(netloc) {
  if (!netloc || /^[\x00-\x7f]*$/.test(netloc)) return;
  const n = netloc.replace(/[@:#?]/g, "");
  const n2 = n.normalize("NFKC");
  if (n === n2) return;
  for (const c of "/?#@:") if (n2.includes(c)) throw new ValueError("invalid netloc");
}

/** urllib.parse.urlparse(url).netloc (raises ValueError like Python). */
export function urlNetloc(url) {
  url = stripChars(url, C0_OR_SPACE, true, false).replace(/[\t\r\n]/g, "");
  const i = url.indexOf(":");
  if (i > 0 && /^[A-Za-z]$/.test(url[0]) && SCHEME_CHARS.test(url.slice(0, i))) url = url.slice(i + 1);
  let netloc = null;
  if (url.slice(0, 2) === "//") {
    let delim = url.length;
    for (const c of "/?#") {
      const w = url.indexOf(c, 2);
      if (w >= 0) delim = Math.min(delim, w);
    }
    netloc = url.slice(2, delim);
    const o = netloc.includes("["), c = netloc.includes("]");
    if (o !== c) throw new ValueError("Invalid IPv6 URL");
    if (o && c) checkBracketedNetloc(netloc);
  }
  checkNetloc(netloc);
  return netloc || "";
}
