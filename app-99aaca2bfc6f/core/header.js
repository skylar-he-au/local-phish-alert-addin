// Header value parsing, ported from Python's email._header_value_parser and
// email.headerregistry (policy.default), limited to what the detection core reads:
//
//   unstructured headers   Subject, Return-Path, Authentication-Results, ...
//   address headers        From, Reply-To
//   MIME headers           Content-Type, Content-Disposition, Content-Transfer-Encoding
//
// The port keeps Python's function names and structure so it can be checked line by
// line against the original. Defect bookkeeping is left out: no value read here
// depends on it.

import { lstrip, rstrip, strip, removeWhitespace, sanitize, escapedToBytes, decode, decodeB, decodeQ,
  UnicodeDecodeError, LookupError } from "./py.js";

class HeaderParseError extends Error {}
class InvalidEwError extends HeaderParseError {}

const set = (s) => new Set(s);
const WSP = set(" \t");
const CFWS_LEADER = set(" \t(");
const SPECIALS = set('()<>@,:;.\\"[]');
const ATOM_ENDS = new Set([...SPECIALS, ...WSP]);
const DOT_ATOM_ENDS = new Set([...ATOM_ENDS].filter((c) => c !== "."));
const PHRASE_ENDS = new Set([...SPECIALS].filter((c) => !'."('.includes(c)));
const TSPECIALS = new Set([...SPECIALS, "/", "?", "="].filter((c) => c !== "."));
const TOKEN_ENDS = new Set([...TSPECIALS, ...WSP]);
const ASPECIALS = new Set([...TSPECIALS, "*", "'", "%"]);
const ATTRIBUTE_ENDS = new Set([...ASPECIALS, ...WSP]);
const EXTENDED_ATTRIBUTE_ENDS = new Set([...ATTRIBUTE_ENDS].filter((c) => c !== "%"));
const HEXDIGITS = set("0123456789abcdefABCDEF");

const has = (s, c) => c !== undefined && s.has(c);
const disjoint = (chars, s) => { for (const c of s) if (chars.has(c)) return false; return true; };

const quoteString = (v) => '"' + String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';

// ------------------------------------------------------------ tokens
// A token list is {kind, tt, items}; kind is the Python class, tt its token_type
// (which Python code sometimes reassigns). A terminal is {term, kind, tt, text}.

const tl = (kind, tt, items = []) => ({ kind, tt, items, props: {} });
const term = (kind, tt, text) => ({ term: true, kind, tt, text });
const V = (text, tt) => term("Value", tt, text);
const WS = (text, tt) => term("WhiteSpace", tt, text);
const EWWS = (tt) => term("EWWhiteSpace", tt, "");
const DOT = V(".", "dot");
const isTL = (t) => !t.term;
const last = (t) => t.items[t.items.length - 1];

function str(t) {
  if (t.term) return t.kind === "EWWhiteSpace" ? "" : t.text;
  switch (t.kind) {
    case "BareQuotedString": return quoteString(t.items.map(str).join(""));
    case "Comment": return "(" + t.items.map((x) => (x.tt === "comment" ? str(x)
      : str(x).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)"))).join("") + ")";
    case "MimeParameters": {
      const ps = mimeParams(t).map(([n, v]) => (v ? `${n}=${quoteString(v)}` : n)).join("; ");
      return ps ? " " + ps : "";
    }
    default: return t.items.map(str).join("");
  }
}

function value(t) {
  if (t.term) return t.kind === "Value" ? t.text : t.kind === "WhiteSpace" ? " " : "";
  switch (t.kind) {
    case "CFWSList": case "Comment": return " ";
    case "BareQuotedString": return t.items.map(str).join("");
    case "LocalPart":
      return t.items[0].tt === "quoted-string" ? quotedValue(t.items[0]) : value(t.items[0]);
    case "AddrSpec":
      if (t.items.length < 3) return value(t.items[0]);
      return rstrip(value(t.items[0])) + value(t.items[1]) + lstrip(value(t.items[2]));
    case "DisplayName": return displayNameValue(t);
    default: return plainValue(t);
  }
}

const plainValue = (t) => t.items.map(value).filter((x) => x).join("");

function quotedValue(q) {
  return q.items.map((x) => (x.tt === "bare-quoted-string" ? str(x) : value(x))).join("");
}

// DisplayName.display_name
function displayName(t) {
  const res = [...t.items];
  if (res.length === 0) return "";
  if (res[0].tt === "cfws") res.shift();
  else if (isTL(res[0]) && res[0].items[0]?.tt === "cfws") res[0] = tl("TokenList", null, res[0].items.slice(1));
  // Python indexes res[-1] here and raises IndexError on a display name of only CFWS.
  if (!res.length) throw new RangeError("IndexError: display name");
  if (res[res.length - 1].tt === "cfws") res.pop();
  else if (isTL(res[res.length - 1]) && last(res[res.length - 1])?.tt === "cfws") {
    const r = res[res.length - 1];
    res[res.length - 1] = tl("TokenList", null, r.items.slice(0, -1));
  }
  return plainValue(tl("TokenList", null, res));
}

function displayNameValue(t) {
  const quote = t.defects || t.items.some((x) => x.tt === "quoted-string");
  if (t.items.length && quote) {
    const f = t.items[0], l = last(t);
    const pre = f.tt === "cfws" || (isTL(f) && f.items[0]?.tt === "cfws") ? " " : "";
    const post = l.tt === "cfws" || (isTL(l) && last(l)?.tt === "cfws") ? " " : "";
    return pre + quoteString(displayName(t)) + post;
  }
  return plainValue(t);
}

// LocalPart.local_part: strip whitespace from front, back and around dots.
function localPartOf(lp) {
  const res = [DOT];
  let lastTok = DOT, lastIsTL = false;
  for (const tok of [...lp.items[0].items, DOT]) {
    if (tok.tt === "cfws") continue;
    if (lastIsTL && tok.tt === "dot" && lastTok.items.length && last(lastTok).tt === "cfws")
      res[res.length - 1] = tl("TokenList", null, lastTok.items.slice(0, -1));
    const isTl = isTL(tok);
    if (isTl && lastTok.tt === "dot" && tok.items.length && tok.items[0].tt === "cfws")
      res.push(tl("TokenList", null, tok.items.slice(1)));
    else res.push(tok);
    lastTok = res[res.length - 1];
    lastIsTL = isTl;
  }
  return plainValue(tl("TokenList", null, res.slice(1, -1)));
}

// .local_part / .domain / .display_name of the address-related classes
function localPart(t) {
  switch (t.kind) {
    case "Mailbox": return localPart(t.items[0]);
    case "NameAddr": return localPart(last(t));
    case "AngleAddr": { const a = t.items.find((x) => x.tt === "addr-spec"); return a ? localPart(a) : null; }
    case "AddrSpec": return localPartOf(t.items[0]);
    default: return null;
  }
}

function domain(t) {
  switch (t.kind) {
    case "Mailbox": return domain(t.items[0]);
    case "NameAddr": return domain(last(t));
    case "AngleAddr": { const a = t.items.find((x) => x.tt === "addr-spec"); return a ? domain(a) : null; }
    case "AddrSpec": return t.items.length < 3 ? null : domain(last(t));
    case "Domain": case "DomainLiteral": return removeWhitespace(plainValue(t));
    default: return null;
  }
}

function mailboxDisplayName(t) {
  if (t.kind === "Mailbox") return t.items[0].tt === "name-addr" ? mailboxDisplayName(t.items[0]) : null;
  if (t.kind === "NameAddr") return t.items.length === 1 ? null : displayName(t.items[0]);
  return null;
}

function allMailboxes(t) {
  switch (t.kind) {
    case "Address":
      if (t.items[0].tt === "mailbox" || t.items[0].tt === "invalid-mailbox") return [t.items[0]];
      return allMailboxes(t.items[0]);
    case "Group": return t.items[2]?.tt !== "group-list" ? [] : allMailboxes(t.items[2]);
    case "GroupList": return !t.items.length || t.items[0].tt !== "mailbox-list" ? [] : allMailboxes(t.items[0]);
    case "MailboxList": return t.items.filter((x) => x.tt === "mailbox" || x.tt === "invalid-mailbox");
    default: return [];
  }
}

// ------------------------------------------------------------ parser helpers

function wspSplit1(v) {
  const m = /[ \t]+/.exec(v);
  return m ? [v.slice(0, m.index), m[0], v.slice(m.index + m[0].length)] : [v];
}

function matchRun(v, ends) {
  let i = 0;
  while (i < v.length && !ends.has(v[i])) i++;
  return v.slice(0, i);
}

function getPtextToEndchars(v, endchars) {
  if (!v) return ["", "", false];
  const [fragment, ...rem] = wspSplit1(v);
  const vchars = [];
  let escape = false, hadQp = false, pos;
  for (pos = 0; pos < fragment.length; pos++) {
    const c = fragment[pos];
    if (c === "\\") {
      if (escape) { escape = false; hadQp = true; } else { escape = true; continue; }
    }
    if (escape) escape = false;
    else if (endchars.includes(c)) break;
    vchars.push(c);
  }
  return [vchars.join(""), fragment.slice(pos) + rem.join(""), hadQp];
}

function getFws(v) {
  const nv = lstrip(v);
  return [WS(v.slice(0, v.length - nv.length), "fws"), nv];
}

/** email._encoded_words.decode */
function ewDecode(ew) {
  const parts = ew.split("?");
  if (parts.length !== 5) throw new InvalidEwError("format");
  let [, charset, cte, cteString] = parts;
  charset = charset.split("*")[0];
  cte = cte.toLowerCase();
  if (cte !== "q" && cte !== "b") throw new InvalidEwError("cte");
  let bytes;
  try { bytes = escapedToBytes(cteString); } catch { throw new InvalidEwError("non-ascii"); }
  bytes = cte === "q" ? decodeQ(bytes) : decodeB(bytes);
  try {
    try { return decode(bytes, charset, "strict"); }
    catch (e) {
      if (e instanceof UnicodeDecodeError) return decode(bytes, charset, "surrogateescape");
      throw e;
    }
  } catch (e) {
    if (e instanceof LookupError) return decode(bytes, "ascii", "surrogateescape");
    if (e instanceof UnicodeDecodeError) throw new InvalidEwError("undecodable");
    throw e;
  }
}

function getEncodedWord(v, terminalType = "vtext") {
  const ew = tl("EncodedWord", "encoded-word");
  if (!v.startsWith("=?")) throw new HeaderParseError("expected encoded word");
  const body = v.slice(2);
  const k = body.indexOf("?=");
  if (k < 0) throw new HeaderParseError("expected encoded word");
  let tok = body.slice(0, k);
  let remainder = body.slice(k + 2);
  let rest = remainder;
  if (remainder.length > 1 && HEXDIGITS.has(remainder[0]) && HEXDIGITS.has(remainder[1]) && tok.split("?").length - 1 < 2) {
    const k2 = remainder.indexOf("?=");
    if (k2 < 0) { tok = tok + "?=" + remainder; rest = ""; }
    else { tok = tok + "?=" + remainder.slice(0, k2); rest = remainder.slice(k2 + 2); }
  }
  v = rest;
  let text = ewDecode("=?" + tok + "?=");
  while (text) {
    if (WSP.has(text[0])) { const [t, r] = getFws(text); ew.items.push(t); text = r; continue; }
    const [chars, ...rem] = wspSplit1(text);
    ew.items.push(V(chars, terminalType));
    text = rem.join("");
  }
  return [ew, v];
}

const RFC2047 = /=\?[^?]*\?[qQbB]\?.*?\?=/;

function getUnstructured(v) {
  const u = tl("TokenList", "unstructured");
  while (v) {
    if (WSP.has(v[0])) { const [t, r] = getFws(v); u.items.push(t); v = r; continue; }
    let validEw = true;
    if (v.startsWith("=?")) {
      let ok = false, token, r;
      try { [token, r] = getEncodedWord(v, "utext"); ok = true; }
      catch (e) {
        if (e instanceof InvalidEwError) validEw = false;
        else if (!(e instanceof HeaderParseError)) throw e;
      }
      if (ok) {
        v = r;
        let haveWs = true;
        if (u.items.length > 0 && last(u).tt !== "fws") haveWs = false;
        if (haveWs && u.items.length > 1 && u.items[u.items.length - 2].tt === "encoded-word")
          u.items[u.items.length - 1] = EWWS("fws");
        u.items.push(token);
        continue;
      }
    }
    let [tok, ...rem] = wspSplit1(v);
    if (validEw && RFC2047.test(tok)) {
      const p = v.indexOf("=?"); // value.partition('=?'); a match in tok implies p >= 0
      tok = v.slice(0, p);
      rem = [v.slice(p)];
    }
    u.items.push(V(tok, "utext"));
    v = rem.join("");
  }
  return u;
}

function getQpCtext(v) { const [p, r] = getPtextToEndchars(v, "()"); return [WS(p, "ptext"), r]; }
function getQcontent(v) { const [p, r] = getPtextToEndchars(v, '"'); return [V(p, "ptext"), r]; }

function getAtext(v) {
  const m = matchRun(v, ATOM_ENDS);
  if (!m) throw new HeaderParseError("expected atext");
  return [V(m, "atext"), v.slice(m.length)];
}

function getBareQuotedString(v) {
  if (!v || v[0] !== '"') throw new HeaderParseError("expected '\"'");
  const bqs = tl("BareQuotedString", "bare-quoted-string");
  v = v.slice(1);
  if (v && v[0] === '"') return [bqs, v.slice(1)];
  while (v && v[0] !== '"') {
    let token;
    if (WSP.has(v[0])) [token, v] = getFws(v);
    else if (v.slice(0, 2) === "=?") {
      let validEw = false;
      try { [token, v] = getEncodedWord(v); validEw = true; }
      catch (e) { if (!(e instanceof HeaderParseError)) throw e; [token, v] = getQcontent(v); }
      if (validEw && bqs.items.length > 1 && last(bqs).tt === "fws" && bqs.items[bqs.items.length - 2].tt === "encoded-word")
        bqs.items[bqs.items.length - 1] = EWWS("fws");
    } else [token, v] = getQcontent(v);
    bqs.items.push(token);
  }
  if (!v) return [bqs, v];
  return [bqs, v.slice(1)];
}

function getComment(v) {
  if (v && v[0] !== "(") throw new HeaderParseError("expected '('");
  const c = tl("Comment", "comment");
  v = v.slice(1);
  while (v && v[0] !== ")") {
    let token;
    if (WSP.has(v[0])) [token, v] = getFws(v);
    else if (v[0] === "(") [token, v] = getComment(v);
    else [token, v] = getQpCtext(v);
    c.items.push(token);
  }
  if (!v) return [c, v];
  return [c, v.slice(1)];
}

function getCfws(v) {
  const c = tl("CFWSList", "cfws");
  while (v && CFWS_LEADER.has(v[0])) {
    let token;
    if (WSP.has(v[0])) [token, v] = getFws(v); else [token, v] = getComment(v);
    c.items.push(token);
  }
  return [c, v];
}

function getQuotedString(v) {
  const q = tl("QuotedString", "quoted-string");
  let token;
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); q.items.push(token); }
  [token, v] = getBareQuotedString(v);
  q.items.push(token);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); q.items.push(token); }
  return [q, v];
}

function getAtom(v) {
  const a = tl("Atom", "atom");
  let token;
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  if (v && ATOM_ENDS.has(v[0])) throw new HeaderParseError("expected atom");
  if (v.startsWith("=?")) {
    try { [token, v] = getEncodedWord(v); }
    catch (e) { if (!(e instanceof HeaderParseError)) throw e; [token, v] = getAtext(v); }
  } else [token, v] = getAtext(v);
  a.items.push(token);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  return [a, v];
}

function getDotAtomText(v) {
  const d = tl("DotAtomText", "dot-atom-text");
  if (!v || ATOM_ENDS.has(v[0])) throw new HeaderParseError("expected atom");
  while (v && !ATOM_ENDS.has(v[0])) {
    let token;
    [token, v] = getAtext(v);
    d.items.push(token);
    if (v && v[0] === ".") { d.items.push(DOT); v = v.slice(1); }
  }
  if (last(d) === DOT) throw new HeaderParseError("expected atom at end of dot-atom-text");
  return [d, v];
}

function getDotAtom(v) {
  const d = tl("DotAtom", "dot-atom");
  let token;
  if (has(CFWS_LEADER, v[0])) { [token, v] = getCfws(v); d.items.push(token); }
  if (v.startsWith("=?")) {
    try { [token, v] = getEncodedWord(v); }
    catch (e) { if (!(e instanceof HeaderParseError)) throw e; [token, v] = getDotAtomText(v); }
  } else [token, v] = getDotAtomText(v);
  d.items.push(token);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); d.items.push(token); }
  return [d, v];
}

function getWord(v) {
  let leader = null, token;
  if (has(CFWS_LEADER, v[0])) [leader, v] = getCfws(v);
  if (!v) throw new HeaderParseError("Expected 'atom' or 'quoted-string' but found nothing.");
  if (v[0] === '"') [token, v] = getQuotedString(v);
  else if (SPECIALS.has(v[0])) throw new HeaderParseError("Expected 'atom' or 'quoted-string'");
  else [token, v] = getAtom(v);
  if (leader !== null) token.items.unshift(leader);
  return [token, v];
}

const comments = (t) => (t.term ? [] : t.kind === "Comment" ? [t] : t.items.flatMap(comments));

function getPhrase(v) {
  const p = tl("TokenList", "phrase");
  p.defects = false;
  try { const [t, r] = getWord(v); p.items.push(t); v = r; }
  catch (e) { if (!(e instanceof HeaderParseError)) throw e; p.defects = true; }
  while (v && !PHRASE_ENDS.has(v[0])) {
    if (v[0] === ".") { p.items.push(DOT); p.defects = true; v = v.slice(1); continue; }
    let token;
    try {
      [token, v] = getWord(v);
      const lp = last(p);
      if (token.items[0]?.tt === "encoded-word" && p.items.length && lp.tt === "atom" && lp.items.length > 1
          && lp.items[lp.items.length - 2].tt === "encoded-word" && last(lp).tt === "cfws" && !comments(last(lp)).length)
        lp.items[lp.items.length - 1] = EWWS("fws");
    } catch (e) {
      if (!(e instanceof HeaderParseError)) throw e;
      if (CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); p.defects = true; }
      else throw e;
    }
    p.items.push(token);
  }
  return [p, v];
}

function getLocalPart(v) {
  const lp = tl("LocalPart", "local-part");
  let leader = null, token;
  if (v && CFWS_LEADER.has(v[0])) [leader, v] = getCfws(v);
  if (!v) throw new HeaderParseError("expected local-part");
  try { [token, v] = getDotAtom(v); }
  catch (e) {
    if (!(e instanceof HeaderParseError)) throw e;
    try { [token, v] = getWord(v); }
    catch (e2) {
      if (!(e2 instanceof HeaderParseError)) throw e2;
      if (v[0] !== "\\" && PHRASE_ENDS.has(v[0])) throw e2;
      token = tl("TokenList", null);
    }
  }
  if (leader !== null) token.items.unshift(leader);
  lp.items.push(token);
  if (v && (v[0] === "\\" || !PHRASE_ENDS.has(v[0]))) {
    const [obs, r] = getObsLocalPart(str(lp) + v);
    v = r;
    lp.items[0] = obs;
  }
  return [lp, v];
}

function getObsLocalPart(v) {
  const o = tl("TokenList", "obs-local-part");
  while (v && (v[0] === "\\" || !PHRASE_ENDS.has(v[0]))) {
    if (v[0] === ".") { o.items.push(DOT); v = v.slice(1); continue; }
    if (v[0] === "\\") { o.items.push(V(v[0], "misplaced-special")); v = v.slice(1); continue; }
    let token;
    try { [token, v] = getWord(v); }
    catch (e) {
      if (!(e instanceof HeaderParseError)) throw e;
      if (!CFWS_LEADER.has(v[0])) throw e;
      [token, v] = getCfws(v);
    }
    o.items.push(token);
  }
  if (!o.items.length) throw new HeaderParseError("expected obs-local-part");
  return [o, v];
}

function getDtext(v) { const [p, r] = getPtextToEndchars(v, "[]"); return [V(p, "ptext"), r]; }

function getDomainLiteral(v) {
  const d = tl("DomainLiteral", "domain-literal");
  let token;
  if (has(CFWS_LEADER, v[0])) { [token, v] = getCfws(v); d.items.push(token); }
  if (!v) throw new HeaderParseError("expected domain-literal");
  if (v[0] !== "[") throw new HeaderParseError("expected '['");
  v = v.slice(1);
  d.items.push(V("[", "domain-literal-start"));
  const early = () => { if (v) return false; d.items.push(V("]", "domain-literal-end")); return true; };
  if (early()) return [d, v];
  if (WSP.has(v[0])) { [token, v] = getFws(v); d.items.push(token); }
  [token, v] = getDtext(v);
  d.items.push(token);
  if (early()) return [d, v];
  if (WSP.has(v[0])) { [token, v] = getFws(v); d.items.push(token); }
  if (early()) return [d, v];
  if (v[0] !== "]") throw new HeaderParseError("expected ']'");
  d.items.push(V("]", "domain-literal-end"));
  v = v.slice(1);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); d.items.push(token); }
  return [d, v];
}

function getDomain(v) {
  const d = tl("Domain", "domain");
  let leader = null, token;
  if (v && CFWS_LEADER.has(v[0])) [leader, v] = getCfws(v);
  if (!v) throw new HeaderParseError("expected domain");
  if (v[0] === "[") {
    [token, v] = getDomainLiteral(v);
    if (leader !== null) token.items.unshift(leader);
    d.items.push(token);
    return [d, v];
  }
  try { [token, v] = getDotAtom(v); }
  catch (e) { if (!(e instanceof HeaderParseError)) throw e; [token, v] = getAtom(v); }
  if (v && v[0] === "@") throw new HeaderParseError("Invalid Domain");
  if (leader !== null) token.items.unshift(leader);
  d.items.push(token);
  if (v && v[0] === ".") {
    if (d.items[0].tt === "dot-atom") d.items = [...d.items[0].items];
    while (v && v[0] === ".") {
      d.items.push(DOT);
      [token, v] = getAtom(v.slice(1));
      d.items.push(token);
    }
  }
  return [d, v];
}

function getAddrSpec(v) {
  const a = tl("AddrSpec", "addr-spec");
  let token;
  [token, v] = getLocalPart(v);
  a.items.push(token);
  if (!v || v[0] !== "@") return [a, v];
  a.items.push(V("@", "address-at-symbol"));
  [token, v] = getDomain(v.slice(1));
  a.items.push(token);
  return [a, v];
}

function getObsRoute(v) {
  const o = tl("TokenList", "obs-route");
  let token;
  while (v && (v[0] === "," || CFWS_LEADER.has(v[0]))) {
    if (CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); o.items.push(token); }
    else { o.items.push(V(",", "list-separator")); v = v.slice(1); }
  }
  if (!v || v[0] !== "@") throw new HeaderParseError("expected obs-route domain");
  o.items.push(V("@", "route-component-marker"));
  [token, v] = getDomain(v.slice(1));
  o.items.push(token);
  while (v && v[0] === ",") {
    o.items.push(V(",", "list-separator"));
    v = v.slice(1);
    if (!v) break;
    if (CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); o.items.push(token); }
    if (!v) break;
    if (v[0] === "@") {
      o.items.push(V("@", "route-component-marker"));
      [token, v] = getDomain(v.slice(1));
      o.items.push(token);
    }
  }
  if (!v) throw new HeaderParseError("end of header while parsing obs-route");
  if (v[0] !== ":") throw new HeaderParseError("expected ':'");
  o.items.push(V(":", "end-of-obs-route-marker"));
  return [o, v.slice(1)];
}

function getAngleAddr(v) {
  const a = tl("AngleAddr", "angle-addr");
  let token;
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  if (!v || v[0] !== "<") throw new HeaderParseError("expected angle-addr");
  a.items.push(V("<", "angle-addr-start"));
  v = v.slice(1);
  if (v && v[0] === ">") { a.items.push(V(">", "angle-addr-end")); return [a, v.slice(1)]; }
  try { [token, v] = getAddrSpec(v); }
  catch (e) {
    if (!(e instanceof HeaderParseError)) throw e;
    try { [token, v] = getObsRoute(v); }
    catch (e2) { if (!(e2 instanceof HeaderParseError)) throw e2; throw new HeaderParseError("expected addr-spec or obs-route"); }
    a.items.push(token);
    [token, v] = getAddrSpec(v);
  }
  a.items.push(token);
  if (v && v[0] === ">") v = v.slice(1);
  a.items.push(V(">", "angle-addr-end"));
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  return [a, v];
}

function getDisplayName(v) {
  const [p, r] = getPhrase(v);
  const d = tl("DisplayName", "display-name", [...p.items]);
  d.defects = p.defects;
  return [d, r];
}

function getNameAddr(v) {
  const n = tl("NameAddr", "name-addr");
  let leader = null, token;
  if (!v) throw new HeaderParseError("expected name-addr");
  if (CFWS_LEADER.has(v[0])) {
    [leader, v] = getCfws(v);
    if (!v) throw new HeaderParseError("expected name-addr");
  }
  if (v[0] !== "<") {
    if (PHRASE_ENDS.has(v[0])) throw new HeaderParseError("expected name-addr");
    [token, v] = getDisplayName(v);
    if (!v) throw new HeaderParseError("expected name-addr");
    if (leader !== null) {
      if (isTL(token.items[0])) token.items[0].items.unshift(leader); else token.items.unshift(leader);
      leader = null;
    }
    n.items.push(token);
  }
  [token, v] = getAngleAddr(v);
  if (leader !== null) token.items.unshift(leader);
  n.items.push(token);
  return [n, v];
}

function getMailbox(v) {
  const m = tl("Mailbox", "mailbox");
  let token;
  try { [token, v] = getNameAddr(v); }
  catch (e) {
    if (!(e instanceof HeaderParseError)) throw e;
    try { [token, v] = getAddrSpec(v); }
    catch (e2) { if (!(e2 instanceof HeaderParseError)) throw e2; throw new HeaderParseError("expected mailbox"); }
  }
  m.items.push(token);
  return [m, v];
}

function getInvalidMailbox(v, endchars) {
  const m = tl("InvalidMailbox", "invalid-mailbox");
  while (v && !endchars.includes(v[0])) {
    if (PHRASE_ENDS.has(v[0])) { m.items.push(V(v[0], "misplaced-special")); v = v.slice(1); }
    else { let token; [token, v] = getPhrase(v); m.items.push(token); }
  }
  return [m, v];
}

function getMailboxList(v) {
  const ml = tl("MailboxList", "mailbox-list");
  while (v && v[0] !== ";") {
    try { const [t, r] = getMailbox(v); ml.items.push(t); v = r; }
    catch (e) {
      if (!(e instanceof HeaderParseError)) throw e;
      let leader = null, token;
      if (CFWS_LEADER.has(v[0])) {
        [leader, v] = getCfws(v);
        if (!v || ",;".includes(v[0])) ml.items.push(leader);
        else {
          [token, v] = getInvalidMailbox(v, ",;");
          if (leader !== null) token.items.unshift(leader);
          ml.items.push(token);
        }
      } else if (v[0] !== ",") {
        [token, v] = getInvalidMailbox(v, ",;");
        ml.items.push(token);
      }
    }
    if (v && !",;".includes(v[0])) {
      const mb = last(ml);
      mb.tt = "invalid-mailbox";
      let token;
      [token, v] = getInvalidMailbox(v, ",;");
      mb.items.push(...token.items);
    }
    if (v && v[0] === ",") { ml.items.push(V(",", "list-separator")); v = v.slice(1); }
  }
  return [ml, v];
}

function getGroupList(v) {
  const g = tl("GroupList", "group-list");
  if (!v) return [g, v];
  let leader = null, token;
  if (v && CFWS_LEADER.has(v[0])) {
    [leader, v] = getCfws(v);
    if (!v) { g.items.push(leader); return [g, v]; }
    if (v[0] === ";") { g.items.push(leader); return [g, v]; }
  }
  [token, v] = getMailboxList(v);
  if (allMailboxes(token).length === 0) {
    if (leader !== null) g.items.push(leader);
    g.items.push(...token.items);
    return [g, v];
  }
  if (leader !== null) token.items.unshift(leader);
  g.items.push(token);
  return [g, v];
}

function getGroup(v) {
  const g = tl("Group", "group");
  let token;
  [token, v] = getDisplayName(v);
  if (!v || v[0] !== ":") throw new HeaderParseError("expected ':'");
  g.items.push(token);
  g.items.push(V(":", "group-display-name-terminator"));
  v = v.slice(1);
  if (v && v[0] === ";") { g.items.push(V(";", "group-terminator")); return [g, v.slice(1)]; }
  [token, v] = getGroupList(v);
  g.items.push(token);
  if (v && v[0] !== ";") throw new HeaderParseError("expected ';'");
  g.items.push(V(";", "group-terminator"));
  v = v.slice(1);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); g.items.push(token); }
  return [g, v];
}

function getAddress(v) {
  const a = tl("Address", "address");
  let token;
  try { [token, v] = getGroup(v); }
  catch (e) {
    if (!(e instanceof HeaderParseError)) throw e;
    try { [token, v] = getMailbox(v); }
    catch (e2) { if (!(e2 instanceof HeaderParseError)) throw e2; throw new HeaderParseError("expected address"); }
  }
  a.items.push(token);
  return [a, v];
}

function getAddressList(v) {
  const al = tl("TokenList", "address-list");
  while (v) {
    try { const [t, r] = getAddress(v); al.items.push(t); v = r; }
    catch (e) {
      if (!(e instanceof HeaderParseError)) throw e;
      let leader = null, token;
      if (CFWS_LEADER.has(v[0])) {
        [leader, v] = getCfws(v);
        if (!v || v[0] === ",") al.items.push(leader);
        else {
          [token, v] = getInvalidMailbox(v, ",");
          if (leader !== null) token.items.unshift(leader);
          al.items.push(tl("Address", "address", [token]));
        }
      } else if (v[0] !== ",") {
        [token, v] = getInvalidMailbox(v, ",");
        al.items.push(tl("Address", "address", [token]));
      }
    }
    if (v && v[0] !== ",") {
      let token;
      [token, v] = getInvalidMailbox(v, ",");
      al.items.push(tl("Address", "address", [token]));
    }
    if (v) { al.items.push(V(",", "list-separator")); v = v.slice(1); }
  }
  return al;
}

// ------------------------------------------------------------ headerregistry strings

function addrSpecString(username, dom) {
  let lp = username;
  if (!disjoint(DOT_ATOM_ENDS, lp)) lp = quoteString(lp);
  if (dom) return lp + "@" + dom;
  if (!lp) return "<>";
  return lp;
}

function addressString(disp, username, dom) {
  if (!disjoint(SPECIALS, disp)) disp = quoteString(disp);
  const spec = addrSpecString(username, dom);
  if (disp) return `${disp} <${spec === "<>" ? "" : spec}>`;
  return spec;
}

function groupString(disp, addrs) {
  if (disp === null && addrs.length === 1) return addrs[0];
  if (disp !== null && !disjoint(SPECIALS, disp)) disp = quoteString(disp);
  const a = addrs.join(", ");
  return `${disp === null ? "None" : disp}:${a ? " " + a : a};`;
}

/** str() of an AddressHeader (From, Reply-To, To, Cc) under policy.default. */
export function addressHeader(raw) {
  const al = getAddressList(raw);
  const groups = al.items.filter((x) => x.tt === "address").map((addr) => {
    const disp = addr.items[0].tt === "group" ? displayName(addr.items[0].items[0]) : null;
    const addrs = allMailboxes(addr).map((mb) => addressString(mailboxDisplayName(mb) || "", localPart(mb) || "", domain(mb) || ""));
    return groupString(disp, addrs);
  });
  return sanitize(groups.join(", "));
}

/** str() of an UnstructuredHeader. */
export function unstructuredHeader(raw) {
  return sanitize(str(getUnstructured(raw)));
}

// ------------------------------------------------------------ MIME headers

function getTtext(v) {
  const m = matchRun(v, TOKEN_ENDS);
  if (!m) throw new HeaderParseError("expected ttext");
  return [V(m, "ttext"), v.slice(m.length)];
}

function getToken(v) {
  const t = tl("TokenList", "token");
  let token;
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); t.items.push(token); }
  if (v && TOKEN_ENDS.has(v[0])) throw new HeaderParseError("expected token");
  [token, v] = getTtext(v);
  t.items.push(token);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); t.items.push(token); }
  return [t, v];
}

function getAttrtext(v, ends = ATTRIBUTE_ENDS, tt = "attrtext") {
  const m = matchRun(v, ends);
  if (!m) throw new HeaderParseError("expected attrtext");
  return [V(m, tt), v.slice(m.length)];
}
const getExtendedAttrtext = (v) => getAttrtext(v, EXTENDED_ATTRIBUTE_ENDS, "extended-attrtext");

function getAttribute(v, ends = ATTRIBUTE_ENDS, textFn = getAttrtext) {
  const a = tl("Attribute", "attribute");
  let token;
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  if (v && ends.has(v[0])) throw new HeaderParseError("expected token");
  [token, v] = textFn(v);
  a.items.push(token);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); a.items.push(token); }
  return [a, v];
}
const getExtendedAttribute = (v) => getAttribute(v, EXTENDED_ATTRIBUTE_ENDS, getExtendedAttrtext);

function getSection(v) {
  const s = tl("TokenList", "section");
  if (!v || v[0] !== "*") throw new HeaderParseError("Expected section");
  s.items.push(V("*", "section-marker"));
  v = v.slice(1);
  if (!v || !/\p{Nd}/u.test(v[0])) throw new HeaderParseError("Expected section number");
  let digits = "";
  while (v && /\p{Nd}/u.test(v[0])) { digits += v[0]; v = v.slice(1); }
  s.number = parseInt(digits, 10);
  s.items.push(V(digits, "digits"));
  return [s, v];
}

function getValue(v) {
  const val = tl("Value", "value");
  if (!v) throw new HeaderParseError("Expected value");
  let leader = null, token;
  if (CFWS_LEADER.has(v[0])) [leader, v] = getCfws(v);
  if (!v) throw new HeaderParseError("Expected value");
  if (v[0] === '"') [token, v] = getQuotedString(v); else [token, v] = getExtendedAttribute(v);
  if (leader !== null) token.items.unshift(leader);
  val.items.push(token);
  return [val, v];
}

function strippedValue(t) {
  if (t.kind === "Value") {
    let tok = t.items[0];
    if (tok.tt === "cfws") tok = t.items[1];
    if (/(quoted-string|attribute|extended-attribute)$/.test(tok.tt)) return strippedValue(tok);
    return value(t);
  }
  if (t.kind === "QuotedString" || t.kind === "BareQuotedString") {
    const b = t.items.find((x) => x.tt === "bare-quoted-string");
    return b ? value(b) : null;
  }
  if (t.kind === "Attribute") { const a = t.items.find((x) => x.tt.endsWith("attrtext")); return a ? value(a) : null; }
  return null;
}

function getParameter(v) {
  const param = tl("Parameter", "parameter");
  param.sectioned = false; param.extended = false; param.charset = "us-ascii";
  let token;
  [token, v] = getAttribute(v);
  param.items.push(token);
  if (!v || v[0] === ";") return [param, v];
  if (v[0] === "*") {
    try { [token, v] = getSection(v); param.sectioned = true; param.items.push(token); }
    catch (e) { if (!(e instanceof HeaderParseError)) throw e; }
    if (!v) throw new HeaderParseError("Incomplete parameter");
    if (v[0] === "*") { param.items.push(V("*", "extended-parameter-marker")); v = v.slice(1); param.extended = true; }
  }
  if (v[0] !== "=") throw new HeaderParseError("Parameter not followed by '='");
  param.items.push(V("=", "parameter-separator"));
  v = v.slice(1);
  if (v && CFWS_LEADER.has(v[0])) { [token, v] = getCfws(v); param.items.push(token); }
  let remainder = null, appendto = param;
  const sectionNumber = () => (param.sectioned ? param.items[1].number : 0);
  if (param.extended && v && v[0] === '"') {
    const [qstring, rem] = getQuotedString(v);
    remainder = rem;
    const inner = strippedValue(qstring);
    let semiValid = false;
    if (sectionNumber() === 0) {
      if (inner && inner[0] === "'") semiValid = true;
      else { const [, rest] = getAttrtext(inner); if (rest && rest[0] === "'") semiValid = true; }
    } else {
      try { const [, rest] = getExtendedAttrtext(inner); if (!rest) semiValid = true; }
      catch { /* as in Python: ignored */ }
    }
    if (semiValid) {
      param.items.push(qstring);
      for (const t of qstring.items) if (t.tt === "bare-quoted-string") { t.items = []; appendto = t; break; }
      v = inner;
    } else remainder = null;
  }
  if (v && v[0] === "'") token = null; else [token, v] = getValue(v);
  if (!param.extended || sectionNumber() > 0) {
    if (!v || v[0] !== "'") {
      appendto.items.push(token);
      if (remainder !== null) v = remainder;
      return [param, v];
    }
  }
  if (!v) {
    appendto.items.push(token);
    if (remainder === null) return [param, v];
  } else {
    if (token !== null) {
      let t;
      for (t of token.items) if (t.tt === "extended-attrtext") break;
      appendto.items.push(t);
      param.charset = value(t);
    }
    if (v[0] !== "'") throw new HeaderParseError("Expected RFC2231 char/lang encoding delimiter");
    appendto.items.push(V("'", "RFC2231-delimiter"));
    v = v.slice(1);
    if (v && v[0] !== "'") {
      [token, v] = getAttrtext(v);
      appendto.items.push(token);
      if (!v || v[0] !== "'") throw new HeaderParseError("Expected RFC2231 char/lang encoding delimiter");
    }
    appendto.items.push(V("'", "RFC2231-delimiter"));
    v = v.slice(1);
  }
  if (remainder !== null) {
    const val = tl("Value", "value");
    while (v) {
      let t;
      if (WSP.has(v[0])) [t, v] = getFws(v);
      else if (v[0] === '"') { t = V('"', "DQUOTE"); v = v.slice(1); }
      else [t, v] = getQcontent(v);
      val.items.push(t);
    }
    token = val;
  } else [token, v] = getValue(v);
  appendto.items.push(token);
  if (remainder !== null) v = remainder;
  return [param, v];
}

function getInvalidParameter(v) {
  const p = tl("Parameter", "invalid-parameter");
  p.sectioned = false; p.extended = false; p.charset = "us-ascii";
  while (v && v[0] !== ";") {
    if (PHRASE_ENDS.has(v[0])) { p.items.push(V(v[0], "misplaced-special")); v = v.slice(1); }
    else { let token; [token, v] = getPhrase(v); p.items.push(token); }
  }
  return [p, v];
}

function parseMimeParameters(v) {
  const mp = tl("MimeParameters", "mime-parameters");
  while (v) {
    try { const [t, r] = getParameter(v); mp.items.push(t); v = r; }
    catch (e) {
      if (!(e instanceof HeaderParseError)) throw e;
      let leader = null, token;
      if (CFWS_LEADER.has(v[0])) [leader, v] = getCfws(v);
      if (!v) { mp.items.push(leader); return mp; }
      if (v[0] === ";") { if (leader !== null) mp.items.push(leader); }
      else {
        [token, v] = getInvalidParameter(v);
        if (leader && leader.items.length) token.items.unshift(leader);
        mp.items.push(token);
      }
    }
    if (v && v[0] !== ";") {
      const param = last(mp);
      param.tt = "invalid-parameter";
      let token;
      [token, v] = getInvalidParameter(v);
      param.items.push(...token.items);
    }
    if (v) { mp.items.push(V(";", "parameter-separator")); v = v.slice(1); }
  }
  return mp;
}

// urllib.parse.unquote_to_bytes on the ASCII / surrogate-escaped value
function unquoteToBytes(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (s[i] === "%" && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) { bytes.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; }
    else if (c < 0x80) bytes.push(c);
    else return null; // Python: UnicodeEncodeError path
  }
  return Uint8Array.from(bytes);
}

/** MimeParameters.params */
function mimeParams(mp) {
  const byName = new Map();
  for (const t of mp.items) {
    if (!t.tt || !t.tt.endsWith("parameter") || t.term) continue;
    if (t.items[0]?.tt !== "attribute") continue;
    const name = strip(value(t.items[0]));
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push([t.sectioned ? t.items[1].number : 0, t]);
  }
  const out = [];
  for (const [name, partsIn] of byName) {
    let parts = [...partsIn].sort((a, b) => a[0] - b[0]);
    const first = parts[0][1];
    const charset = first.charset;
    if (!first.extended && parts.length > 1 && parts[1][0] === 0) parts = parts.slice(0, 1);
    const values = [];
    let i = 0;
    for (const [sn, param] of parts) {
      if (sn !== i && !param.extended) continue;
      i++;
      let val = paramValue(param);
      if (param.extended) {
        const bytes = unquoteToBytes(val);
        if (bytes === null) val = latin1Unquote(val);
        else {
          try { val = decode(bytes, charset, "surrogateescape"); }
          catch (e) { if (e instanceof LookupError) val = decode(bytes, "ascii", "surrogateescape"); else throw e; }
        }
      }
      values.push(val);
    }
    out.push([name, values.join("")]);
  }
  return out;
}

function latin1Unquote(s) {
  return s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function paramValue(param) {
  for (const t of param.items) {
    if (t.tt === "value") return strippedValue(t);
    if (t.tt === "quoted-string") {
      for (const b of t.items) if (b.tt === "bare-quoted-string") for (const x of b.items) if (x.tt === "value") return strippedValue(x);
    }
  }
  return "";
}

function findMimeParameters(list, v) {
  while (v && v[0] !== ";") {
    if (PHRASE_ENDS.has(v[0])) { list.items.push(V(v[0], "misplaced-special")); v = v.slice(1); }
    else { let token; [token, v] = getPhrase(v); list.items.push(token); }
  }
  if (!v) return;
  list.items.push(V(";", "parameter-separator"));
  list.items.push(parseMimeParameters(v.slice(1)));
}

function parseContentType(v) {
  const c = tl("TokenList", "content-type");
  if (!v) return c;
  let token;
  try { [token, v] = getToken(v); }
  catch (e) { if (!(e instanceof HeaderParseError)) throw e; findMimeParameters(c, v); return c; }
  c.items.push(token);
  if (!v || v[0] !== "/") { if (v) findMimeParameters(c, v); return c; }
  c.items.push(V("/", "content-type-separator"));
  v = v.slice(1);
  try { [token, v] = getToken(v); }
  catch (e) { if (!(e instanceof HeaderParseError)) throw e; findMimeParameters(c, v); return c; }
  c.items.push(token);
  if (!v) return c;
  if (v[0] !== ";") { findMimeParameters(c, v); return c; }
  c.items.push(V(";", "parameter-separator"));
  c.items.push(parseMimeParameters(v.slice(1)));
  return c;
}

function parseContentDisposition(v) {
  const c = tl("TokenList", "content-disposition");
  if (!v) return c;
  let token;
  try { [token, v] = getToken(v); }
  catch (e) { if (!(e instanceof HeaderParseError)) throw e; findMimeParameters(c, v); return c; }
  c.items.push(token);
  if (!v) return c;
  if (v[0] !== ";") { findMimeParameters(c, v); return c; }
  c.items.push(V(";", "parameter-separator"));
  c.items.push(parseMimeParameters(v.slice(1)));
  return c;
}

/** str() of a ContentTypeHeader / ContentDispositionHeader. */
export function mimeHeader(name, raw) {
  const tree = name === "content-type" ? parseContentType(raw) : parseContentDisposition(raw);
  return sanitize(str(tree));
}

/** ContentTransferEncodingHeader.cte */
export function cteHeader(raw) {
  if (!raw) return "7bit";
  try {
    const [token] = getToken(raw);
    return sanitize(strip(value(token)).toLowerCase());
  } catch (e) {
    if (!(e instanceof HeaderParseError)) throw e;
    return "7bit";
  }
}
