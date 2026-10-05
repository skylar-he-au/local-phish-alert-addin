// Link-protection services (MVP-PRD R10, decision D27). An organisation's mail gateway
// rewrites every link so that clicks go through its own checking service first; Mimecast
// at UOW turns each link into url.au.m.mimecastprotect.com/s/...?domain=parcel.io.
// The links rule then sees "says parcel.io but goes to mimecastprotect.com" on every
// genuine email, and the model sees only the gateway's domain. The product therefore
// puts back the original address, or at least its domain, before the rules and the model
// look at the email. Product only: the evaluation corpora contain no rewritten links, and
// the Python pipeline has no such step.

const URL_IN_TEXT = /https?:\/\/[^\s"'<>()]+/gi;

const MIMECAST = /(?:^|\.)(?:mimecastprotect\.com|mimecast\.com)$/;
const SAFELINKS = /\.safelinks\.protection\.outlook\.com$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** The address a protected link stands for, or null if `u` is not one (or cannot be read). */
export function originalUrl(u) {
  let url;
  try { url = new URL(u.replace(/&amp;/g, "&")); } catch { return null; }
  const host = url.hostname.toLowerCase();
  if (MIMECAST.test(host) && url.pathname.startsWith("/s/")) {
    // Mimecast keeps only the original domain, in ?domain=
    const d = (url.searchParams.get("domain") || "").toLowerCase();
    return DOMAIN.test(d) ? `https://${d}/` : null;
  }
  if (SAFELINKS.test(host)) {
    const t = url.searchParams.get("url") || "";
    return /^https?:\/\//i.test(t) ? t : null;
  }
  if (host === "urldefense.com") {
    // Proofpoint v3: urldefense.com/v3/__<original>__;!!...
    const m = /^\/v3\/__(https?:\/\/.+?)__;/.exec(url.pathname + url.search);
    return m ? m[1] : null;
  }
  return null;
}

const swap = (u) => originalUrl(u) || u;
const swapAll = (text) => (text || "").replace(URL_IN_TEXT, swap);

/** A copy of a parsed email with protected links replaced by the addresses they stand for. */
export function unwrapLinks(email) {
  return {
    ...email,
    body: swapAll(email.body),
    raw_html: swapAll(email.raw_html),
    links: [...new Set(email.links.map(swap))],
    anchors: email.anchors.map(([label, href]) => [swapAll(label), swap(href)]),
  };
}
