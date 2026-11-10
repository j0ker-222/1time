// Link parsing and helpers shared by the pages.
//
// New messages use format v2 (./cryptoV2.js: AES-256-GCM, HKDF, PBKDF2).
// Links of the old format are still opened through ./legacy.js.
import { parseFragment } from "./cryptoV2.js";

export const LEGACY_KEY_LEN = 12;

const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz123456789-_=+.,%:";

// Uniform random string over `alphabet` using rejection sampling.
export function randomString(length, alphabet) {
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    const buf = new Uint8Array(length * 2);
    globalThis.crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b >= limit) continue;
      out += alphabet[b % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}

export function generatePassword() {
  return randomString(16, PASSWORD_ALPHABET);
}

// Accepts "/v/#v2.<key>.<id>" (v2), "/v/#<12 chars><id>" and "/v/<12 chars><id>"
// (old format). Returns null for anything else.
export function parseLink(href) {
  let frag = "";
  const hashPos = href.indexOf("#");
  if (hashPos >= 0) {
    frag = href.slice(hashPos + 1);
  } else {
    const m = href.match(/\/v\/([^/?#]+)/);
    if (m) frag = m[1];
  }
  if (frag.startsWith("v2.")) {
    const v2 = parseFragment(frag);
    return v2 ? { version: 2, ...v2 } : null;
  }
  if (frag.length <= LEGACY_KEY_LEN || !/^[A-Za-z0-9]+$/.test(frag)) return null;
  return { version: 1, randomKey: frag.slice(0, LEGACY_KEY_LEN), id: frag.slice(LEGACY_KEY_LEN) };
}
