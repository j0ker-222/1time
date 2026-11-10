// 1time message formats on Web Crypto. The same formats are implemented in
// Go (internal/otcrypto) and both are checked against shared test vectors.
//
// Format v3 (current, short links):
//   linkKey = 16 random bytes, the whole URL fragment: /v/#<base64url> (22 chars)
//   id      = hex(HKDF-SHA256(linkKey, "1time v3 id", 16))   -> message id on the server
//   IKM     = linkKey                                   (no additional secret)
//   IKM     = linkKey || PBKDF2-SHA256(secret, HKDF(linkKey, "1time v3 pbkdf2 salt", 16),
//                                      600000 iterations, 32 bytes)
//   encKey  = HKDF-SHA256(IKM, salt "", info "1time v3 enc")   -> AES-256-GCM
//   token   = hex(HKDF-SHA256(IKM, salt "", info "1time v3 auth"))  -> server access
//   payload = "v3:" + base64(iv(12) || ciphertext || tag(16)), AAD "1time v3"
//
// Format v2 (read only): the same with a 32-byte link key, "v2" in the info
// strings, AAD and prefix, and a server id in the link: /v/#v2.<key>.<id>
//
// AES-GCM authenticates the ciphertext, so any change to it is detected.

export const LINK_PREFIX_V2 = "v2.";
export const LINK_KEY_LEN = 16;
export const LINK_KEY_LEN_V2 = 32;
export const FRAGMENT_LEN = 22;
export const PBKDF2_ITERATIONS = 600000;
const IV_LEN = 12;
const enc = new TextEncoder();

const FORMATS = {
  [LINK_KEY_LEN]: { v: "v3", prefix: "v3:", id: true },
  [LINK_KEY_LEN_V2]: { v: "v2", prefix: "v2:", id: false },
};

function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error("Web Crypto is not available (the page must be opened over https)");
  return s;
}

// ---- encoding helpers

function bytesToBinary(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return s;
}

function binaryToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const toBase64 = (b) => btoa(bytesToBinary(b));
export const fromBase64 = (s) => binaryToBytes(atob(s));
export const toBase64Url = (b) => toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export function fromBase64Url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return fromBase64(b64 + "===".slice((b64.length + 3) % 4));
}
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ---- key derivation

async function hkdf(ikm, info, length) {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

export function newLinkKey() {
  return globalThis.crypto.getRandomValues(new Uint8Array(LINK_KEY_LEN));
}

export async function deriveKeys(linkKey, secret = "") {
  const f = linkKey instanceof Uint8Array ? FORMATS[linkKey.length] : undefined;
  if (!f) throw new Error("bad link key");
  let ikm = linkKey;
  if (secret) {
    const salt = await hkdf(linkKey, `1time ${f.v} pbkdf2 salt`, 16);
    const pw = await subtle().importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
    const p = new Uint8Array(
      await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, pw, 256)
    );
    ikm = new Uint8Array(linkKey.length + p.length);
    ikm.set(linkKey);
    ikm.set(p, linkKey.length);
  }
  const encKeyBytes = await hkdf(ikm, `1time ${f.v} enc`, 32);
  const token = toHex(await hkdf(ikm, `1time ${f.v} auth`, 32));
  // v3: the message id depends on the link key only, not on the secret.
  const id = f.id ? toHex(await hkdf(linkKey, "1time v3 id", 16)) : "";
  const encKey = await subtle().importKey("raw", encKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { encKey, token, id, format: f };
}

// ---- encryption

export async function encryptWithIV(keys, iv, text) {
  const ct = new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(`1time ${keys.format.v}`) },
      keys.encKey,
      enc.encode(text)
    )
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return keys.format.prefix + toBase64(out);
}

export function encrypt(keys, text) {
  return encryptWithIV(keys, globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN)), text);
}

export async function decrypt(keys, payload) {
  const prefix = keys.format.prefix;
  if (typeof payload !== "string" || !payload.startsWith(prefix)) throw new Error(`not a ${prefix} payload`);
  const raw = fromBase64(payload.slice(prefix.length));
  if (raw.length < IV_LEN + 16) throw new Error("payload too short");
  const pt = await subtle().decrypt(
    { name: "AES-GCM", iv: raw.subarray(0, IV_LEN), additionalData: enc.encode(`1time ${keys.format.v}`) },
    keys.encKey,
    raw.subarray(IV_LEN)
  );
  return new TextDecoder("utf-8", { fatal: true }).decode(pt);
}

// ---- links

// v3: the fragment is the link key alone (the id is derived from it).
// v2 keys (32 bytes) still produce "v2.<key>.<id>".
export function fragment(linkKey, id) {
  if (linkKey.length === LINK_KEY_LEN_V2) return LINK_PREFIX_V2 + toBase64Url(linkKey) + "." + id;
  return toBase64Url(linkKey);
}

// Returns { version, linkKey, id } or null. For v3 id is null: take it
// from deriveKeys().
export function parseFragment(frag) {
  if (frag.startsWith(LINK_PREFIX_V2)) {
    const parts = frag.slice(LINK_PREFIX_V2.length).split(".");
    if (parts.length !== 2 || !parts[1]) return null;
    try {
      const linkKey = fromBase64Url(parts[0]);
      if (linkKey.length !== LINK_KEY_LEN_V2) return null;
      return { version: 2, linkKey, id: parts[1] };
    } catch {
      return null;
    }
  }
  if (frag.length !== FRAGMENT_LEN) return null;
  try {
    const linkKey = fromBase64Url(frag);
    return linkKey.length === LINK_KEY_LEN ? { version: 3, linkKey, id: null } : null;
  } catch {
    return null;
  }
}
