// 1time message format v2 on Web Crypto. The same format is implemented in
// Go (internal/otcrypto) and both are checked against shared test vectors.
//
//   linkKey = 32 random bytes, only in the URL fragment: /v/#v2.<base64url>.<id>
//   IKM     = linkKey                                   (no additional secret)
//   IKM     = linkKey || PBKDF2-SHA256(secret, HKDF(linkKey, "1time v2 pbkdf2 salt", 16),
//                                      600000 iterations, 32 bytes)
//   encKey  = HKDF-SHA256(IKM, salt "", info "1time v2 enc")   -> AES-256-GCM
//   token   = hex(HKDF-SHA256(IKM, salt "", info "1time v2 auth"))  -> server access
//   payload = "v2:" + base64(iv(12) || ciphertext || tag(16)), AAD "1time v2"
//
// AES-GCM authenticates the ciphertext, so any change to it is detected.

export const PAYLOAD_PREFIX = "v2:";
export const LINK_PREFIX = "v2.";
export const LINK_KEY_LEN = 32;
export const PBKDF2_ITERATIONS = 600000;
const IV_LEN = 12;
const AAD = new TextEncoder().encode("1time v2");
const enc = new TextEncoder();

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
  if (!(linkKey instanceof Uint8Array) || linkKey.length !== LINK_KEY_LEN) throw new Error("bad link key");
  let ikm = linkKey;
  if (secret) {
    const salt = await hkdf(linkKey, "1time v2 pbkdf2 salt", 16);
    const pw = await subtle().importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
    const p = new Uint8Array(
      await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, pw, 256)
    );
    ikm = new Uint8Array(LINK_KEY_LEN + p.length);
    ikm.set(linkKey);
    ikm.set(p, LINK_KEY_LEN);
  }
  const encKeyBytes = await hkdf(ikm, "1time v2 enc", 32);
  const token = toHex(await hkdf(ikm, "1time v2 auth", 32));
  const encKey = await subtle().importKey("raw", encKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { encKey, token };
}

// ---- encryption

export async function encryptWithIV(keys, iv, text) {
  const ct = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv, additionalData: AAD }, keys.encKey, enc.encode(text))
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return PAYLOAD_PREFIX + toBase64(out);
}

export function encrypt(keys, text) {
  return encryptWithIV(keys, globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN)), text);
}

export async function decrypt(keys, payload) {
  if (typeof payload !== "string" || !payload.startsWith(PAYLOAD_PREFIX)) throw new Error("not a v2 payload");
  const raw = fromBase64(payload.slice(PAYLOAD_PREFIX.length));
  if (raw.length < IV_LEN + 16) throw new Error("payload too short");
  const pt = await subtle().decrypt(
    { name: "AES-GCM", iv: raw.subarray(0, IV_LEN), additionalData: AAD },
    keys.encKey,
    raw.subarray(IV_LEN)
  );
  return new TextDecoder("utf-8", { fatal: true }).decode(pt);
}

// ---- links

export function fragment(linkKey, id) {
  return LINK_PREFIX + toBase64Url(linkKey) + "." + id;
}

export function parseFragment(frag) {
  if (!frag.startsWith(LINK_PREFIX)) return null;
  const parts = frag.slice(LINK_PREFIX.length).split(".");
  if (parts.length !== 2 || !parts[1]) return null;
  try {
    const linkKey = fromBase64Url(parts[0]);
    if (linkKey.length !== LINK_KEY_LEN) return null;
    return { linkKey, id: parts[1] };
  } catch {
    return null;
  }
}
