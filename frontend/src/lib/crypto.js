// Client-side encryption for one-time messages.
//
// The wire format is unchanged from the original 1time: AES-256-CBC in the
// OpenSSL "Salted__" format produced by CryptoJS.AES.encrypt(text, passphrase),
// and SHA-256 of the passphrase as the access token. Keeping it means links
// created before the upgrade still open, and /api/unsecSave (Go) stays
// compatible. What changed: all randomness now comes from
// crypto.getRandomValues (crypto-js 4.x also uses it for the salt).
import AES from "crypto-js/aes";
import SHA256 from "crypto-js/sha256";
import Utf8 from "crypto-js/enc-utf8";

export const RANDOM_KEY_LEN = 12;

const KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz123456789-_=+.,%:";

// Uniform random string over `alphabet` using rejection sampling.
export function randomString(length, alphabet = KEY_ALPHABET) {
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

export function encryptMessage(message, passphrase) {
  return AES.encrypt(message, passphrase).toString();
}

export function decryptMessage(ciphertext, passphrase) {
  return AES.decrypt(ciphertext, passphrase).toString(Utf8);
}

export function hashKey(passphrase) {
  return SHA256(passphrase).toString();
}

// Link fragment = 12-char random key + message id. Both the current
// "/v/#<fragment>" and the old "/v/<fragment>" forms are accepted.
export function parseLink(href) {
  let fragment = "";
  const hashPos = href.indexOf("#");
  if (hashPos >= 0) {
    fragment = href.slice(hashPos + 1);
  } else {
    const m = href.match(/\/v\/([^/?#]+)/);
    if (m) fragment = m[1];
  }
  if (fragment.length <= RANDOM_KEY_LEN) return null;
  return { randomKey: fragment.slice(0, RANDOM_KEY_LEN), id: fragment.slice(RANDOM_KEY_LEN) };
}
