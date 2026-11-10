// Reading links created before the v2 format (AES-CBC via CryptoJS with the
// MD5 EVP_BytesToKey KDF). Used only to open messages that were created by
// the old version and have not expired yet (at most 30 days after the
// upgrade). New messages never use this code. This module is loaded on
// demand, so crypto-js is not downloaded for v2 links.
//
// TODO: remove this file and the crypto-js dependency 30 days after the
// v2 release is deployed.
import AES from "crypto-js/aes";
import SHA256 from "crypto-js/sha256";
import Utf8 from "crypto-js/enc-utf8";

export function legacyHashKey(passphrase) {
  return SHA256(passphrase).toString();
}

export function legacyDecrypt(ciphertext, passphrase) {
  return AES.decrypt(ciphertext, passphrase).toString(Utf8);
}

// Test-only helper to produce legacy fixtures.
export function legacyEncrypt(message, passphrase) {
  return AES.encrypt(message, passphrase).toString();
}
