import { describe, expect, it } from "vitest";
import {
  decrypt,
  deriveKeys,
  encrypt,
  encryptWithIV,
  fragment,
  fromBase64Url,
  newLinkKey,
  parseFragment,
  PBKDF2_ITERATIONS,
} from "./cryptoV2.js";

const hex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

// Same vectors as internal/otcrypto/otcrypto_test.go (also checked with Python).
const VEC = {
  linkKey: hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
  iv: hex("a0a1a2a3a4a5a6a7a8a9aaab"),
  text: "Привет, 1time v2!",
  noSecret: {
    token: "692195aedeeaec0ac11b9524076f43bb2c4cb99fe26896044e9da1b823d5ede0",
    payload: "v2:oKGio6SlpqeoqaqrA14HlIi5DmmE3y3iA1A3RDDfkkskG5oIrAUqDQ1Ry7aCWYJarIOp",
  },
  secret: "correct horse",
  withSecret: {
    token: "63ee307f23de4aee4f2bfac590504cdad8269f08e7549eb5c22960c4ca81d82f",
    payload: "v2:oKGio6Slpqeoqaqr1OEWbNACI9Z1WkAIFNdxsknHNvTB76+A21XimRl8XbToLxAxBzxb",
  },
};

describe("format v2 (Web Crypto)", () => {
  it("uses 600000 PBKDF2 iterations", () => {
    expect(PBKDF2_ITERATIONS).toBe(600000);
  });

  it("matches the Go/Python vectors without a secret", async () => {
    const k = await deriveKeys(VEC.linkKey);
    expect(k.token).toBe(VEC.noSecret.token);
    expect(await encryptWithIV(k, VEC.iv, VEC.text)).toBe(VEC.noSecret.payload);
  });

  it("matches the Go/Python vectors with an additional secret", async () => {
    const k = await deriveKeys(VEC.linkKey, VEC.secret);
    expect(k.token).toBe(VEC.withSecret.token);
    expect(await encryptWithIV(k, VEC.iv, VEC.text)).toBe(VEC.withSecret.payload);
  });

  it("decrypts a message encrypted by the Go backend", async () => {
    const link = parseFragment("v2.awoKxDBa7HspPx38MgiMdJYdn3z8lODCKhdcsPRVEtk.1");
    const k = await deriveKeys(link.linkKey, "go-secret");
    expect(k.token).toBe("828d5473bd95d1e5078fd626903fb0535361dab9cc38629482b9b571829ae887");
    const payload = "v2:zLjpoLMk8W3EeuoTz/hykLDajOfcK1Na/X9ptjA0Licf6JnIshoeTCeJyml9NkHF65ByJSLi5XMQ";
    expect(await decrypt(k, payload)).toBe("сообщение из Go v2");
  });

  it("round-trips and uses a fresh IV every time", async () => {
    const k = await deriveKeys(newLinkKey(), "x");
    const a = await encrypt(k, "same text");
    const b = await encrypt(k, "same text");
    expect(a).not.toBe(b);
    expect(await decrypt(k, a)).toBe("same text");
  });

  it("detects any modification of the ciphertext", async () => {
    const k = await deriveKeys(newLinkKey());
    const p = await encrypt(k, "do not change me");
    for (let i = 3; i < p.length - 2; i += 3) {
      const mod = p.slice(0, i) + (p[i] === "A" ? "B" : "A") + p.slice(i + 1);
      await expect(decrypt(k, mod)).rejects.toThrow();
    }
  });

  it("rejects a wrong secret", async () => {
    const lk = newLinkKey();
    const good = await deriveKeys(lk, "right");
    const bad = await deriveKeys(lk, "wrong");
    expect(bad.token).not.toBe(good.token);
    await expect(decrypt(bad, await encrypt(good, "m"))).rejects.toThrow();
  });

  it("builds and parses links", () => {
    const lk = newLinkKey();
    const f = fragment(lk, "0123abcd");
    expect(f).toMatch(/^v2\.[A-Za-z0-9_-]{43}\.0123abcd$/);
    const p = parseFragment(f);
    expect(Array.from(p.linkKey)).toEqual(Array.from(lk));
    expect(p.id).toBe("0123abcd");
    expect(parseFragment("v2.short.1")).toBeNull();
    expect(parseFragment("abcdefghijkl1f")).toBeNull();
    expect(() => fromBase64Url("a+b")).toThrow();
  });
});
