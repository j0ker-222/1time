import { describe, expect, it } from "vitest";
import { RANDOM_KEY_LEN, decryptMessage, encryptMessage, generatePassword, hashKey, parseLink, randomString } from "./crypto.js";

describe("crypto", () => {
  it("round-trips unicode text", () => {
    const ct = encryptMessage("пароль: p@ss 🔑", "keyABC123456");
    expect(ct.startsWith("U2FsdGVkX1")).toBe(true); // "Salted__"
    expect(decryptMessage(ct, "keyABC123456")).toBe("пароль: p@ss 🔑");
  });

  it("decrypts messages created by the old frontend (crypto-js 3.3.0)", () => {
    const ct =
      "U2FsdGVkX19Qi+pKv1INLFNhHq+vqs/aBfx+ZwK3sKnI5sSpkJZnIlZ0erjrU+YuqBeTQF0MQ719gSET8qfrlbPyrvqLpdTKg9qqWrK3n+w=";
    expect(decryptMessage(ct, "myKeyabcDEF123456789")).toBe("секрет из старой версии 1time");
  });

  it("decrypts messages created by the Go backend (/api/unsecSave)", () => {
    const ct = "U2FsdGVkX19zkF8+Os4Wizl2+Bg1/+9Do9ZQ69aSFT2AuZmEFr5tz9+ybivKnvHb";
    expect(decryptMessage(ct, "GoKey1234567")).toBe("сообщение из Go");
  });

  it("hashes keys with SHA-256 hex like the backend expects", () => {
    expect(hashKey("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("generates uniform random keys from the CSPRNG", () => {
    const seen = new Set();
    for (let i = 0; i < 500; i++) {
      const k = randomString(RANDOM_KEY_LEN);
      expect(k).toMatch(/^[A-Za-z0-9]{12}$/);
      seen.add(k);
    }
    expect(seen.size).toBe(500);
    expect(generatePassword()).toHaveLength(16);
  });

  it("parses new and old link formats", () => {
    expect(parseLink("https://x/v/#abcdefghijkl0123abcd")).toEqual({ randomKey: "abcdefghijkl", id: "0123abcd" });
    expect(parseLink("https://x/v/abcdefghijkl1f")).toEqual({ randomKey: "abcdefghijkl", id: "1f" });
    expect(parseLink("https://x/v/#short")).toBeNull();
  });
});
