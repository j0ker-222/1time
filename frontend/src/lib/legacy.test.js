import { describe, expect, it } from "vitest";
import { legacyDecrypt, legacyHashKey } from "./legacy.js";
import { generatePassword, parseLink } from "./crypto.js";

describe("old format (links created before v2)", () => {
  it("decrypts messages created by the old frontend (crypto-js 3.3.0)", () => {
    const ct =
      "U2FsdGVkX19Qi+pKv1INLFNhHq+vqs/aBfx+ZwK3sKnI5sSpkJZnIlZ0erjrU+YuqBeTQF0MQ719gSET8qfrlbPyrvqLpdTKg9qqWrK3n+w=";
    expect(legacyDecrypt(ct, "myKeyabcDEF123456789")).toBe("секрет из старой версии 1time");
  });

  it("decrypts messages created by the old Go unsecSave", () => {
    const ct = "U2FsdGVkX19zkF8+Os4Wizl2+Bg1/+9Do9ZQ69aSFT2AuZmEFr5tz9+ybivKnvHb";
    expect(legacyDecrypt(ct, "GoKey1234567")).toBe("сообщение из Go");
  });

  it("hashes the passphrase like the old version", () => {
    expect(legacyHashKey("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("links", () => {
  it("tells v2 and old links apart", () => {
    const v2 = parseLink("https://x/v/#v2." + "A".repeat(43) + ".0123abcd");
    expect(v2.version).toBe(2);
    expect(v2.id).toBe("0123abcd");
    expect(parseLink("https://x/v/#abcdefghijkl0123abcd")).toEqual({ version: 1, randomKey: "abcdefghijkl", id: "0123abcd" });
    expect(parseLink("https://x/v/abcdefghijkl1f")).toEqual({ version: 1, randomKey: "abcdefghijkl", id: "1f" });
    expect(parseLink("https://x/v/#short")).toBeNull();
    expect(parseLink("https://x/v/#v2.bad.1")).toBeNull();
  });

  it("generates passwords", () => {
    expect(generatePassword()).toHaveLength(16);
  });
});
