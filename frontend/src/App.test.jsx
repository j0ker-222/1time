import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import App from "./App.jsx";
import { legacyEncrypt, legacyHashKey } from "./lib/legacy.js";
import { deriveKeys, encrypt, fragment } from "./lib/cryptoV2.js";

// In-memory stand-in for the Go API with the same one-time semantics.
function fakeBackend() {
  const db = new Map();
  let n = 0;
  const fn = vi.fn(async (url, init) => {
    const body = JSON.parse(init.body);
    let data;
    if (url.endsWith("/saveSecret")) {
      const id = body.id || (++n).toString(16).padStart(32, "0");
      if (db.has(id)) {
        data = { status: "id taken", newId: "0" };
      } else {
        db.set(id, { message: body.secretMessage, hashedKey: body.hashedKey });
        data = { status: "ok", newId: id };
      }
    } else if (url.endsWith("/get")) {
      const rec = db.get(body.id);
      if (!rec) data = { status: "no message", cryptedMessage: "0" };
      else if (rec.hashedKey !== body.hashedKey) data = { status: "wrong key", cryptedMessage: "0" };
      else {
        db.delete(body.id);
        data = { status: "ok", cryptedMessage: rec.message };
      }
    }
    return { ok: true, status: 200, json: async () => data };
  });
  fn.db = db;
  return fn;
}

let originalHref;
let backend;
beforeEach(() => {
  originalHref = window.location.href;
  backend = fakeBackend();
  globalThis.fetch = backend;
});
afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", originalHref);
});

async function createLink(text, secret) {
  render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>
  );
  fireEvent.change(screen.getByLabelText("One-time Message"), { target: { value: text } });
  if (secret) {
    fireEvent.click(screen.getByText("Options"));
    fireEvent.change(screen.getByLabelText("Additional Secret Key:"), { target: { value: secret } });
  }
  fireEvent.click(screen.getByText("Get a link"));
  const input = await screen.findByDisplayValue(/\/v\/#/);
  const link = input.value;
  cleanup();
  return link;
}

function openLink(link) {
  const url = new URL(link);
  window.history.replaceState(null, "", url.pathname + url.hash);
  render(
    <MemoryRouter initialEntries={[url.pathname]}>
      <App />
    </MemoryRouter>
  );
}

describe("one-time message flow", () => {
  it("creates a link, reads it once, then reports it destroyed", async () => {
    const link = await createLink("hello secret");
    expect(link).toMatch(/\/v\/#[A-Za-z0-9_-]{22}$/);

    openLink(link);
    fireEvent.click(screen.getByText("Read the message"));
    expect(await screen.findByText("hello secret")).toBeTruthy();
    cleanup();

    openLink(link);
    fireEvent.click(screen.getByText("Read the message"));
    expect(await screen.findByText("Message was destroyed or never existed.")).toBeTruthy();
  });

  it("asks for the additional secret key", async () => {
    const link = await createLink("guarded", "s3cret");
    openLink(link);
    fireEvent.click(screen.getByText("Read the message"));
    const keyInput = await screen.findByLabelText("Secret Key");
    fireEvent.change(keyInput, { target: { value: "s3cret" } });
    fireEvent.click(screen.getByText("Read the message"));
    await waitFor(() => expect(screen.getByText("guarded")).toBeTruthy());
  });

  it("stores only ciphertext on the server", async () => {
    await createLink("plain words here");
    const [rec] = [...backend.db.values()];
    expect(rec.message.startsWith("v3:")).toBe(true);
    // The id the server got is not in the link.
    const [id] = [...backend.db.keys()];
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(rec.message).not.toContain("plain words");
    expect(rec.hashedKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("reports a modified message instead of showing garbage", async () => {
    const link = await createLink("original");
    const [rec] = [...backend.db.values()];
    rec.message = rec.message.slice(0, -4) + (rec.message.endsWith("AAAA") ? "BBBB" : "AAAA");
    openLink(link);
    fireEvent.click(screen.getByText("Read the message"));
    expect(await screen.findByText(/modified or damaged/)).toBeTruthy();
  });

  it("still opens v2 links", async () => {
    const linkKey = new Uint8Array(32).fill(5);
    const keys = await deriveKeys(linkKey);
    backend.db.set("ab".repeat(16), { message: await encrypt(keys, "ссылка v2"), hashedKey: keys.token });
    openLink("http://localhost/v/#" + fragment(linkKey, "ab".repeat(16)));
    fireEvent.click(screen.getByText("Read the message"));
    expect(await screen.findByText("ссылка v2")).toBeTruthy();
  });

  it("still opens links created by the old version", async () => {
    // Old record: CryptoJS AES with passphrase = secret + 12-char key.
    const passphrase = "abcdefghijkl";
    backend.db.set("1f", { message: legacyEncrypt("старая ссылка", passphrase), hashedKey: legacyHashKey(passphrase) });
    openLink("http://localhost/v/#abcdefghijkl1f");
    fireEvent.click(screen.getByText("Read the message"));
    expect(await screen.findByText("старая ссылка")).toBeTruthy();
  });
});


describe("keyboard shortcut", () => {
  function renderForm(text) {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    );
    const area = screen.getByLabelText("One-time Message");
    fireEvent.change(area, { target: { value: text } });
    return area;
  }

  it("sends the message with Ctrl+Enter", async () => {
    const area = renderForm("ctrl enter");
    fireEvent.keyDown(area, { key: "Enter", ctrlKey: true });
    expect(await screen.findByDisplayValue(/\/v\/#/)).toBeTruthy();
    expect(backend.db.size).toBe(1);
  });

  it("sends the message with Cmd+Enter", async () => {
    const area = renderForm("cmd enter");
    fireEvent.keyDown(area, { key: "Enter", metaKey: true });
    expect(await screen.findByDisplayValue(/\/v\/#/)).toBeTruthy();
  });

  it("does nothing on plain Enter or with an empty message", async () => {
    const area = renderForm("");
    fireEvent.keyDown(area, { key: "Enter", ctrlKey: true });
    fireEvent.change(area, { target: { value: "x" } });
    fireEvent.keyDown(area, { key: "Enter" });
    await new Promise((r) => setTimeout(r, 50));
    expect(backend).not.toHaveBeenCalled();
  });
});
