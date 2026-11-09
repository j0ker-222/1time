async function post(path, payload) {
  const resp = await fetch(`/api/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "same-origin",
    cache: "no-store",
  });
  let data = {};
  try {
    data = await resp.json();
  } catch {
    // non-JSON error page from a proxy
  }
  if (!resp.ok && !data.status) {
    throw new Error(`HTTP ${resp.status}`);
  }
  return data;
}

export const saveSecret = (secretMessage, hashedKey, duration) =>
  post("saveSecret", { secretMessage, hashedKey, duration });

export const getSecret = (id, hashedKey) => post("get", { id, hashedKey });
