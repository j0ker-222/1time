# 1time API

All calls are `POST` with `Content-Type: application/json` (other content
types are rejected with 415). Body size is limited to 1 MB, nginx limits the
rate to 10 requests per second per IP.

Messages are encrypted on the client. The server stores only the ciphertext
and an access token and never sees the plaintext or the key.

## From scripts: `1time send` / `1time read`

The backend binary is also a client that encrypts locally:

```shell
echo 'db password: s3cr3t' | 1time send -days 1
# https://onetime.j0ker.site/v/#v2.<key>.<id>

1time read 'https://onetime.j0ker.site/v/#v2.<key>.<id>'
```

Options: `-url` (or `ONETIME_URL`), `-days` 1..30. An additional secret key
is taken from the `ONETIME_SECRET` environment variable (not a flag, so it
does not appear in `ps`). Build for macOS: `GOOS=darwin go build -o 1time .`

## Format v2

```
linkKey = 32 random bytes; link = <origin>/v/#v2.<base64url(linkKey)>.<id>
IKM     = linkKey                                (no additional secret)
IKM     = linkKey || PBKDF2-HMAC-SHA256(secret,
            salt = HKDF-SHA256(linkKey, info "1time v2 pbkdf2 salt", 16 bytes),
            600000 iterations, 32 bytes)         (with additional secret)
encKey  = HKDF-SHA256(IKM, salt "", info "1time v2 enc", 32 bytes)
token   = hex(HKDF-SHA256(IKM, salt "", info "1time v2 auth", 32 bytes))
payload = "v2:" + base64(iv(12 bytes) || AES-256-GCM(encKey, iv, text, AAD "1time v2"))
```

AES-GCM authenticates the ciphertext, so a modified message is rejected
instead of being decrypted into garbage.

## Save

`POST /api/saveSecret`

```json
{ "secretMessage": "v2:...", "hashedKey": "<token, 64 hex>", "duration": 86400 }
```

`duration` is in seconds, default 7 days, maximum 30 days (2592000).
Response: `{ "status": "ok", "newId": "<32 hex>" }`.

## Read once

`POST /api/get`

```json
{ "id": "<id>", "hashedKey": "<token>" }
```

Response: `{ "status": "ok", "cryptedMessage": "v2:..." }` and the message
is deleted. Other statuses: `"wrong key"` (message kept, ask for the
additional secret) and `"no message"`.

## /api/unsecSave (disabled)

Server-side encryption from plain text. The server sees the plaintext, so
the endpoint is off in the backend (`ENABLE_UNSEC_SAVE=0`) and blocked in
nginx. Use `1time send` instead.

## Health check

`GET /api/health` returns `{"status":"ok"}` (200) or 503 when Redis is down.
