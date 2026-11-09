# 1time API

All calls are `POST` with `Content-Type: application/json` (other content
types are rejected with 415). Body size is limited to 1 MB, nginx limits the
rate to 10 requests per second per IP.

## Create a link from plain text

`POST /api/unsecSave`

The server encrypts the message, so it sees the plaintext. For full
client-side encryption use the web interface.

Request:

```json
{ "secretMessage": "text", "duration": 86400 }
```

`duration` is in seconds, default 7 days, maximum 30 days (2592000).

Response:

```json
{ "status": "ok", "newLink": "/v/#<12-char key><id>" }
```

The full link is the site origin plus `newLink`, for example
`https://onetime.j0ker.site/v/#AbCdEfGhIjKl0123456789abcdef0123456789abcdef`.

On error `status` is not `"ok"` and `newLink` is empty.

Example:

```shell
curl -sS -X POST -H 'Content-Type: application/json' \
  https://onetime.j0ker.site/api/unsecSave \
  -d '{"secretMessage":"test message","duration":3600}'
```

## Health check

`GET /api/health` returns `{"status":"ok"}` (200) or 503 when Redis is down.
