# keymaster relay

The relay passes keymaster remote-approval requests to your phone and the
phone's passkey signatures back. It holds no keys and decides nothing.
keymaster verifies every signature against the request it sent. A
compromised relay can deny service or show misleading text. It can't approve
a request. See [../docs/remote-approval.md](../docs/remote-approval.md).

Requests live in memory for at most 15 minutes. A restart drops the requests
in flight and nothing else, so the relay needs no volume.

## Image

`ghcr.io/aroberts/keymaster-relay`, for linux/amd64 and linux/arm64, built by
`.github/workflows/relay-image.yml`:

| Tag | Built from |
|---|---|
| `master`, `sha-<short>` | each push to master that touches `relay/` |
| `1.2.3`, `1.2`, `latest` | a keymaster `v1.2.3` release tag |

The image is distroless, runs as a non-root user, listens on port 8080 and
has a built-in healthcheck (`/relay -healthcheck`).

## Configuration

| Variable | Meaning |
|---|---|
| `RELAY_TOKEN` | Shared secret keymaster sends to create requests and read results. At least 32 characters. |
| `RELAY_TOKEN_FILE` | Read the token from a file instead (Docker secrets). Wins over `RELAY_TOKEN`. |
| `RELAY_LISTEN` | Listen address, default `:8080`. |

Generate a token with `openssl rand -base64 32`, and give the same value to
`keymaster remote setup`.

## Deploying

The relay must be reachable from your phone over HTTPS, because WebAuthn only
runs in a secure context. The passkey is bound to the relay's hostname, so
pick a hostname you'll keep. Changing it means enrolling again.

Run exactly one replica, and stop the old one before starting the new one
(Swarm: `update_config: {order: stop-first}`). Pending requests live in
memory, so two replicas would split requests from their answers.

Behind a login proxy (Authelia, oauth2-proxy and the like), put everything
behind the login except the two endpoints keymaster calls, which can't log
in: `POST /api/requests` and `GET /api/requests/<id>/result`. Match those
exactly, require an `Authorization: Bearer` header on them, and let the
relay check the token. The phone's own calls carry no Authorization header,
so they stay behind the login. The page treats a redirect as an expired
login and asks for a reload.

Behind any TLS-terminating reverse proxy, forward everything to port 8080.
Long-polls hold requests open for 25 seconds, so allow read timeouts of at
least 40 seconds. A minimal Compose file with Caddy, which obtains the
certificate itself:

```yaml
services:
  relay:
    image: ghcr.io/aroberts/keymaster-relay:latest
    restart: unless-stopped
    environment:
      RELAY_TOKEN_FILE: /run/secrets/relay_token
    secrets: [relay_token]

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    command: caddy reverse-proxy --from approve.example.com --to relay:8080
    volumes: [caddy_data:/data]

secrets:
  relay_token:
    file: ./relay_token

volumes:
  caddy_data:
```

Then check the page loads at `https://approve.example.com/healthz`, and run
`keymaster remote setup` and `keymaster remote enroll` from your Mac.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/requests` | relay token | store a request until its `exp` (at most 15 min) |
| `GET` | `/r/<id>` | capability URL | approval or enrollment page |
| `GET` | `/api/requests/<id>` | capability URL | the request bytes and status, for the page |
| `POST` | `/api/requests/<id>/response` | capability URL | the phone's WebAuthn response; first answer wins |
| `POST` | `/api/requests/<id>/deny` | capability URL | mark denied; first answer wins |
| `GET` | `/api/requests/<id>/result` | relay token | long-poll (25 s) for the answer |
| `GET` | `/healthz` | none | liveness |

The request id is 128 random bits and doubles as the capability. Responses
carry `Cache-Control: no-store`, `Referrer-Policy: no-referrer` and a strict
Content-Security-Policy.

## Development

```bash
go test ./...
RELAY_TOKEN=$(openssl rand -hex 32) go run . -listen 127.0.0.1:8080
```

`cmd/fakephone` stands in for the phone in keymaster's tests. It isn't part of
the image.
