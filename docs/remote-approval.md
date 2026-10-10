# Remote approval via WebAuthn

Status: implemented on the `remote-approval` branch. It is not yet tested
with a real phone, real TouchID or a deployed relay; see [Not yet
verified](#not-yet-verified). Related:
[pcrn-mgmt#965](https://git.pcrn.us/aroberts/pcrn-mgmt/issues/965) (deploy via
CI with a phone-approved secret release).

## Goal

Let a keymaster request be approved from a phone when nobody is at the Mac.
A scheduled agent run on a Sunday morning should be able to read a gated key
after a Face ID approval on the phone. TouchID stays the default path.

There is no native iOS app and no Apple Developer Program membership. The
phone side is a web page and an iCloud Keychain passkey. Face ID is the
passkey's user verification.

## Why this is no weaker than TouchID

keymaster's TouchID gate is a policy check. `main()` calls
`LAContext.evaluatePolicy` and then reads a keychain item that trusts the
keymaster binary ("Always Allow"). The item carries no `SecAccessControl`
biometry flag. A remote approval that keymaster verifies itself sits at the
same point in the same code path. keymaster verifies the approval; no server
decides it.

## Non-goals

- Pre-authorizing a session until a wall-clock time (`--until`).
- The pcrn-mgmt#965 secret broker. The request format and verifier are kept
  reusable so the broker can adopt them.
- Duo, Okta, or any other push-MFA backend.
- Remote approval of `set` or `delete`.

## Components

```
keymaster (Mac)               relay (untrusted)              phone
---------------               -----------------              -----
build request R
challenge = SHA256(R)
POST R  ───────────────────▶  store R (until exp)
Pushover nudge (URL)  ──────────────────────────────────────▶ notification
                              GET /r/<id> page + R  ◀──────── open link
                                                              show R, Face ID
                              POST response  ◀─────────────── navigator.credentials.get
long-poll result  ◀────────── response
verify locally
updateSession + performAction
```

- **keymaster** is the only verifier. It holds the enrolled passkey public
  keys and checks every assertion.
- **The relay** (`relay/`, Go, standard library only) stores pending requests
  in memory, serves the page and passes the response back. It holds no keys
  and makes no decisions. It ships as the Docker image
  `ghcr.io/aroberts/keymaster-relay` for amd64 and arm64.
- **Pushover** delivers the link. It is a doorbell only. `enroll` also prints
  a QR code in the terminal.

## Protocol

### Request

keymaster builds a JSON object `R` with sorted keys and no whitespace:

| Field | Value |
|---|---|
| `v` | `1` |
| `kind` | `approve` or `enroll` |
| `id` | 128 random bits, base64url (22 characters) |
| `requester` | `"keymaster"` (the #965 broker would use its own name) |
| `host` | `gethostname()` |
| `user` | login name |
| `iat`, `exp` | issued-at and expiry, epoch seconds |
| `action` | approve: `get`, or `test` for `keymaster remote test` |
| `key` | approve: requested key |
| `session`, `scope` | approve: named session and `--scope` prefix, when given |
| `ttl` | approve, `get`: how long the grant will be cached |
| `caller` | approve: the process chain summary from the TouchID prompt |
| `cwd` | approve: working directory, `~`-abbreviated |
| `reason` | approve: `--reason` / `KEYMASTER_REASON`, when given |
| `label` | enroll: the passkey's label |
| `userId` | enroll: a fresh 16-byte WebAuthn user handle |

The WebAuthn challenge is `SHA256(R_bytes)`. That one hash binds the signature
to the exact request: key, scope, TTL, host and expiry. keymaster hashes the
bytes it sent and never re-parses the relay's copy. The relay carries `R` as
base64url, because Go's JSON encoder would otherwise escape `<`, `>` and `&`
and change the bytes. The page hashes the bytes it received.

Both sides show a request code, the first 4 bytes of the challenge in hex.
That lets someone at the Mac match the terminal to the phone.

### Approval

The page fetches `R`, renders it with `textContent` only, computes
`SHA256(R)` at load time and, on the button press, calls:

```js
navigator.credentials.get({ publicKey: {
  challenge, rpId: location.hostname, userVerification: "required", timeout
}})
```

The page computes the challenge at load because Safari drops user activation
if anything is awaited between the click and the WebAuthn call.
`allowCredentials` is omitted. Passkeys are discoverable, and the page doesn't
need to know the credential IDs.

The page posts `{type: "assertion", credentialId, authenticatorData,
clientDataJSON, signature}`. A Deny button marks the request denied, and
keymaster exits non-zero at once. A deny needs no signature, because a forged
deny can only cause a denial of service. The relay accepts only the first
answer.

After an approve or a deny, the page shows the result for 1.5 seconds and
then calls `window.close()`, so answered tabs don't pile up on the phone.
Browsers close only a tab whose history holds the page alone, and a trip
through the login proxy's sign-in page adds one entry. When the close is
refused, the page stays up and says the tab can be closed. The tab is not a
record: keymaster's audit log is. Closing it also takes the key name, host
and reason off the phone's screen. Enrollment pages stay open, because their
fingerprint has to be compared with the one keymaster prints.

### Verification (in keymaster)

`verifyAssertion` in `Sources/RemoteVerify.swift`. Every check must pass:

1. `credentialId` is enrolled. Its stored `rpId` and `origin` are used below,
   not the current config.
2. `clientDataJSON.type == "webauthn.get"`.
3. `clientDataJSON.challenge == base64url(SHA256(R))`, compared to the `R` in
   keymaster's memory.
4. `clientDataJSON.origin` equals the enrolled origin, and `crossOrigin` is
   not true.
5. `authenticatorData.rpIdHash == SHA256(rpId)`.
6. The UP and UV flags are both set.
7. The ES256 signature over `authenticatorData || SHA256(clientDataJSON)`
   verifies with the enrolled key (CryptoKit, DER signature).
8. `now < exp`.

`signCount` is ignored, because iCloud Keychain passkeys always report 0.
Replay is blocked anyway: every challenge comes from a fresh random `id`, and
keymaster only accepts the answer to the request it is waiting on.

On success keymaster calls `updateSession` and `performAction`, exactly as
after TouchID.

### Enrollment

`keymaster remote enroll` requires local TouchID. It posts an `enroll`
request, prints a QR code for the page, and sends the link through Pushover
if configured. The page calls `navigator.credentials.create` with ES256 only,
`residentKey: "required"`, `userVerification: "required"` and `attestation:
"none"`. It returns:

- `getPublicKey()`, the key as SubjectPublicKeyInfo DER, so keymaster needs no
  CBOR parser;
- `getPublicKeyAlgorithm()`;
- `getAuthenticatorData()`;
- `clientDataJSON`.

`verifyEnrollment` checks the following:

- `type == "webauthn.create"`, plus the challenge, the origin and the
  `rpIdHash`;
- the UP, UV and AT flags;
- that the credential ID inside the attested credential data equals the
  reported one;
- that the key parses as P-256.

Apple passkeys use `none` attestation, so keymaster can't prove the key came
from your phone. The relay is trusted at enrollment time. Both keymaster and
the page show a key fingerprint (the first 8 bytes of SHA-256 of the SPKI)
to compare. `rpId` is the relay URL's host, and `origin` is its scheme, host
and port. Both are stored with the credential.

Labels are unique. The default is `keymaster on <host> <YYYY-MM-DD>`, with
` (2)` and so on for a second enrollment the same day, and `--label` refuses a
label already in use. The page names the passkey with the label (`user.name`
and `user.displayName`), so the phone's passkey list matches `remote list`.

The passkey syncs through iCloud Keychain, so the Mac can also approve. That
is acceptable because UV is still required.

## CLI

```
keymaster remote setup --relay <https-url>
keymaster remote enroll [--label <name>]
keymaster remote list
keymaster remote revoke <credential-id|label>
keymaster remote allow <key|prefix*>
keymaster remote disallow <key|prefix*>
keymaster remote test

keymaster --approve local|remote|auto get <key>
KEYMASTER_APPROVE=local|remote|auto
KEYMASTER_LOCAL_TIMEOUT=<seconds>     # auto: default 20
KEYMASTER_REMOTE_TIMEOUT=<seconds>    # default 300, clamped to 30–900
```

`setup`, `enroll`, `revoke`, `allow` and `disallow` require local TouchID.
`list` and `test` don't, because they change nothing and release nothing.

`setup` also asks for a Pushover priority from -2 to 1 when Pushover is on.
Priority 1 bypasses quiet hours. Emergency priority 2 is not offered.

`list` shows each passkey's last remote approval, read from the audit log by
credential ID. The log keeps about 2 MB across its rotation, so a passkey with
no approval in it says how far back the log goes. After enrolling the same
phone twice, the passkey with no recent approval is the one to revoke.

- `local` (default) is today's behaviour.
- `remote` skips TouchID and goes straight to the phone. It fails at once if
  the request isn't eligible.
- `auto` goes to the phone at once in two cases: the screen is locked
  (`CGSSessionScreenIsLocked`, or the session is off the console), or TouchID
  can't be evaluated, for example with the lid closed. Otherwise it shows
  TouchID and invalidates the `LAContext` after `KEYMASTER_LOCAL_TIMEOUT`
  seconds. It also falls back on `systemCancel`, `notInteractive` and the
  biometry-unavailable errors. A user cancel or a failed match is a no and
  does not fall back. An ineligible request stays on plain TouchID.

The environment variable is allowed, unlike `--scope`, because scheduled runs
can only set the mode through the environment.

### Eligibility and the allowlist

A request can go to the phone only if all of these hold:

- the action is `get`;
- the key isn't one of keymaster's own items (`keymaster_remote_*` or the
  session HMAC key);
- remote approval is set up with at least one passkey;
- the allowlist covers the request.

An allowlist entry is an exact key or a `prefix*`. A scoped request needs a
prefix entry that contains the whole scope, because the approval will also
release every key under that scope. A scope that could cover keymaster's own
items is never eligible. `allow` refuses entries that would cover them, and
refuses a bare `*`. The list starts empty. The pcrn-mgmt vault password should
stay off it until #965's broker exists.

keymaster's own items are also never served from the session cache, even
locally. Without that rule, a `--scope keymaster_` grant could release the
HMAC key or the relay token without a fresh approval.

## Storage

| Item | Keychain service | Notes |
|---|---|---|
| Relay URL, relay token, Pushover user key, app token and priority | `keymaster_remote_config` | JSON |
| Enrolled credentials (id, SPKI, alg, rpId, origin, label, created) | `keymaster_remote_credentials` | JSON. rpId and origin are stored per credential, so a config edit can't change what gets verified |
| Remote allowlist | `keymaster_remote_allowlist` | JSON array |

They are generic-password items like the user's secrets. `keymaster set` on a
`keymaster_remote_*` name is refused; use the `remote` commands. `keymaster
delete keymaster_remote_config` still works (with TouchID) to wipe the setup.

## Relay

Go, standard library only. In-memory store, capped at 256 pending requests.
Requests must expire within 15 minutes. See [relay/README.md](../relay/README.md)
for endpoints, configuration and a Compose example.

It runs as one replica on the homelab swarm, behind Traefik:

- The route is internal-only. The phone reaches it over WireGuard.
- Everything except keymaster's two endpoints goes through Authelia (owner
  only). That covers the page, its static files, and the phone's request,
  response and deny calls.
- A carve-out router passes `POST /api/requests` and
  `GET /api/requests/<id>/result` without Authelia, and only when the request
  carries `Authorization: Bearer …`. The relay checks the token itself.

Authelia adds a second gate in front of the capability URL. Someone holding a
Pushover link can no longer deny or spam a request without also logging in.
The page refuses to follow redirects, so an expired login shows "reload"
instead of a false "answered".

The homelab dependency is accepted. If the swarm is down, phone approval is
down and TouchID still works at the Mac. In practice the uses that need the
phone also need the homelab. The scheduled agent runs work on the homelab, and
the #965 CI deploys run on the homelab's Gitea runners. The vault password,
the key a homelab repair would need, stays off the allowlist. The image is on
GHCR all the same, so a pull doesn't depend on the Gitea registry.

## Threat model

| Attacker has | Outcome |
|---|---|
| Relay only | Denial of service. It can't forge an assertion. A replayed old assertion fails check 3. |
| Pushover only | Learns that requests happen, and their links. Can't approve without the passkey. Can deny via the link. |
| Same-UID process on the Mac only | Can trigger requests, which you see on the phone and deny. This is no worse than triggering TouchID prompts. It can read the relay token through keymaster with a TouchID approval, which only lets it create requests. |
| Same-UID process **and** the relay | The relay shows a harmless-looking request while the challenge belongs to the attacker's real one. The design can't close this, because the page that renders `R` comes from the relay. Mitigations: the allowlist, short `exp`, and the request code, which only helps when you are at the Mac. |
| Phone unlocked in someone's hand | Face ID or passcode, the same as any passkey. |

Push fatigue: every notification names the key, host, caller and reason, and
the page shows all of `R`. `auto` only pushes when the Mac is locked or TouchID
went unanswered.

## Operational constraints

- **Agent tool timeouts.** Claude Code's Bash tool defaults to a 120 s
  timeout, and a remote approval waits up to `KEYMASTER_REMOTE_TIMEOUT` (300 s
  by default). The README tells callers to raise the tool timeout or warm the
  session first.
- **The Mac must be awake.** A scheduled run that fires while the Mac sleeps
  never reaches keymaster. That is the scheduler's problem.
- **Session cache.** A remote approval warms the same cache as TouchID, with
  the same TTL.

## Code layout

The sources moved from one file to `Sources/*.swift`, compiled together by
`swiftc` (`build.sh`, the Homebrew formula). `main.swift` holds argument
parsing and the approval decision. The `Remote*.swift` files hold the
request, verifier, config, relay client, Pushover client, approval flow and
`remote` subcommands.

`test.sh` compiles every source except `main.swift` together with
`Tests/main.swift`, and runs:

- unit tests for encoding, the allowlist and the verifier, each check
  exercised with CryptoKit-signed assertions;
- an integration run against a real relay process, with `relay/cmd/fakephone`
  signing through Go's crypto, including every tamper case;
- the real page in headless Chrome with a DevTools virtual authenticator
  (`Tests/browser-phone.mjs`), which covers the page's JavaScript end to end.

Nothing in the tests touches the keychain or TouchID.

## Decisions made without review

These choices were made on 2026-10-06 without a chance to ask, and reviewed
on 2026-10-07. Items 12 and 13 changed in review; the rest stand.

1. **Relay in Go, image on GHCR, tags follow keymaster's `v*` tags.** You
   chose these. The image has `:master` and `:sha-*` tags from master, and
   semver plus `:latest` from release tags.
2. **Relay host.** Settled with you: the homelab swarm, internal-only (LAN
   and WireGuard), with Authelia in front of everything but the two token
   endpoints. The Cloudflare Worker and oci01 options are dropped.
3. **The relay sees `R` in plain text** (open decision 2 in the original
   plan). It is self-hosted now, so the URL-fragment trick isn't worth the
   complexity. Pushover sees the key name, host, caller and reason in the
   notification text.
4. **Default `KEYMASTER_LOCAL_TIMEOUT` is 20 s** (open decision 3).
5. **Remote approvals get the same session TTL** (open decision 4). The phone
   page shows the TTL.
6. **Plain `swiftc` over `Sources/*.swift`, not SwiftPM** (open decision 5).
   See [Homebrew formula](#homebrew-formula).
7. **Remote approval only releases `get`.** The original plan carried
   `set`/`delete` in `R`. Writes from a phone seemed riskier than they are
   useful.
8. **Allowlist syntax** is an exact key or `prefix*`. A scope needs a prefix
   entry containing it.
9. **keymaster's own items never use the session cache.** This is a small
   change to local behaviour: reading the HMAC key now always prompts.
10. **`remote test` and `remote list` need no TouchID.**
11. **`auto` falls back on more than the timeout:** also on a locked screen,
    unavailable TouchID, `systemCancel` and `notInteractive`. It does not fall
    back on a user cancel.
12. **Pushover priority is set in `remote setup`,** from -2 to 1, default 0.
    Reviewed 2026-10-07: no emergency priority. The message's `ttl` is the
    request's expiry.
13. **Each enrollment gets a fresh WebAuthn user handle,** so enrolling twice
    adds a second passkey and doesn't overwrite the first. Reviewed
    2026-10-07: labels are unique and name the passkey on the phone, and
    `remote list` shows each passkey's last approval, so a stale duplicate
    can be found and revoked.
14. **Go code is gofmt-formatted with tabs.** That departs from the two-space
    rule, because gofmt is not configurable and CI checks it.

## Homebrew formula

The formula in `aroberts/homebrew-tap` compiles `Sources/*.swift`, as of
v0.9.0. The release workflow only rewrites the formula's `url` and `sha256`,
so a change to the build line still has to be made in the tap by hand.

Swift links LocalAuthentication, Security, CryptoKit, CoreGraphics and
CoreImage from the imports, so the formula needs no `-framework` flags.

## Verification

Verified on 2026-10-08 with the relay on the swarm (`sha-d39f6e6`) and the
Homebrew HEAD build:

- enrollment and approval from Safari on a real iPhone, with Face ID;
- `remote setup`, `enroll`, `allow`, `disallow`, `revoke` and `test`, with
  their TouchID prompts;
- `--approve remote`: approve, deny on the phone, expiry, refusal of a key
  off the allowlist, and the session cache after a remote approval;
- `--approve auto`: fallback to the phone on the TouchID timeout, on a locked
  screen and over ssh, and no fallback on Cancel;
- Pushover delivery and its link. Pushover opens links in its in-app browser
  by default. Its setting to open links in Safari keeps the Pushover message
  from lingering behind the page.
- the GitHub workflows, and the multi-arch image on GHCR;
- the Authelia login in front of the page, and the token carve-out (a
  request with a wrong bearer token reaches the relay and gets a 401).

Still unverified:

- Pushover removing the message from the phone when the request expires
  (`ttl`).
- The page's handling of an Authelia session that expires while the page is
  open. The page's `fetch` should refuse the redirect and say "Your login has
  expired. Reload the page."
- Safari closing the tab after an answer. A tab that went through the Authelia
  sign-in should stay open and say it can be closed.
