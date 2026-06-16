# Keymaster

Keymaster is a small binary written in Swift that allows scripts to access the
Mac Keychain guarded by TouchID.

Macs come with the `security` command which can get and set secrets to the
Keychain:

```bash
# Save a key/value to the default "login" keychain, with key "MyKeyName",
# update if exists (-U), allow no app to access without a prompt (-T ""),
# and prompt for secret to store (-w)
security add-generic-password -a login -s "MyKeyName" -T "" -U -w

# Get the secret value from a key
security find-generic-password -s "MyKeyName" -w
```

You can use `security` in a script, but (AFAIK) you can't tell it to use
biometrics to guard secrets, you have to enter the password each time, or
"always allow" the `security` binary to access the secret.

Keymaster fixes this.

## Building

Build with the provided script, which compiles and code-signs the binary:

```bash
./build.sh
```

Put the `keymaster` binary somewhere in your `$PATH`, or run it directly from
the project directory.

To compile without the script:

```bash
swiftc -O -o keymaster keymaster.swift -framework LocalAuthentication -framework Security
```

### Code signing (recommended, one-time setup)

Both `build.sh` (local builds) and `keymaster-resign` (after a Homebrew
upgrade) sign with a self-signed code-signing identity named `keymaster-signing`.
This matters because macOS records a binary's Keychain trust (the "Always Allow"
below) against its code signature. An unsigned binary is trusted by its
`cdhash`, which changes on every recompile — so each rebuild breaks the trust
and you get Keychain and TouchID prompts all over again. Signing with a stable
identity makes the trust survive rebuilds.

If the `keymaster-signing` identity is not present, `build.sh` still builds, but
unsigned, and prints a warning — expect a prompt on every build until you
create it.

Create the identity once. The GUI path is Keychain Access → Certificate
Assistant → Create a Certificate… (Name: `keymaster-signing`, Identity Type:
Self Signed Root, Certificate Type: Code Signing). If Certificate Assistant
errors out (it can on migrated systems with a stale keychain search list),
create it from the command line instead:

```bash
# Generate a self-signed code-signing cert
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/keymaster-signing.key -out /tmp/keymaster-signing.crt \
  -days 3650 -subj "/CN=keymaster-signing" \
  -addext "basicConstraints=critical,CA:false" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=critical,codeSigning"

# Bundle and import into the login keychain, authorizing codesign to use the key
openssl pkcs12 -export -inkey /tmp/keymaster-signing.key \
  -in /tmp/keymaster-signing.crt -name keymaster-signing \
  -out /tmp/keymaster-signing.p12 -passout pass:temp
security import /tmp/keymaster-signing.p12 \
  -k ~/Library/Keychains/login.keychain-db -P temp -T /usr/bin/codesign

# Shred the temporary key material — the private key now lives in the keychain
rm -f /tmp/keymaster-signing.key /tmp/keymaster-signing.crt /tmp/keymaster-signing.p12
```

The identity shows as untrusted (`CSSMERR_TP_NOT_TRUSTED`) in
`security find-identity -p codesigning`. That is expected for a self-signed
cert and does not prevent signing.

### Re-signing after a Homebrew upgrade

If you install via Homebrew, each `brew upgrade` recompiles keymaster from
source and re-applies an ad-hoc signature. Homebrew's build runs with an
isolated `HOME` and sandbox and cannot reach your login keychain, so it cannot
sign with `keymaster-signing` itself. After an upgrade that rebuilt keymaster,
re-sign it once:

```bash
keymaster-resign
```

This signs the installed `keymaster` binary with the `keymaster-signing`
identity (override via `KEYMASTER_SIGNING_IDENTITY`), restoring the stable
designated requirement so the Keychain "Always Allow" trust holds across the
upgrade. It is harmless to run when the binary is already signed.

## Usage

```
keymaster [options] get <key>                       # Retrieve a secret (printed to stdout)
echo <secret> | keymaster [options] set <key>       # Store a secret (read from stdin)
keymaster [options] delete <key>                    # Delete a secret

Options:
  -v                              Enable debug logging (stderr)
  -s, --session <name>            Use a named session shared across keys and processes (see Sessions)
```

### First Run — Keychain Prompts

On first use, macOS will show two Keychain Access prompts asking whether to
allow `keymaster` to access keychain items. Select **Always Allow** for both:

1. **HMAC session key** (`keymaster_session_hmac_key`) — used internally to
   validate sessions. This is read on every invocation, before TouchID, so it
   must be accessible without a prompt.
2. **Your secret** — the actual keychain item you're storing or retrieving.

Keymaster handles authentication itself via TouchID. The keychain is a passive
store — "Always Allow" makes it transparent, leaving TouchID as the sole
authentication gate. If you don't select "Always Allow", you'll get a keychain
dialog on every invocation in addition to TouchID.

These prompts are recorded against the binary's code signature. Signed with a
stable identity (see [Code signing](#code-signing-recommended-one-time-setup)),
they are a one-time cost. An unsigned (ad-hoc) binary is trusted by its cdhash
and is re-prompted on every rebuild — including each `brew upgrade`, which
recompiles from source; run
[`keymaster-resign`](#re-signing-after-a-homebrew-upgrade) afterward to restore
the trust. The first switch from unsigned to signed also triggers one fresh
round of prompts, after which it sticks.

To change a secret, delete and re-set it, or edit it directly in
`Keychain Access.app`.

### Sessions

After a successful TouchID authentication, keymaster caches the auth so that
subsequent calls within a TTL window can skip the prompt. The default TTL is
5 minutes (300 seconds); configure with `KEYMASTER_TTL`:

```bash
# Extend to 10 minutes
export KEYMASTER_TTL=600

# Require TouchID every time
export KEYMASTER_TTL=0
```

The session file lives in `$TMPDIR` (a per-user directory on macOS, mode 700),
HMAC-SHA256 signed with a key stored in the keychain. Key and session names are
hashed before being written, so the file does not reveal which entries have
been accessed. It does not persist across reboots; expired entries are pruned
automatically.

#### Per-key sessions (default)

Each key has its own session, bound to the calling POSIX session
(`getsid(0)`). The cache only satisfies subsequent calls from the same terminal
or process tree, and authenticating for one key does not affect another.

#### Named sessions

Pass `-s <name>` or set `KEYMASTER_SESSION=<name>` to share auth across
multiple keys and across unrelated processes:

```bash
KEYMASTER_SESSION=aws keymaster get aws_access_key_id
KEYMASTER_SESSION=aws keymaster get aws_secret_access_key
```

A named session is *not* bound to the POSIX session ID — any process running
as the same user can use the cache within the TTL window as long as it
provides the same name. This is the right escape hatch for agentic shells
(each command may run under a fresh `setsid()`) and long-running daemons.

The flag takes precedence over the environment variable.

#### Trust scope

Per-key sessions' SID binding prevents an unrelated same-UID process from
racing the TTL window to piggyback on a recent auth. Named sessions opt out of
that binding by design — any same-UID process that knows the name can use the
cache. The keychain ACL boundary (same-UID, post-TouchID) is the underlying
security control; the SID binding is defense-in-depth that named sessions
trade for cross-process sharing.

## SSH Integration

Keymaster can act as an `SSH_ASKPASS` provider, supplying SSH key passphrases
via TouchID instead of typing them. Every SSH connection triggers a TouchID
prompt (or reuses the cached session within the TTL window).

This means you don't need `ssh-add` or a running `ssh-agent` — SSH itself
calls keymaster directly each time it needs a passphrase.

### Quick Start

```bash
# 1. Import an existing SSH key's passphrase
bin/keymaster-ssh import ~/.ssh/id_ed25519

# 2. Configure your shell (add output to ~/.zshrc)
bin/keymaster-ssh setup >> ~/.zshrc
source ~/.zshrc

# 3. SSH now uses TouchID for passphrases
ssh user@host
```

### Commands

#### `keymaster-ssh generate`

Generate a new SSH key with a random passphrase, automatically stored in
keymaster.

```
keymaster-ssh generate [-t type] [-b bits] [-C comment] [-f file]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | `ed25519` | Key type (`ed25519`, `rsa`, `ecdsa`) |
| `-b` | _(none)_ | Key size in bits (only applies to `rsa`) |
| `-C` | `$USER@$(hostname -s)` | Key comment |
| `-f` | `~/.ssh/id_<type>` | Output file path |

The passphrase is a random 32-character string generated from `/dev/urandom`.
You never need to see or type it — keymaster handles retrieval via TouchID.

The command refuses to overwrite an existing key file. If keymaster fails to
store the passphrase after key generation, the passphrase is printed to stderr
so you can store it manually.

```bash
# Generate an ed25519 key with defaults
keymaster-ssh generate

# Generate an RSA-4096 key for a specific purpose
keymaster-ssh generate -t rsa -b 4096 -f ~/.ssh/id_work -C "work@example.com"
```

#### `keymaster-ssh import`

Store an existing key's passphrase in keymaster.

```
keymaster-ssh import <key_path>
```

The command prompts you to enter the passphrase, then verifies it by attempting
to extract the public key with `ssh-keygen -y`. If the key has no passphrase,
it exits with a message and stores nothing.

```bash
keymaster-ssh import ~/.ssh/id_ed25519
keymaster-ssh import ~/.ssh/id_rsa
```

#### `keymaster-ssh setup`

Print shell configuration lines to stdout. Pipe or copy these into your
`~/.zshrc` or `~/.bashrc`.

```bash
# Preview what will be added
keymaster-ssh setup

# Apply directly
keymaster-ssh setup >> ~/.zshrc
source ~/.zshrc
```

This sets two environment variables:

- `SSH_ASKPASS` — points to the `keymaster-askpass` script
- `SSH_ASKPASS_REQUIRE=force` — tells SSH to always use the askpass program,
  even when running in a terminal (without this, SSH only uses askpass when
  there is no TTY)

If you're using a custom prefix, it also includes the `KEYMASTER_SSH_PREFIX`
export.

#### `keymaster-ssh list`

Show which SSH keys in `~/.ssh/` have passphrases stored in keymaster.

```bash
keymaster-ssh list
```

Output:

```
KEY                            STORED
id_ed25519                     yes
id_rsa                         no
```

Scans `~/.ssh/id_*` (excluding `.pub` files). The first invocation may trigger
a TouchID prompt; subsequent checks within the TTL window are cached.

#### `keymaster-ssh remove`

Remove a stored passphrase from keymaster. Takes the key **basename** (not the
full path).

```bash
keymaster-ssh remove id_ed25519
```

This only removes the passphrase from keymaster's keychain store. It does not
delete or modify the SSH key file itself.

### Custom Key Prefix

By default, passphrases are stored under the keychain key
`ssh_key_passphrase:<key_basename>` (e.g., `ssh_key_passphrase:id_ed25519`).
You can change the prefix to namespace keys differently:

```bash
# Via environment variable (affects both keymaster-ssh and keymaster-askpass)
export KEYMASTER_SSH_PREFIX="work_ssh"
# Resulting keychain key: work_ssh:id_ed25519

# Via flag (keymaster-ssh only, overrides the env var)
keymaster-ssh --prefix work_ssh import ~/.ssh/id_ed25519
```

If you use a custom prefix, make sure the same `KEYMASTER_SSH_PREFIX` is set in
your shell profile so that `keymaster-askpass` uses it when SSH invokes it. The
`setup` command includes this export automatically when a custom prefix is
active.

### How It Works

SSH supports an `SSH_ASKPASS` environment variable pointing to a program that
returns the passphrase on stdout. The `bin/keymaster-askpass` script:

1. Receives the SSH prompt as `$1` (e.g., `"Enter passphrase for /path/to/key: "`)
2. Checks `SSH_ASKPASS_PROMPT` — only handles passphrase prompts (ignores
   confirmation and notification prompts)
3. Parses the key path from the prompt and extracts its basename
4. Calls `keymaster get <prefix>:<basename>` which triggers TouchID
5. Returns the passphrase to SSH on stdout

Both `keymaster-askpass` and `keymaster-ssh` resolve the `keymaster` binary by
first checking relative to the script's location (the project root), then
falling back to `$PATH`.

### Security Notes

- Passphrases are stored in the macOS Keychain, protected by TouchID via
  keymaster. They are never written to disk in plaintext.
- The session file is stored in `$TMPDIR` (per-user, mode 700 on macOS) and
  HMAC-signed to prevent forgery. The HMAC key is stored in the keychain and
  generated automatically on first use.
- Passphrases are never exposed in process arguments. `keymaster set` reads
  from stdin, and `keymaster-ssh` passes passphrases to `ssh-keygen` via
  `SSH_ASKPASS` rather than command-line flags.
- The `KEYMASTER_TTL` setting controls how often TouchID is required. Set it to
  `0` for maximum security (TouchID on every SSH connection).

