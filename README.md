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

Compile `keymaster.swift` into a binary:

```bash
swiftc -O -o keymaster keymaster.swift -framework LocalAuthentication -framework Security
```

Put the `keymaster` binary somewhere in your `$PATH`, or run it directly from
the project directory.

## Usage

```
keymaster get <key>                       # Retrieve a secret (printed to stdout)
echo <secret> | keymaster set <key>       # Store a secret (read from stdin)
keymaster delete <key>                    # Delete a secret
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

To change a secret, delete and re-set it, or edit it directly in
`Keychain Access.app`.

### Session TTL

After a successful TouchID authentication, keymaster caches the session for
that specific key for 5 minutes (300 seconds) by default. Accessing a different
key within the TTL window still requires TouchID. Configure the TTL with the
`KEYMASTER_TTL` environment variable:

```bash
# Extend to 10 minutes
export KEYMASTER_TTL=600

# Require TouchID every time
export KEYMASTER_TTL=0
```

The session file is stored in `$TMPDIR` (a per-user directory on macOS, e.g.,
`/var/folders/xx/.../T/keymaster_session`). It does not persist across reboots.
Expired entries are pruned automatically.

The session is HMAC-SHA256 signed using a key stored in the keychain. Key names
are hashed before being written to the session file, so the file does not reveal
which keychain entries have been accessed.

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
