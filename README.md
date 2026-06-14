# kblocker

A kernel-level internet blocker designed to remove your ability to break your own focus. Once enabled, it blocks access to configured domains by dropping matching TCP connections via netfilter and null-routing them via `/etc/hosts`. The key needed to disable or unload the module can be encrypted to trusted recipients and erased from kernel memory — making the decision to unblock a deliberate, collaborative act rather than an impulse.

## Use case

You want to block distracting sites and make it *genuinely hard* to disable the blocker — even for yourself. The goal isn't just to block, but to remove your own agency to undo it in a moment of weakness.

- The kernel module hooks `NF_INET_LOCAL_OUT` and `NF_INET_FORWARD`, inspects TLS SNI, and drops matching connections
- Disabling or unloading requires a 128-bit key, validated against a SHA-256 hash stored in the kernel
- With PGP mode, the key is encrypted to your trusted recipients' GPG public keys and then **erased from kernel memory** — the only way to retrieve it is to have someone else PGP-decrypt it. You've outsourced your willpower.
- The module file, auto-load config, hosts file, and domains config are protected with `chattr +i` (immutable) and `inode_operations` overrides, re-applied every second

## Quick start

```sh
# build and install
sudo make install

# register a PGP key (do this first)
sudo kblockerctl add-pgp alice.pub

# block YouTube for 60 minutes
sudo kblockerctl enable 60

# check status
sudo kblockerctl status

# disable blocking (module stays loaded)
sudo kblockerctl unblock

# remove module entirely
sudo kblockerctl unload
```

## PGP mode

Without PGP, the unload key is readable from `/sys/kernel/kblocker/key` — anyone with root can retrieve it and disable the blocker. PGP mode encrypts the key to trusted recipients so that:

1. On `enable`, kblockerctl reads the key from sysfs, GPG-encrypts it for all registered public keys, and signals the kernel to zero the key from memory
2. The `key` sysfs attribute returns `"encrypted"` instead of the raw hex
3. `unblock` and `unload` require the decrypted key (PGP-decrypt the ciphertext, write the plain hex to the kernel)

```sh
# register a PGP public key
sudo kblockerctl add-pgp alice.pub

# enable with PGP protection
sudo kblockerctl enable 60

# disable (needs PGP private key to decrypt)
sudo kblockerctl unblock

# unload (needs the key too)
sudo kblockerctl unload
```

### Web UI: Browser-based PGP key management

Generate PGP keys entirely in your browser (using OpenPGP.js) — the private key never touches the server:

```sh
# start web UI for key generation
sudo kblockerctl add-pgp-web
# Opens on http://127.0.0.1:<random-port>
```

The unblock-web UI lets you decrypt the PGP ciphertext client-side in the browser and submit the key:

```sh
sudo kblockerctl unblock-web
# Opens on http://127.0.0.1:<random-port>
```

### Insecure mode

Without any key registered, `--insecure` mode prints the key to stdout instead:

```sh
sudo kblockerctl enable 60 --insecure
```

## Commands

| Command | Description |
|---------|-------------|
| `enable <minutes> [--insecure]` | Enable blocking. Requires PGP unless `--insecure` |
| `disable` / `unblock [--key <hex>]` | Disable blocking. Needs PGP key when PGP mode is active |
| `unload [--key <hex>]` | Permanently remove the module. Needs the unblock key |
| `status` | Show blocking state, remaining time, protected files |
| `block <domain>...` | Write domains to kernel and config file (does not enable) |
| `add <domain>` | Add a domain to the persistent config |
| `remove <domain>` | Remove a domain |
| `reload` | Re-write domains to kernel, refresh PGP ciphertexts, restore persisted state |
| `block-ip <ip>...` | Set blocked IPs directly (replaces existing list) |
| `list` | Show blocked IPs and configured domains |
| `key` | Show the current unload key and PGP key fingerprints |
| `add-pgp <pubkey.asc> [name]` | Register a PGP public key |
| `remove-pgp <fingerprint>` | Remove a registered PGP key |
| `list-pgp` | List registered PGP keys |
| `pgp-cipher <fingerprint>` | Print the PGP-encrypted unload key for a recipient |
| `add-pgp-web [--port <port>] [--bind <ip>]` | Start web UI for browser-based PGP key generation |
| `unblock-web [--port <port>] [--bind <ip>]` | Start web UI to decrypt and submit unblock key via browser |
| `crash` | Force-remove module (triggers kernel panic) |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Userspace                             │
│                                                          │
│  kblockerctl                                             │
│      │ writes                                            │
│      ▼                                                   │
│  /sys/kernel/kblocker/{enabled,blocked_ips,              │
│                        blocked_domains,unblock,          │
│                        disable,pgp_active,...}            │
│                                                          │
│  PGP keys: /etc/kblocker/keys/                           │
│  Ciphertexts: /var/lib/kblocker/unlock-pgp/              │
│  Persisted state: /var/lib/kblocker/state                │
│  Domain config: /etc/kblocker/domains.conf               │
│                                                          │
│  Web UIs: add-pgp-web (key gen)                          │
│           unblock-web (browser PGP decrypt)              │
└──────────────────────┬───────────────────────────────────┘
                       │ sysfs
┌──────────────────────▼───────────────────────────────────┐
│                    Kernel                                │
│                                                          │
│  netfilter hooks (LOCAL_OUT, FORWARD)                    │
│    ├─ IPv4/IPv6 IP blacklist check                       │
│    ├─ TLS SNI inspection (domain blacklist)              │
│    └─ TLS ECH (0xFE0A) drop to force SNI fallback        │
│                                                          │
│  File protection (inode_operations override + immut)     │
│    ├─ kblocker.ko                                        │
│    ├─ /etc/modules-load.d/kblocker.conf                  │
│    └─ /etc/hosts                                         │
│                                                          │
│  Key management                                          │
│    ├─ 128-bit random key at module init                  │
│    ├─ SHA-256 hash stored for verification               │
│    ├─ PGP mode: key zeroed on pgp_active=1               │
│    └─ disable: regenerates key + clears pgp_active       │
│                                                          │
│  Timer: auto-disable on expiry (checks every 1s)         │
│  Workqueue: file protection re-check (every 1s)          │
└──────────────────────────────────────────────────────────┘
```

## Build

```sh
make
```

Requires kernel headers (`linux-headers-$(uname -r)`) and Go 1.21+.

## Install / Uninstall

```sh
# install
sudo ./install

# uninstall
sudo ./uninstall
```

Or via the deb package: `./build-deb.sh` produces a `.deb` in `build/`.

## Testing

```sh
sudo ./test.sh
```

Runs integration tests against the live kernel module via sysfs.
