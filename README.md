# ytblock

A kernel-level self-discipline internet blocker. Once enabled, it blocks access to configured domains by dropping matching TCP connections via netfilter and redirecting DNS to 0.0.0.0/:: in `/etc/hosts`. Cannot be disabled or unloaded without the correct key — and with PGP mode, the key is encrypted to trusted recipients' public keys, then erased from kernel memory.

## Use case

You want to block distracting sites (YouTube, Reddit, etc.) and make it *genuinely hard* to turn the blocker off.

- The kernel module hooks `NF_INET_LOCAL_OUT` and `NF_INET_FORWARD`, inspects TLS SNI, and drops matching connections
- Disabling (`unblock`) or unloading the module requires a 128-bit key, validated against a SHA-256 hash stored in the kernel
- With PGP mode enabled, the key is encrypted to your trusted recipients' GPG public keys and then **erased from kernel memory** — the only way to retrieve it is via PGP decryption
- The module file, auto-load config, and domains file are protected with `chattr +i` (immutable) and `inode_operations` overrides, polled every second

## Quick start

```sh
# build and install
sudo make install

# block YouTube for 60 minutes (requires PGP unless --insecure)
sudo ytblockctl enable 60

# check status
sudo ytblockctl status

# disable blocking (module stays loaded)
sudo ytblockctl unblock

# remove module entirely
sudo ytblockctl unload
```

## PGP mode

Without PGP, the unload key is readable from `/sys/kernel/ytblock/key` — anyone with root can retrieve it and disable the blocker. PGP mode encrypts the key to trusted recipients so that:

1. On `enable`, ytblockctl reads the key from sysfs, GPG-encrypts it for all registered public keys, and signals the kernel to zero the key from memory
2. The `key` sysfs attribute returns `"encrypted"` instead of the raw hex
3. `unblock` and `unload` require the decrypted key (PGP-decrypt the ciphertext, write the plain hex to the kernel)

```sh
# register a PGP public key
sudo ytblockctl add-pgp alice.pub

# enable with PGP protection
sudo ytblockctl enable 60

# disable (needs PGP private key to decrypt)
sudo ytblockctl unblock

# unload (needs the key too)
sudo ytblockctl unload
```

Without any key registered, `--insecure` mode prints the key to stdout instead:

```sh
sudo ytblockctl enable 60 --insecure
```

## Commands

| Command | Description |
|---------|-------------|
| `enable <minutes> [--insecure]` | Enable blocking. Requires PGP unless `--insecure` |
| `disable` / `unblock [--key <hex>]` | Disable blocking. Needs PGP key when PGP mode is active |
| `unload [--key <hex>]` | Permanently remove the module. Needs the unblock key |
| `status` | Show blocking state, remaining time, protected files |
| `block <domain>...` | Write domains to kernel and `/etc/hosts` (does not enable) |
| `add <domain>` | Add a domain to the persistent config |
| `remove <domain>` | Remove a domain |
| `reload` | Re-resolve IPs, re-apply protections, restore persisted state |
| `block-ip <ip>...` | Set blocked IPs directly (replaces existing list) |
| `list` | Show blocked IPs and configured domains |
| `key` | Show the current unload key and PGP key fingerprints |
| `add-pgp <pubkey.asc> [name]` | Register a PGP public key |
| `remove-pgp <fingerprint>` | Remove a registered PGP key |
| `list-pgp` | List registered PGP keys |
| `pgp-cipher <fingerprint>` | Print the PGP-encrypted unload key for a recipient |
| `crash` | Force-remove module (triggers kernel panic) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Userspace                         │
│                                                      │
│  ytblockctl                                             │
│      │ writes                                        │
│      ▼                                               │
│  /sys/kernel/ytblock/{enabled,blocked_ips,           │
│                        blocked_domains,unblock,      │
│                        disable,pgp_active,...}        │
│                                                      │
│  PGP keys: /etc/ytblock/keys/                        │
│  Ciphertexts: /var/lib/ytblock/unlock-pgp/           │
│  Persisted state: /var/lib/ytblock/state             │
│  Domain config: /etc/ytblock/domains.conf            │
└──────────────────────┬──────────────────────────────┘
                       │ sysfs
┌──────────────────────▼──────────────────────────────┐
│                    Kernel                            │
│                                                      │
│  netfilter hooks (LOCAL_OUT, FORWARD)                │
│    ├─ IPv4/IPv6 IP blacklist check                   │
│    ├─ TLS SNI inspection (domain blacklist)           │
│    └─ TLS ECH (0xFE0A) drop to force SNI fallback    │
│                                                      │
│  File protection (inode_operations override + immut) │
│    ├─ ytblock.ko                                     │
│    └─ /etc/modules-load.d/ytblock.conf               │
│                                                      │
│  Key management                                      │
│    ├─ 128-bit random key at module init              │
│    ├─ SHA-256 hash stored for verification           │
│    ├─ PGP mode: key zeroed on pgp_active=1           │
│    └─ disable: regenerates key + clears pgp_active   │
│                                                      │
│  Timer: auto-disable on expiry (checks every 1s)     │
│  Workqueue: file protection re-check (every 1s)      │
└──────────────────────────────────────────────────────┘
```

## Install / Uninstall

```sh
# from source
sudo make install
sudo make uninstall

# via build scripts
./build-deb.sh
./clean.sh          # clean build artifacts
./install.sh        # same as make install
./uninstall.sh      # same as make uninstall
```

The deb package is built with `./build-deb.sh` and produces a `.deb` in `build/`.

## Building

```sh
make          # build kernel module
sudo make modules_install  # install module only
```

Requires kernel headers (`linux-headers-$(uname -r)`).

## Testing

```sh
sudo make test
```

Runs integration tests against the live kernel module via sysfs.