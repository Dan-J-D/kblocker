# 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Userspace                             │
│                                                          │
│  kblockerctl                                             │
│      │ writes                                            │
│      ▼                                                   │
│  /sys/kernel/kblocker/{enabled,blocked_ips,              │
│                        blocked_domains,unblock,          │
│                        disable,pgp_active,...}           │
│                                                          │
│  PGP keys: /etc/kblocker/keys/                           │
│  Ciphertexts: /var/lib/kblocker/unlock-pgp/              │
│  Persisted state: /var/lib/kblocker/state (kernel-owned) │
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
│    ├─ outer SNI matched for ECH (0xFE0D) hellos          │
│    └─ UDP/443 (QUIC) drop to force TCP fallback          │
│                                                          │
│  File protection (inode_operations override + immut)     │
│    ├─ kblocker.ko                                        │
│    ├─ /etc/modules-load.d/kblocker.conf                  │
│    ├─ /etc/hosts                                         │
│    └─ /var/lib/kblocker/state (append-only)              │
│                                                          │
│  Key management                                          │
│    ├─ 128-bit random key at module init                  │
│    ├─ SHA-256 hash stored for verification               │
│    ├─ PGP mode: key zeroed on pgp_active=1               │
│    └─ disable: regenerates key + clears pgp_active       │
│                                                          │
│  Timer: auto-disable on expiry (boottime, checks 1s)     │
│  State: remaining time appended every 60s, restored at   │
│         module load only                                 │
│  Workqueue: file protection re-check (every 1s)          │
└──────────────────────────────────────────────────────────┘
```

## How a block holds

- The kernel module hooks `NF_INET_LOCAL_OUT` and `NF_INET_FORWARD`, inspects TLS SNI, and drops matching connections. Domains are also null-routed via `/etc/hosts`.
- While domains are blocked, QUIC (UDP/443) is dropped so browsers fall back to TCP, where SNI is visible.
- Disabling or unloading requires a 128-bit key, validated against a SHA-256 hash stored in the kernel.
- With PGP mode, the key is encrypted to your key holders' public keys and then **erased from kernel memory**.
- While a session is enabled, the module file, auto-load config, hosts file and state file are protected by kernel-set immutable/append-only flags and `inode_operations` overrides (which also refuse `chattr`), re-checked every second. Nothing is protected while disabled.
- Sessions are timed with the boot-time clock, so changing the system clock cannot end them. A PGP session is persisted by the kernel itself and restored when the module loads; time spent powered off does not count towards the session.

## 🖥️ Desktop app

`gui/` is a Tauri app (Astro + Svelte + Tailwind). It reads state directly and makes
changes through `pkexec kblockerctl`, using the polkit policy that `make install`
puts in place. Run as root (`sudo kblocker`, from the `.deb`), it calls `kblockerctl`
directly, and files it saves are given to the user who ran sudo. Scheduled blocks and history don't depend on it: the scheduler service
handles both.
