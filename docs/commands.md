# ⌨️ Command reference

Every command is run as root: `sudo kblockerctl <command>`.

## Blocking

| Command | Description |
|---------|-------------|
| `enable <minutes> [--insecure]` | Enable blocking. Requires PGP unless `--insecure` |
| `disable` / `unblock [--key <hex>]` | Disable blocking. Needs PGP key when PGP mode is active |
| `unload [--key <hex>]` | Permanently remove the module. Needs the unblock key |
| `status` | Show blocking state, remaining time, protected files |
| `crash` | Force-remove module (triggers kernel panic) |
| `reset [--history] [--key-holders] [--yes]` | Back to a fresh install's settings: the starter site list, no allowed networks or blocked IPs, no schedule, key holder pages on this computer only. `--history` and `--key-holders` also delete those. Asks you to type `reset` unless `--yes`; refused while blocking is active. Also under System → Maintenance in the desktop app |

## Sites and IPs

| Command | Description |
|---------|-------------|
| `block <domain>...` | Write domains to kernel and config file (does not enable) |
| `add <domain>` | Add a domain to the persistent config |
| `remove <domain>` | Remove a domain |
| `reload` | Re-write domains to kernel, refresh PGP ciphertexts |
| `block-ip <ip>...` | Set blocked IPs directly (replaces existing list) |
| `allow-ip <ip\|cidr>...` | Never block traffic to these addresses, e.g. a WireGuard subnet `10.0.0.0/24` (replaces existing list; `--clear` empties it). Saved to `/etc/kblocker/allowed_ips.conf`, applied on every `enable`, and fixed while a block is active |
| `list` | Show blocked IPs and configured domains |

Domain rules match the exact name or any subdomain: `x.com` blocks `www.x.com`, not `netflix.com`.

## Key holders (PGP)

| Command | Description |
|---------|-------------|
| `key` | Show the current unload key and PGP key fingerprints |
| `add-pgp <pubkey.asc> [name]` | Register a PGP public key |
| `remove-pgp <fingerprint>` | Remove a registered PGP key |
| `list-pgp` | List registered PGP keys |
| `pgp-cipher <fingerprint>` | Print the PGP-encrypted unload key for a recipient |
| `add-pgp-web [--port <port>] [--bind <ip>]` | Start web UI for browser-based PGP key generation |
| `unblock-web [--port <port>] [--bind <ip>]` | Start web UI to decrypt and submit unblock key via browser |
| `web-pages [off \| local \| lan \| custom --bind <ip>] [--port <port>]` | Show or set where the scheduler service hosts the key holder pages |

## Schedule and history

| Command | Description |
|---------|-------------|
| `schedule [--json]` | Show scheduled blocks |
| `schedule set <file \| ->` | Replace the weekly schedule (not while blocking) |
| `schedule clear` | Remove all scheduled blocks |
| `schedule-daemon` | Start scheduled blocks, record history and host the key holder pages (run by `kblocker-scheduler.service`) |
| `history [--json]` | Show past blocks and time spent blocking |

## 🔐 PGP mode in detail

Without PGP, the unload key is readable from `/sys/kernel/kblocker/key`. Anyone with root can retrieve it and disable the blocker. PGP mode encrypts the key to trusted recipients so that:

1. On `enable`, kblockerctl reads the key from sysfs, GPG-encrypts it for all registered public keys, and signals the kernel to zero the key from memory
2. The `key` sysfs attribute returns `"encrypted"` instead of the raw hex
3. `unblock` and `unload` require the decrypted key (PGP-decrypt the ciphertext, write the plain hex to the kernel)

```sh
sudo kblockerctl add-pgp alice.pub   # register a PGP public key
sudo kblockerctl enable 60           # enable with PGP protection
sudo kblockerctl unblock             # needs the PGP private key to decrypt
sudo kblockerctl unload              # needs the key too
```

### 🌐 Browser-based key management

Generate PGP keys entirely in the browser (using OpenPGP.js). The private key never touches the server:

```sh
sudo kblockerctl add-pgp-web
# Opens on http://127.0.0.1:<random-port>
```

The unblock page decrypts the PGP ciphertext client-side in the browser and submits the key:

```sh
sudo kblockerctl unblock-web
# Opens on http://127.0.0.1:<random-port>
```

### 🔁 Surviving a reboot

PGP-protected sessions are persisted to `/var/lib/kblocker/state` and restored
when the module loads again. A restored session is always re-armed with PGP
protection inside the kernel: the key stays erased from memory and `disable`
still requires the key, so rebooting does not weaken the block. The block
clears itself when the timer expires, key or not. Insecure (`--insecure`)
sessions are never persisted and do not survive a reboot.

### ⚠️ Insecure mode

Without any key registered, `--insecure` mode prints the key to stdout instead:

```sh
sudo kblockerctl enable 60 --insecure
```

## 🗓️ Scheduled blocks

`kblockerctl schedule set` stores a weekly schedule in `/etc/kblocker/schedule.json`,
and `kblocker-scheduler.service` (installed and enabled by `make install`) starts a
PGP-locked block whenever a window opens, lasting until the window closes:

```json
{ "blocks": [
  { "id": "am", "name": "Morning focus", "days": [1,2,3,4,5], "start": "09:00", "end": "12:00", "enabled": true },
  { "id": "pm", "name": "Afternoon focus", "days": [1,2,3,4,5], "start": "13:00", "end": "17:00", "enabled": true }
] }
```

Days are numbered from Sunday (0) to Saturday (6); an end at or before the start runs
past midnight. Each window is started once: unlocking it early with the key lifts it
until the next window. The schedule can't be changed while a block is running. Scheduled
blocks need at least one registered PGP key.

The same service records every block, however it was started, in
`/var/lib/kblocker/history.jsonl`; `kblockerctl history` summarizes it. It also hosts
the key holder pages on `http://127.0.0.1:8737` (`/keys` to create and register a key,
`/unblock` to decrypt the unload key in the browser and end a block).
`sudo kblockerctl web-pages lan` opens them to other devices on your network,
`local` limits them to this computer again, `custom --bind <ip>` listens on one
address you choose (a VPN address, say) and `off` turns them off. Browsers only let
the pages use WebCrypto, which OpenPGP.js needs, on https or localhost, so when other
devices can reach the pages they're also served over https on the same port, and plain
http requests for anything but localhost are redirected there. The certificate is
self-signed and kept in `/var/lib/kblocker/web-cert.pem` (key in `web-key.pem`), so each
device warns about it the first time; accepting it lets them continue. It's renewed a
month before it expires, or when this computer gets a new address. Its SHA-256
fingerprint is in the service log (`journalctl -u kblocker-scheduler | grep certificate`)
for comparing with what a browser shows.

The pages turn themselves off once nobody has viewed them for 5 minutes. A page sends a
heartbeat every 30 seconds while it's being viewed (its tab showing in the focused
window); a closed, background or locked tab, or one whose window is behind another app,
doesn't, and neither does the keys page's background status check. If a heartbeat
fails, the page says the pages can't be reached instead of failing on the next click.
When they turn off, the setting is saved as `off` so they stay off after a restart. Turn them on again with `web-pages` or in the app when a
key holder needs them. `add-pgp-web` and `unblock-web` stop the same way. Add `--port <port>`
to any of them to move the pages; otherwise the port is kept. The setting is saved in
a drop-in for the service, and `add-pgp-web` / `unblock-web` use the same address by
default. All of it is also on the desktop app's Key holders and System pages. The pages
only accept same-origin requests, and OpenPGP.js is built into `kblockerctl` rather than
loaded from a CDN.
