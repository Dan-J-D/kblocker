# Fuzzing kblocker with syzkaller

[syzkaller](https://github.com/google/syzkaller) is a coverage-guided kernel
fuzzer. It boots a separately built, KCOV/KASAN-instrumented kernel in QEMU/KVM
VMs, loads `kblocker.ko` there, and evolves programs of system calls towards
new code in the module. Crashes, KASAN reports, lockdep splats and hangs are
collected and reproduced automatically. Your host kernel is never involved.

What the descriptions in `kblocker.txt` exercise:

- every `/sys/kernel/kblocker` attribute, with valid, edge-case and malformed
  input (durations, domain and IP lists, PGP arming, keys)
- the TLS ClientHello/SNI parser, through well-formed but mutated ClientHellos
  sent on TCP over IPv4/IPv6, including TCP Fast Open (data in the SYN), ECH
  extensions, padding that pushes SNI past the first segment, and records that
  announce more bytes than they carry
- the UDP/443 path
- the file-protection hooks, through `open`, `unlink`, `rename`, `link`,
  `truncate`, `chmod`, bind mounts and `FS_IOC_SETFLAGS` on the protected paths,
  racing with sessions being enabled and disabled
- boot-time recovery from the state file: the fuzzer rewrites the state file
  with valid, torn and legacy records while no session is active, then
  triggers a simulated reboot through `debug_restore` (a debug-build-only
  attribute that drops the in-memory session, keeps the files and runs
  recovery as at module init)
- the periodic `remaining:` appends, which debug builds make every 2 seconds
  instead of every 60

The module is built with `KBLOCKER_DEBUG=1` and loaded in the VM with:

- `hook_all_netns=1`, because syz-executor runs every test process in its own
  network namespace;
- `hosts_file=/dev/kblocker-hosts`, `state_file=/dev/kblocker-state` and
  `modconf_file=/dev/kblocker-modules.conf` (created by a `tmpfiles.d` entry),
  because the executor sandbox only sees `/dev`, `/proc` and `/sys`, so
  protected files under `/etc` and `/var` would be unreachable. These
  parameters exist only in debug builds;
- `fixed_key=1` (debug builds only), which makes every key `00 01 02 … 0f`.
  syzkaller cannot feed what it reads from `key` into a later write, so with
  random keys the authorized `disable` and `unblock` paths would be
  unreachable.

`KBLOCKER_DEBUG` also checks kblocker's session invariants each time
`kb_lock` is released (`kb_check_invariants()` in `src/state.c`). A violated
invariant is a `WARN`, so logic bugs show up as crashes even when nothing
faults.

## Requirements

- x86_64 host with `/dev/kvm` writable by your user, `qemu-system-x86_64`
- kernel build tools (`gcc make flex bison bc libelf-dev libssl-dev`)
- Go (any recent version; syzkaller's newer toolchain is downloaded
  automatically), `git`
- `debootstrap` and `sudo` for building the VM image
- about 30 GB of disk and some time for the first kernel build

## Usage

```sh
make syz-setup     # = fuzz/syzkaller/setup.sh all
make syz-run       # starts syz-manager; dashboard on http://127.0.0.1:56741
```

Stages can be run individually: `fuzz/syzkaller/setup.sh syzkaller|kernel|
module|image|config|run`. After changing the module, rerun `module` and
`image` to rebuild it and install it into the VM image.

Environment variables: `SYZ_WORK` (work directory, default
`fuzz/syzkaller/work`), `KERNEL_REF` (stable tag to fuzz, default `v7.0.14`),
`SYZ_COMMIT` (syzkaller commit), `VMS` (number of VMs, default 4).

Findings appear on the dashboard and under `$SYZ_WORK/workdir/crashes/`.

## Updating the descriptions

Edit `kblocker.txt`; if you use a new constant, add its amd64 value to
`kblocker.txt.const`. syzlang strings have no escape sequences, so a
newline must be a separate `const[0xa, int8]` byte.

`seeds/` holds starting programs (a restored session, a PGP session, a
session with protected-file operations) that random generation reaches
slowly. `setup.sh syzkaller` copies them to `sys/linux/test`, where
syz-manager loads them on every start; a seed that no longer parses is
reported as broken in the manager log. `setup.sh syzkaller` copies both into syzkaller and
rebuilds, which fails with a precise error if a description is invalid.
