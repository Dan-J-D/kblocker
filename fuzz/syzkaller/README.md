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

The module is loaded with `hook_all_netns=1` in the VM, because syz-executor
runs every test process in its own network namespace.

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
`kblocker.txt.const`. `setup.sh syzkaller` copies both into syzkaller and
rebuilds, which fails with a precise error if a description is invalid.
