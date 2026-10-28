# 🧪 Development and tests

## 🔨 Build

```sh
make
```

Requires kernel headers (`linux-headers-$(uname -r)`) and Go 1.21+. The module needs Linux 6.3 or newer.

```sh
sudo ./install.sh     # same as: sudo make install
sudo ./uninstall.sh   # same as: sudo make uninstall
make deb              # .deb (DKMS module + kblockerctl + the app as kblocker) in build/
make gui              # just the app: gui/src-tauri/target/release/kblocker-gui
```

## 🖥️ Desktop app

```sh
cd gui
pnpm install
pnpm tauri dev      # run against the installed kblockerctl
pnpm dev            # UI only, in a browser, with sample data
pnpm tauri build    # .deb and AppImage in src-tauri/target/release/bundle
```

Linux builds need `libwebkit2gtk-4.1-dev` and `libayatana-appindicator3-dev`.

`pnpm dev` uses the demo data in `gui/src/lib/mock.ts`. Add `?state=active` to the
URL to start mid-block, or `?state=new` for a fresh install. The screenshots in
[`docs/screenshots`](screenshots) are taken this way.

## ✅ Integration tests

```sh
sudo ./test.sh
```

Runs integration tests against the live kernel module via sysfs.

## 🐛 Fuzzing

`cmd/fuzz` is a quick black-box fuzzer for the sysfs interface on the host.
For coverage-guided fuzzing of the whole module (sysfs, the TLS/SNI parser via
real traffic, and the file-protection hooks) under KASAN and lockdep in
throwaway VMs, see [fuzz/syzkaller](../fuzz/syzkaller/README.md):

```sh
make syz-setup && make syz-run
```

A second setup swaps KASAN for KCSAN and runs several processes per VM to
find data races:

```sh
make syz-setup-kcsan && make syz-run-kcsan
```

The fuzzing build is compiled with `KBLOCKER_DEBUG=1`, which checks the
session invariants after every state change (enabled exactly when the module
holds its own reference, no protected files or state file while disabled, no
raw key in memory during a PGP session, a restored session is always
PGP-locked, list sizes in bounds, stored domains normalized). A violation is
a `WARN`, which syzkaller reports as a crash with a reproducer.

## 🧮 Property tests

The parsing code (`src/parse.c`: SNI extraction, domain matching and
normalization, key and state-file parsing, the hosts-file block) is plain C
shared with a userspace build. `make proptest` runs Hypothesis property tests
of it under AddressSanitizer and UBSan, comparing each function with a short
Python model:

```sh
make proptest
KB_PROPTEST_EXAMPLES=100000 tests/proptest/run.sh   # longer soak
```
