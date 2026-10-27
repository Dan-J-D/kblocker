#!/bin/bash
# Build everything needed to fuzz kblocker with syzkaller in QEMU/KVM VMs.
#
#   fuzz/syzkaller/setup.sh [all|syzkaller|kernel|module|image|config|run]
#
# Stages are idempotent; "all" runs every stage except "run". Only "image"
# needs sudo (debootstrap and loop mounts). The host kernel is never touched.
#
# Environment:
#   SYZ_WORK     work directory (default: fuzz/syzkaller/work, ~30 GB)
#   KERNEL_REF   stable kernel tag to fuzz (default: v7.0.14)
#   SYZ_COMMIT   syzkaller commit (default: the one the descriptions were
#                validated against)
#   VMS          number of fuzzing VMs (default: 4)
#   SANITIZER    kasan (default: memory errors, one process per VM) or kcsan
#                (data races, several processes per VM); each has its own
#                kernel, module, image, workdir and dashboard port
#   PROCS        fuzzing processes per VM (default: 1 for kasan, 4 for kcsan)
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
	# sudo would also drop SYZ_WORK and leave root-owned files that
	# syz-manager cannot read; the stages that need root call sudo themselves.
	echo "run $0 as your normal user, not with sudo" >&2
	exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${SYZ_WORK:-$HERE/work}
KERNEL_REF=${KERNEL_REF:-v7.0.14}
SYZ_COMMIT=${SYZ_COMMIT:-96923c60bc33dfd47fae3ebc1f6dccf048e7c918}
VMS=${VMS:-4}
SANITIZER=${SANITIZER:-kasan}
case "$SANITIZER" in
	kasan) SFX=""; PORT=56741; PROCS=${PROCS:-1} ;;
	# KCSAN only reports races between accesses that actually overlap, so
	# it needs programs running concurrently in the same kernel
	kcsan) SFX="-kcsan"; PORT=56742; PROCS=${PROCS:-4} ;;
	*) echo "SANITIZER must be kasan or kcsan" >&2; exit 2 ;;
esac
LINUX=$WORK/linux$SFX
MODULE=$WORK/module$SFX
IMAGE=$WORK/image/trixie$SFX.img
JOBS=$(nproc)
KERNEL_GIT=https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

mkdir -p "$WORK"

need() {
	for tool in "$@"; do
		command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
	done
}

stage_syzkaller() {
	need git go
	if [[ ! -d "$WORK/syzkaller/.git" ]]; then
		git init -q "$WORK/syzkaller"
		git -C "$WORK/syzkaller" remote add origin https://github.com/google/syzkaller.git
	fi
	if [[ "$(git -C "$WORK/syzkaller" rev-parse HEAD 2>/dev/null)" != "$SYZ_COMMIT" ]]; then
		git -C "$WORK/syzkaller" fetch -q --depth 1 origin "$SYZ_COMMIT"
		git -C "$WORK/syzkaller" checkout -q FETCH_HEAD
	fi
	cp "$HERE/kblocker.txt" "$HERE/kblocker.txt.const" "$WORK/syzkaller/sys/linux/"
	# syz-manager starts from every program in sys/linux/test; these reach
	# deep states (a restored session, a PGP session) that random
	# generation finds slowly
	cp "$HERE"/seeds/kblocker_* "$WORK/syzkaller/sys/linux/test/"
	# syzkaller pins a newer Go than distros ship; let go fetch it
	GOTOOLCHAIN=auto make -C "$WORK/syzkaller" -j"$JOBS"
}

stage_kernel() {
	need git make gcc flex bison bc
	if [[ ! -d "$LINUX/.git" ]]; then
		git clone -q --depth 1 --branch "$KERNEL_REF" "$KERNEL_GIT" "$LINUX"
	fi
	cd "$LINUX"
	if [[ ! -f .config ]]; then
		local fragments=("$HERE/kernel.config")
		[[ $SANITIZER == kcsan ]] && fragments+=("$HERE/kernel-kcsan.config")
		make defconfig
		make kvm_guest.config
		scripts/kconfig/merge_config.sh -m .config "${fragments[@]}"
		make olddefconfig
		if [[ $SANITIZER == kcsan ]] && ! grep -q '^CONFIG_KCSAN=y' .config; then
			# KCSAN silently drops out if the compiler lacks -fsanitize=thread
			echo "CONFIG_KCSAN did not survive olddefconfig (compiler too old?)" >&2
			rm .config
			exit 1
		fi
	fi
	# "modules" also writes Module.symvers, which out-of-tree modules link against
	make -j"$JOBS" bzImage modules
}

stage_module() {
	mkdir -p "$MODULE"
	# Build from a copy so the fuzzing kernel's objects never mix with a
	# regular host build in the repository.
	rm -rf "$MODULE"/*
	cp -a "$REPO/src" "$MODULE/"
	cp "$REPO/Makefile" "$MODULE/"
	# KBLOCKER_DEBUG turns invariant violations into WARNs, which the
	# fuzzer reports as crashes, and allows relocating the protected files.
	# The kernel's sanitizer (KASAN or KCSAN) instruments the module too.
	make -C "$LINUX" M="$MODULE" KBLOCKER_DEBUG=1 -j"$JOBS" modules
	echo "built $MODULE/kblocker.ko"
}

stage_image() {
	need debootstrap sudo
	local rel base mnt
	rel=$(make -s -C "$LINUX" kernelrelease)
	base="$WORK/image/trixie.img"
	mkdir -p "$WORK/image"
	if [[ ! -f "$base" ]]; then
		# debootstrap creates device nodes, so the chroot must live on a
		# filesystem without nodev (home directories often have it); only
		# the finished image and key are kept.
		local build
		build=$(mktemp -d "${IMAGE_BUILD_DIR:-/var/tmp}/kblocker-image.XXXXXX")
		(cd "$build" && "$WORK/syzkaller/tools/create-image.sh" --distribution trixie)
		mv "$build/trixie.img" "$build/trixie.id_rsa" "$build/trixie.id_rsa.pub" "$WORK/image/"
		sudo rm -rf "$build"
	fi
	# Each sanitizer gets its own copy of the base image: both kernels have
	# the same release, so their kblocker.ko would land at the same path
	if [[ ! -f "$IMAGE" ]]; then
		cp --sparse=always "$base" "$IMAGE"
	fi

	mnt=$(mktemp -d)
	sudo mount -o loop "$IMAGE" "$mnt"
	trap 'sudo umount "$mnt"; rmdir "$mnt"' RETURN
	sudo install -D -m 644 "$MODULE/kblocker.ko" "$mnt/lib/modules/$rel/extra/kblocker.ko"
	sudo depmod -b "$mnt" "$rel"
	echo kblocker | sudo tee "$mnt/etc/modules-load.d/kblocker.conf" >/dev/null
	# The executor sandbox only sees /dev, /proc and /sys, so the debug
	# build protects files under /dev (a devtmpfs, recreated each boot)
	# instead of /etc and /var, letting syscalls reach the protection code.
	sudo tee "$mnt/etc/tmpfiles.d/kblocker-fuzz.conf" >/dev/null <<-'EOF'
		f /dev/kblocker-hosts 0644 root root - 127.0.0.1 localhost\n::1 localhost\n
		f /dev/kblocker-modules.conf 0644 root root - kblocker\n
		f /dev/kblocker-state 0600 root root -
	EOF
	# fixed_key=1: a constant key the descriptions know, so authorized
	# disables and unloads are reachable
	echo "options kblocker hook_all_netns=1 fixed_key=1 hosts_file=/dev/kblocker-hosts" \
		"state_file=/dev/kblocker-state modconf_file=/dev/kblocker-modules.conf" |
		sudo tee "$mnt/etc/modprobe.d/kblocker.conf" >/dev/null
	sudo mkdir -p "$mnt/var/lib/kblocker"
	# debootstrap images have no /etc/hosts; kblocker rewrites it
	if ! sudo test -f "$mnt/etc/hosts"; then
		printf '127.0.0.1\tlocalhost\n127.0.1.1\tsyzkaller\n::1\tlocalhost ip6-localhost ip6-loopback\n' |
			sudo tee "$mnt/etc/hosts" >/dev/null
	fi
	echo "installed kblocker.ko for $rel into $IMAGE"
}

stage_config() {
	# kcsan-ignores as a JSON string list: drop comments and blank lines,
	# escape backslashes and quotes, quote each line, join with commas
	local ignores=""
	if [[ $SANITIZER == kcsan ]]; then
		ignores=$(grep -v -e '^#' -e '^[[:space:]]*$' "$HERE/kcsan-ignores" |
			sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/"&"/' | paste -sd, -)
	fi
	# "|" is the sed delimiter, so escape the regexps' alternations (and
	# the backslashes and "&" that sed would otherwise interpret)
	ignores=$(printf '%s' "$ignores" | sed -e 's/[\\&|]/\\&/g')
	sed -e "s|@IGNORES@|$ignores|" -e "s|@WORK@|$WORK|g" -e "s|@VMS@|$VMS|g" -e "s|@PROCS@|$PROCS|g" \
		-e "s|@PORT@|$PORT|g" -e "s|@WORKDIR@|$WORK/workdir$SFX|g" \
		-e "s|@LINUX@|$LINUX|g" -e "s|@MODULE@|$MODULE|g" -e "s|@IMAGE@|$IMAGE|g" \
		"$HERE/syz-manager.cfg.in" > "$WORK/syz-manager$SFX.cfg"
	echo "wrote $WORK/syz-manager$SFX.cfg"
}

stage_run() {
	[[ -w /dev/kvm ]] || { echo "/dev/kvm is not writable by $(id -un)" >&2; exit 1; }
	mkdir -p "$WORK/workdir$SFX"
	echo "dashboard: http://127.0.0.1:$PORT"
	exec "$WORK/syzkaller/bin/syz-manager" -config "$WORK/syz-manager$SFX.cfg"
}

case "${1:-all}" in
	all)       stage_syzkaller; stage_kernel; stage_module; stage_image; stage_config ;;
	syzkaller) stage_syzkaller ;;
	kernel)    stage_kernel ;;
	module)    stage_module ;;
	image)     stage_image ;;
	config)    stage_config ;;
	run)       stage_run ;;
	*) echo "usage: $0 [all|syzkaller|kernel|module|image|config|run]" >&2; exit 2 ;;
esac
