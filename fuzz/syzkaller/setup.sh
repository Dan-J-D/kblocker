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
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${SYZ_WORK:-$HERE/work}
KERNEL_REF=${KERNEL_REF:-v7.0.14}
SYZ_COMMIT=${SYZ_COMMIT:-96923c60bc33dfd47fae3ebc1f6dccf048e7c918}
VMS=${VMS:-4}
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
	# syzkaller pins a newer Go than distros ship; let go fetch it
	GOTOOLCHAIN=auto make -C "$WORK/syzkaller" -j"$JOBS"
}

stage_kernel() {
	need git make gcc flex bison bc
	if [[ ! -d "$WORK/linux/.git" ]]; then
		git clone -q --depth 1 --branch "$KERNEL_REF" "$KERNEL_GIT" "$WORK/linux"
	fi
	cd "$WORK/linux"
	if [[ ! -f .config ]]; then
		make defconfig
		make kvm_guest.config
		scripts/kconfig/merge_config.sh -m .config "$HERE/kernel.config"
		make olddefconfig
	fi
	# "modules" also writes Module.symvers, which out-of-tree modules link against
	make -j"$JOBS" bzImage modules
}

stage_module() {
	mkdir -p "$WORK/module"
	# Build from a copy so the fuzzing kernel's objects never mix with a
	# regular host build in the repository.
	rm -rf "$WORK/module"/*
	cp -a "$REPO/src" "$WORK/module/"
	printf 'obj-m += kblocker.o\nkblocker-objs := src/main.o src/netfilter.o src/file_protection.o src/state.o src/key.o\n' \
		> "$WORK/module/Kbuild"
	make -C "$WORK/linux" M="$WORK/module" -j"$JOBS" modules
	echo "built $WORK/module/kblocker.ko"
}

stage_image() {
	need debootstrap sudo
	local rel img mnt
	rel=$(make -s -C "$WORK/linux" kernelrelease)
	img="$WORK/image/trixie.img"
	mkdir -p "$WORK/image"
	if [[ ! -f "$img" ]]; then
		(cd "$WORK/image" && "$WORK/syzkaller/tools/create-image.sh" --distribution trixie)
	fi

	mnt=$(mktemp -d)
	sudo mount -o loop "$img" "$mnt"
	trap 'sudo umount "$mnt"; rmdir "$mnt"' RETURN
	sudo install -D -m 644 "$WORK/module/kblocker.ko" "$mnt/lib/modules/$rel/extra/kblocker.ko"
	sudo depmod -b "$mnt" "$rel"
	echo kblocker | sudo tee "$mnt/etc/modules-load.d/kblocker.conf" >/dev/null
	echo "options kblocker hook_all_netns=1" | sudo tee "$mnt/etc/modprobe.d/kblocker.conf" >/dev/null
	sudo mkdir -p "$mnt/var/lib/kblocker"
	echo "installed kblocker.ko for $rel into $img"
}

stage_config() {
	sed -e "s|@WORK@|$WORK|g" -e "s|@VMS@|$VMS|g" "$HERE/syz-manager.cfg.in" > "$WORK/syz-manager.cfg"
	echo "wrote $WORK/syz-manager.cfg"
}

stage_run() {
	[[ -w /dev/kvm ]] || { echo "/dev/kvm is not writable by $(id -un)" >&2; exit 1; }
	mkdir -p "$WORK/workdir"
	echo "dashboard: http://127.0.0.1:56741"
	exec "$WORK/syzkaller/bin/syz-manager" -config "$WORK/syz-manager.cfg"
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
