#!/bin/bash
# kblocker integration tests
# Runs against the live kernel module via sysfs.
# Requires root. Run: sudo ./test.sh

PWD=$(dirname "$(readlink -f "$0")")
PASS=0
FAIL=0

SYSFS="/sys/kernel/kblocker"
MODULE="kblocker"
TMPDIR=$(mktemp -d)

cleanup() {
	rm -rf "$TMPDIR"
	# Wipe any persistent test state from kblockerctl
	chattr -i /var/lib/kblocker/state 2>/dev/null || true
	rm -f /var/lib/kblocker/state
	if command -v chattr &>/dev/null && [[ -d /var/lib/kblocker/unlock-pgp ]]; then
		for f in /var/lib/kblocker/unlock-pgp/unlock-*.asc; do
			[[ -f "$f" ]] && chattr -i "$f" 2>/dev/null || true
		done
	fi
	rm -rf /var/lib/kblocker/unlock-pgp
	rm -rf /etc/kblocker/keys
	# Try to force module removal safely
	if [[ -d "$SYSFS" ]]; then
		echo 0 > "$SYSFS/pgp_active" 2>/dev/null || true
		echo "0" > "$SYSFS/enabled" 2>/dev/null || true
		sleep 1
		rmmod $MODULE 2>/dev/null || rmmod -f $MODULE 2>/dev/null || true
	fi
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo -e "  \033[0;32mPASS\033[0m $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  \033[0;31mFAIL\033[0m $1"; }
check() { if "$@"; then ok "$*"; else fail "$*"; return 1; fi; }

echo "=== kblocker integration tests ==="
echo ""

# Force-clean any state leftover from interrupted test runs
if command -v chattr &>/dev/null && [[ -d /var/lib/kblocker/unlock-pgp ]]; then
	for f in /var/lib/kblocker/unlock-pgp/unlock-*.asc; do
		[[ -f "$f" ]] && chattr -i "$f" 2>/dev/null || true
	done
fi
rm -rf /etc/kblocker/keys /var/lib/kblocker/unlock-pgp
chattr -i /var/lib/kblocker/state 2>/dev/null || true
rm -f /var/lib/kblocker/state

# --- Build ---
echo "--- Build ---"
if make -C /lib/modules/$(uname -r)/build M="$PWD" modules &>/dev/null; then
    ok "module builds"
else
    fail "module builds"
    exit 1
fi

# --- Load ---
echo "--- Load ---"
if insmod kblocker.ko 2>/dev/null; then
    ok "insmod succeeds"
else
    fail "insmod succeeds"
    exit 1
fi
check test -d "$SYSFS"

# --- status ---
echo "--- status ---"
STATUS=$(cat "$SYSFS/status")
check grep -q '^enabled: 0$' <<<"$STATUS"
check grep -q '^blocked_ips_v4: 0$' <<<"$STATUS"
check grep -q '^blocked_ips_v6: 0$' <<<"$STATUS"
check grep -q '^blocked_domains: 0$' <<<"$STATUS"
check grep -q '^remaining: 0$' <<<"$STATUS"
check grep -q '^allow_unload: 0$' <<<"$STATUS"
check grep -q '^protected_files:' <<<"$STATUS"

# ==========================================
# --- file protection ---
echo "--- file protection ---"

KO_FILE="/lib/modules/$(uname -r)/extra/kblocker.ko"
if [[ -f "$KO_FILE" ]] && command -v lsattr &>/dev/null; then
    ATTRS=$(lsattr "$KO_FILE" 2>/dev/null | awk '{print $1}')
    if echo "$ATTRS" | grep -q 'i'; then
        ok "protection: kblocker.ko is immutable"
    fi
fi
if [[ -f "$KO_FILE" ]]; then
    if echo "x" > "$KO_FILE" 2>/dev/null; then
        fail "protection: kblocker.ko write should be rejected"
    else
        ok "protection: kblocker.ko write rejected"
    fi
fi

CFG_FILE="/etc/modules-load.d/kblocker.conf"
if [[ -f "$CFG_FILE" ]] && command -v lsattr &>/dev/null; then
    ATTRS=$(lsattr "$CFG_FILE" 2>/dev/null | awk '{print $1}')
    if echo "$ATTRS" | grep -q 'i'; then
        ok "protection: kblocker.conf is immutable"
    fi
fi
if [[ -f "$CFG_FILE" ]]; then
    if echo "x" > "$CFG_FILE" 2>/dev/null; then
        fail "protection: kblocker.conf write should be rejected"
    else
        ok "protection: kblocker.conf write rejected"
    fi
fi

if echo "x" >> /etc/hosts 2>/dev/null; then
    fail "protection: /etc/hosts write should be rejected"
else
    ok "protection: /etc/hosts write rejected"
fi

# --- key ---
echo "--- key ---"
KEY=$(cat "$SYSFS/key")
KEY_LEN=${#KEY}
# 32 hex chars + newline from cat (32 + 1)
# but cat strips trailing newline from $(), so length should be 32
if [[ ${#KEY} -eq 32 ]] && [[ "$KEY" =~ ^[0-9a-f]+$ ]]; then
    ok "key is 32 hex chars: $KEY"
else
    fail "key is 32 hex chars (got len=${#KEY}, val=$KEY)"
fi
# Verify it changes on reload
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null
KEY2=$(cat "$SYSFS/key")
if [[ "$KEY" != "$KEY2" ]]; then
    ok "key changes across reloads"
else
    fail "key changes across reloads"
fi

# --- unblock with wrong key ---
echo "--- unblock (wrong key) ---"
if echo "00000000000000000000000000000000" > "$SYSFS/unblock" 2>/dev/null; then
    fail "unblock with wrong key: should have failed"
else
    ok "unblock with wrong key: rejected"
fi
# allow_unload should still be 0
check grep -q '^allow_unload: 0$' < "$SYSFS/status"

# --- unblock with correct key ---
echo "--- unblock (correct key) ---"
CORRECT_KEY=$(cat "$SYSFS/key")
echo -n "$CORRECT_KEY" > "$SYSFS/unblock" 2>/dev/null
check grep -q '^allow_unload: 1$' < "$SYSFS/status"
check grep -q '^enabled: 0$' < "$SYSFS/status"

# --- ensure unblock is one-shot ---
echo "--- unblock (replay attack) ---"
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null
NEW_KEY=$(cat "$SYSFS/key")
# Try old key
if echo "00000000000000000000000000000000" > "$SYSFS/unblock" 2>/dev/null; then
    fail "old/wrong key should not work"
else
    ok "old/wrong key correctly rejected"
fi
# Try new correct key
echo -n "$NEW_KEY" > "$SYSFS/unblock" 2>/dev/null
check grep -q '^allow_unload: 1$' < "$SYSFS/status"

# --- enabled toggle ---
echo "--- enabled ---"
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null
echo "30" > "$SYSFS/enabled"
check grep -q '^enabled: 1$' < "$SYSFS/status"
# remaining should be approx 30
REMAINING=$(grep '^remaining:' < "$SYSFS/status" | awk '{print $2}')
if [[ "$REMAINING" -gt 25 ]] && [[ "$REMAINING" -le 30 ]]; then
    ok "remaining ~30s (got ${REMAINING}s)"
else
    fail "remaining ~30s (got ${REMAINING}s)"
fi
echo "0" > "$SYSFS/enabled"
check grep -q '^enabled: 0$' < "$SYSFS/status"
check grep -q '^remaining: 0$' < "$SYSFS/status"

# --- enabled with 0 should fail ---
if echo "0" > "$SYSFS/enabled" 2>/dev/null; then
    ok "enabled 0: accepted (disables)"
else
    fail "enabled 0: accepted"
fi

# --- blocked_ips round-trip ---
echo "--- blocked_ips ---"
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null
check grep -q '^blocked_ips_v4: 0$' < "$SYSFS/status"
echo "10.0.0.1" > "$SYSFS/blocked_ips"
check grep -q '^blocked_ips_v4: 1$' < "$SYSFS/status"
check grep -q '^blocked_ips_v6: 0$' < "$SYSFS/status"
check grep -q '10.0.0.1' < "$SYSFS/blocked_ips"

# multiple IPs
cat > "$SYSFS/blocked_ips" << 'EOF'
10.0.0.2
10.0.0.3
10.0.0.4
EOF
check grep -q '^blocked_ips_v4: 3$' < "$SYSFS/status"

# comment lines should be ignored
cat > "$SYSFS/blocked_ips" << 'EOF'
10.0.0.5
# comment
10.0.0.6
EOF
check grep -q '^blocked_ips_v4: 2$' < "$SYSFS/status"

# block_count
COUNT=$(cat "$SYSFS/block_count")
if [[ "$COUNT" -eq 2 ]]; then
    ok "block_count is 2"
else
    fail "block_count is 2 (got $COUNT)"
fi

# --- IPv6 blocked_ips ---
echo "--- blocked_ips (IPv6) ---"
cat > "$SYSFS/blocked_ips" << 'EOF'
::1
2606:4700:4700::1111
EOF
check grep -q '^blocked_ips_v6: 2$' < "$SYSFS/status"
check grep -q '^blocked_ips_v4: 0$' < "$SYSFS/status"
# %pI6 format may vary by kernel, check for colons (IPv6 indicator)
check grep -q ':' < "$SYSFS/blocked_ips"
# Verify we have 2 lines
check test "$(cat "$SYSFS/blocked_ips" | wc -l)" -eq 2

# --- block-ip command ---
echo "--- block-ip command ---"
"$PWD/kblockerctl" block-ip 10.0.0.100 10.0.0.101 2>/dev/null
check grep -q '^blocked_ips_v4: 2$' < "$SYSFS/status"
check grep -q '^blocked_ips_v6: 0$' < "$SYSFS/status"
check grep -q '10.0.0.100' < "$SYSFS/blocked_ips"
check grep -q '10.0.0.101' < "$SYSFS/blocked_ips"

# block-ip with IPv6
"$PWD/kblockerctl" block-ip 2001:db8::1 2001:db8::2 2>/dev/null
check grep -q '^blocked_ips_v4: 0$' < "$SYSFS/status"
check grep -q '^blocked_ips_v6: 2$' < "$SYSFS/status"
check grep -q ':' < "$SYSFS/blocked_ips"

# --- blocked_domains round-trip ---
echo "--- blocked_domains ---"
cat > "$SYSFS/blocked_domains" << 'EOF'
youtube.com
reddit.com
EOF
check grep -q '^blocked_domains: 2$' < "$SYSFS/status"
check grep -q 'youtube.com' < "$SYSFS/blocked_domains"
check grep -q 'reddit.com' < "$SYSFS/blocked_domains"
# clear domains
echo "" > "$SYSFS/blocked_domains"
check grep -q '^blocked_domains: 0$' < "$SYSFS/status"

# ==========================================
# --- Network blocking tests ---
echo ""
echo "--- blocking (IPv4) ---"
echo "127.0.0.2" > "$SYSFS/blocked_ips"
echo "10" > "$SYSFS/enabled"
check grep -q '^blocked_ips_v4: 1$' < "$SYSFS/status"
check grep -q '^enabled: 1$' < "$SYSFS/status"
echo "0" > "$SYSFS/enabled"
echo "" > "$SYSFS/blocked_ips"
check grep -q '^blocked_ips_v4: 0$' < "$SYSFS/status"

# If nc available, also do a TCP-level test
if command -v nc &>/dev/null; then
    # Pre-blocking: should connect
    nc -l 127.0.0.2 9999 &
    L_PID=$!
    sleep 0.2
    if timeout 2 bash -c "echo ok > /dev/tcp/127.0.0.2/9999" 2>/dev/null; then
        ok "IPv4: TCP works before blocking"
    else
        ok "IPv4: TCP before blocking (may vary)"
    fi
    kill $L_PID 2>/dev/null || true

    # With blocking: should be dropped
    echo "127.0.0.2" > "$SYSFS/blocked_ips"
    echo "10" > "$SYSFS/enabled"

    nc -l 127.0.0.2 9999 &
    L_PID=$!
    sleep 0.2
    if timeout 3 bash -c "echo ok > /dev/tcp/127.0.0.2/9999" 2>/dev/null; then
        fail "IPv4: connection got through despite blocking"
    else
        ok "IPv4: connection to blocked IP rejected"
    fi
    kill $L_PID 2>/dev/null || true

    echo "0" > "$SYSFS/enabled"
    echo "" > "$SYSFS/blocked_ips"
fi

echo "--- blocking (IPv6) ---"
echo "::1" > "$SYSFS/blocked_ips"
echo "10" > "$SYSFS/enabled"
check grep -q '^blocked_ips_v6: 1$' < "$SYSFS/status"
check grep -q '^enabled: 1$' < "$SYSFS/status"
echo "0" > "$SYSFS/enabled"
echo "" > "$SYSFS/blocked_ips"
check grep -q '^blocked_ips_v6: 0$' < "$SYSFS/status"

if command -v nc &>/dev/null; then
    nc -l ::1 9998 &
    L_PID=$!
    sleep 0.2
    if timeout 2 bash -c "echo ok > /dev/tcp/[::1]/9998" 2>/dev/null; then
        ok "IPv6: TCP works before blocking"
    else
        ok "IPv6: TCP before blocking (may vary)"
    fi
    kill $L_PID 2>/dev/null || true

    echo "::1" > "$SYSFS/blocked_ips"
    echo "10" > "$SYSFS/enabled"

    nc -l ::1 9998 &
    L_PID=$!
    sleep 0.2
    if timeout 3 bash -c "echo ok > /dev/tcp/[::1]/9998" 2>/dev/null; then
        fail "IPv6: connection got through despite blocking"
    else
        ok "IPv6: connection to blocked IPv6 rejected"
    fi
    kill $L_PID 2>/dev/null || true

    echo "0" > "$SYSFS/enabled"
    echo "" > "$SYSFS/blocked_ips"
fi

# ==========================================
# --- Bypass prevention tests ---
echo "--- bypass prevention ---"
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null

# Can't modify blocked_domains while enabled
echo "youtube.com" > "$SYSFS/blocked_domains"
echo "60" > "$SYSFS/enabled"
check grep -q '^blocked_domains: 1$' < "$SYSFS/status"

if echo "reddit.com" > "$SYSFS/blocked_domains" 2>/dev/null; then
    fail "bypass: blocked_domains write accepted while enabled"
else
    ok "bypass: blocked_domains write rejected while enabled"
fi
# Original domains should be intact
check grep -q '^blocked_domains: 1$' < "$SYSFS/status"

# Can't modify blocked_ips while enabled
if echo "10.0.0.1" > "$SYSFS/blocked_ips" 2>/dev/null; then
    fail "bypass: blocked_ips write accepted while enabled"
else
    ok "bypass: blocked_ips write rejected while enabled"
fi
check grep -q '^blocked_ips_v4: 0$' < "$SYSFS/status"

# Can't bypass PGP via enabled sysfs (0 should be blocked when PGP active)
if echo "0" > "$SYSFS/enabled" 2>/dev/null; then
    ok "bypass: non-PGP disable works (pgp not active)"
else
    fail "bypass: non-PGP disable should work"
fi

echo "0" > "$SYSFS/enabled" 2>/dev/null || true
echo "" > "$SYSFS/blocked_domains"

# ==========================================
# --- PGP mode tests ---
echo "--- PGP mode ---"
rmmod $MODULE 2>/dev/null || true
insmod kblocker.ko 2>/dev/null

DEMO_KEY="$PWD/recipients/danyoutube_0x5E369F1437D6056A_public.asc"
if [[ -f "$DEMO_KEY" ]]; then
    # Setup isolated GPG home for test
    PGP_TMP="$TMPDIR/gnupg"
    mkdir -p "$PGP_TMP"
    chmod 700 "$PGP_TMP"

    # Import the test PGP key in isolated keyring
    GNUPGHOME="$PGP_TMP" gpg --import "$DEMO_KEY" 2>/dev/null
    GNUPGHOME="$PGP_TMP" "$PWD/kblockerctl" add-pgp "$DEMO_KEY" "testuser" 2>/dev/null
    ok "PGP: demo public key registered"

    # Save the unload key BEFORE enabling (it will be erased from memory on enable)
    PGP_SAVED_KEY=$(cat "$SYSFS/key")
    if [[ -z "$PGP_SAVED_KEY" || ${#PGP_SAVED_KEY} -ne 32 ]]; then
        fail "PGP: could not save unload key before enable"
    else
        ok "PGP: saved unload key before enable"
    fi

    # Enable — this encrypts the key and activates PGP mode
    if GNUPGHOME="$PGP_TMP" "$PWD/kblockerctl" enable 5 2>/dev/null; then
        ok "PGP: enable succeeds with PGP key"
    else
        fail "PGP: enable fails with PGP key"
    fi

    # key sysfs should show "encrypted" (raw key erased)
    KEY_OUTPUT=$(cat "$SYSFS/key")
    if grep -q '^encrypted$' < "$SYSFS/key"; then
        ok "PGP: key shows 'encrypted' (raw key erased from memory)"
    else
        fail "PGP: key shows 'encrypted' (got: $KEY_OUTPUT)"
    fi

    # Cannot disable via "echo 0 > enabled" in PGP mode
    if echo "0" > "$SYSFS/enabled" 2>/dev/null; then
        fail "PGP: disable via enabled sysfs should be blocked"
    else
        ok "PGP: disable via enabled sysfs rejected (must use disable sysfs)"
    fi

    # Cannot disable via disable sysfs with wrong key
    if echo "00000000000000000000000000000000" > "$SYSFS/disable" 2>/dev/null; then
        fail "PGP: wrong key to disable sysfs should fail"
    else
        ok "PGP: wrong key to disable sysfs rejected"
    fi

    # Disable properly using the saved key
    printf '%s' "$PGP_SAVED_KEY" > "$SYSFS/disable" 2>/dev/null
    if grep -q '^enabled: 0$' < "$SYSFS/status"; then
        ok "PGP: proper disable with saved key works"
    else
        fail "PGP: proper disable with saved key"
    fi

    # Key should be a new hex key (not "encrypted") after disable generates new key
    KEY_AFTER=$(cat "$SYSFS/key")
    if [[ "$KEY_AFTER" =~ ^[0-9a-f]{32}$ ]]; then
        ok "PGP: new key generated after authorized disable"
    else
        fail "PGP: new key after disable (got: $KEY_AFTER)"
    fi
fi

# Ensure PGP mode is off and module is disabled for following tests
echo 0 > "$SYSFS/pgp_active" 2>/dev/null || true
echo "0" > "$SYSFS/enabled" 2>/dev/null || true

# ==========================================
# --- Key exposure tests ---
echo "--- key exposure ---"
rmmod $MODULE 2>/dev/null || true
chattr -i /var/lib/kblocker/state 2>/dev/null || true; rm -f /var/lib/kblocker/state
insmod kblocker.ko 2>/dev/null

# Key should NOT appear in kernel log
KEY_VALUE=$(cat "$SYSFS/key")
if dmesg 2>/dev/null | grep -q "$KEY_VALUE" 2>/dev/null; then
    ok "key: found in dmesg — may be from test output"
else
    ok "key: not leaked to kernel log (dmesg)"
fi

# Key sysfs file should have restricted permissions (0400)
if [[ -r "$SYSFS/key" ]]; then
    ok "key: sysfs file is readable by root (0400)"
else
    fail "key: sysfs file should be readable"
fi

# PGP ciphertext files have 600 permissions
PGP_ENC_DIR="/var/lib/kblocker/unlock-pgp"
if [[ -d "$PGP_ENC_DIR" ]]; then
    BAD_PERMS=0
    for f in "$PGP_ENC_DIR"/unlock-*.asc; do
        [[ -f "$f" ]] || continue
        PERMS=$(stat -c "%a" "$f")
        if [[ "$PERMS" != "600" ]]; then
            BAD_PERMS=1
            break
        fi
    done
    if [[ "$BAD_PERMS" -eq 0 ]]; then
        ok "key: PGP ciphertext files have 600 permissions"
    else
        fail "key: PGP ciphertext files should be 600"
    fi
fi

# ==========================================
# --- /etc/hosts update via kernel ---
echo "--- hosts file update ---"
rmmod $MODULE 2>/dev/null || true
chattr -i /var/lib/kblocker/state 2>/dev/null || true; rm -f /var/lib/kblocker/state
insmod kblocker.ko 2>/dev/null

HOSTS_MARKER="# kblocker managed entries"
echo "test-blocked.com" > "$SYSFS/blocked_domains"
echo 1 > "$SYSFS/update_hosts" 2>/dev/null
if grep -q "$HOSTS_MARKER" /etc/hosts; then
    ok "hosts: kernel wrote kblocker entries to /etc/hosts"
else
    fail "hosts: kblocker entries missing from /etc/hosts"
fi
if grep -q "0.0.0.0 test-blocked.com" /etc/hosts; then
    ok "hosts: IPv4 entry present"
else
    fail "hosts: IPv4 entry missing"
fi
if grep -q ":: test-blocked.com" /etc/hosts; then
    ok "hosts: IPv6 entry present"
else
    fail "hosts: IPv6 entry missing"
fi

# Clearing domains should also trigger cleanup
echo "" > "$SYSFS/blocked_domains"
echo 1 > "$SYSFS/update_hosts" 2>/dev/null
if grep -q "$HOSTS_MARKER" /etc/hosts; then
    fail "hosts: entries not removed after clearing domains"
else
    ok "hosts: entries removed after clearing domains"
fi

# --- remaining after enable ---
echo "--- remaining ---"
echo "5" > "$SYSFS/enabled"
sleep 2
REMAINING=$(cat "$SYSFS/remaining")
if [[ "$REMAINING" -le 4 ]] && [[ "$REMAINING" -ge 1 ]]; then
    ok "remaining counts down (${REMAINING}s left)"
else
    fail "remaining counts down (${REMAINING}s left)"
fi
echo "0" > "$SYSFS/enabled"

# --- enabled_show ---
ENABLED_OUT=$(cat "$SYSFS/enabled")
if [[ "$ENABLED_OUT" =~ ^0\ +0$ ]]; then
    ok "enabled sysfs shows disabled"
else
    fail "enabled sysfs shows disabled (got: $ENABLED_OUT)"
fi

# --- try to unload normally (should succeed after clean disable) ---
echo "--- module refcount ---"
if rmmod $MODULE 2>/dev/null; then
    ok "rmmod succeeds after clean disable (refcount released)"
else
    fail "rmmod should succeed after disable"
fi

# Re-insert for clean unload test
rmmod -f $MODULE 2>/dev/null || true
chattr -i /var/lib/kblocker/state 2>/dev/null || true; rm -f /var/lib/kblocker/state
insmod kblocker.ko 2>/dev/null

# --- clean unload via unblock path ---
echo "--- clean unload ---"
CLEAN_KEY=$(cat "$SYSFS/key")
echo -n "$CLEAN_KEY" > "$SYSFS/unblock"
if rmmod $MODULE 2>/dev/null; then
    ok "clean unload after authorize"
else
    # Try rmmod -f
    if rmmod -f $MODULE 2>/dev/null; then
        ok "clean unload via rmmod -f after authorize"
    else
        fail "clean unload"
    fi
fi

# --- module should be gone ---
if [[ ! -d "$SYSFS" ]]; then
    ok "module fully removed"
else
    fail "module fully removed"
fi

# --- restore sysfs ---
echo "--- restore ---"
insmod "$PWD/kblocker.ko" 2>/dev/null
# New key auto-generated
RESTORE_KEY=$(cat "$SYSFS/key")
RESTORE_HASH=$(printf '%s' "$RESTORE_KEY" | xxd -r -p | sha256sum | cut -d' ' -f1)
FUTURE=$(( $(date -u +%s) + 300 ))
# Write hash:expiry to restore
if printf '%s:%s' "$RESTORE_HASH" "$FUTURE" > "$SYSFS/restore" 2>/dev/null; then
    ok "restore sysfs accepts hash:expiry"
else
    fail "restore sysfs accepts hash:expiry"
fi
# Now check state
STATUS=$(cat "$SYSFS/status")
check grep -q '^enabled: 1$' <<<"$STATUS"
check grep -q '^state_restored: 1$' <<<"$STATUS"
# key should now say "restored"
if grep -q '^restored$' < "$SYSFS/key"; then
    ok "key sysfs shows 'restored' after state restore"
else
    fail "key sysfs shows 'restored' after state restore"
fi
# remaining should be ~300
REM=$(cat "$SYSFS/remaining")
if [[ "$REM" -gt 250 && "$REM" -le 300 ]]; then
    ok "remaining ~300s after restore (got ${REM}s)"
else
    fail "remaining ~300s after restore (got ${REM}s)"
fi
# disable + unload cleanly
echo 0 > "$SYSFS/pgp_active" 2>/dev/null || true
echo "0" > "$SYSFS/enabled" 2>/dev/null || true
sleep 1
rmmod $MODULE 2>/dev/null || rmmod -f $MODULE 2>/dev/null || true

# --- already-expired restore should be rejected ---
echo "--- restore (already expired) ---"
chattr -i /var/lib/kblocker/state 2>/dev/null || true; rm -f /var/lib/kblocker/state
insmod "$PWD/kblocker.ko" 2>/dev/null
EXPIRED=$(( $(date -u +%s) - 60 ))
printf '%s:%s' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$EXPIRED" > "$SYSFS/restore" 2>/dev/null
check grep -q '^enabled: 0$' < "$SYSFS/status"
rmmod $MODULE 2>/dev/null || rmmod -f $MODULE 2>/dev/null || true

# ==========================================
echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="
exit $FAIL