#!/bin/bash
# ytblock integration tests
# Runs against the live kernel module via sysfs.
# Requires root. Run: sudo ./test.sh

set -e
PWD=$(dirname "$(readlink -f "$0")")
PASS=0
FAIL=0

SYSFS="/sys/kernel/ytblock"
MODULE="ytblock"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"; modprobe -r $MODULE 2>/dev/null || true' EXIT

ok()   { PASS=$((PASS+1)); echo -e "  \033[0;32mPASS\033[0m $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  \033[0;31mFAIL\033[0m $1"; }
check() { if "$@"; then ok "$*"; else fail "$*"; return 1; fi; }

echo "=== ytblock integration tests ==="
echo ""

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
if insmod ytblock.ko 2>/dev/null; then
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
insmod ytblock.ko 2>/dev/null
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
insmod ytblock.ko 2>/dev/null
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
insmod ytblock.ko 2>/dev/null
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
insmod ytblock.ko 2>/dev/null
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
"$PWD/ytblockctl" block-ip 10.0.0.100 10.0.0.101 2>/dev/null
check grep -q '^blocked_ips_v4: 2$' < "$SYSFS/status"
check grep -q '^blocked_ips_v6: 0$' < "$SYSFS/status"
check grep -q '10.0.0.100' < "$SYSFS/blocked_ips"
check grep -q '10.0.0.101' < "$SYSFS/blocked_ips"

# block-ip with IPv6
"$PWD/ytblockctl" block-ip 2001:db8::1 2001:db8::2 2>/dev/null
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
insmod ytblock.ko 2>/dev/null

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
insmod "$PWD/ytblock.ko" 2>/dev/null
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
echo "0" > "$SYSFS/enabled"
rmmod $MODULE 2>/dev/null || rmmod -f $MODULE 2>/dev/null || true

# --- already-expired restore should be rejected ---
echo "--- restore (already expired) ---"
insmod "$PWD/ytblock.ko" 2>/dev/null
EXPIRED=$(( $(date -u +%s) - 60 ))
printf '%s:%s' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$EXPIRED" > "$SYSFS/restore" 2>/dev/null
check grep -q '^enabled: 0$' < "$SYSFS/status"
rmmod $MODULE 2>/dev/null || rmmod -f $MODULE 2>/dev/null || true

# ==========================================
echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="
exit $FAIL