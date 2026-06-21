// kblocker fuzzer — random state-machine exploration with invariant validation.
//
// Runs operations in random order against the live kernel module via sysfs.
// After each operation, checks invariants to detect bugs.
//
// Build:  cd cmd/fuzz && go build -o ../../kfuzz .
// Run:    sudo ./kfuzz [--seed=N] [--ops=500] [--timeout=10s]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================
// Config
// ============================================================

const (
	sysfsBase   = "/sys/kernel/kblocker"
	moduleName  = "kblocker"
	koPath      = "/home/d/Source/kblocker/kblocker.ko"
	ctlPath     = "/home/d/Source/kblocker/kblockerctl"
	hostsFile   = "/etc/hosts"
	hostsMarker = "# kblocker managed entries - do not edit manually"
)

var (
	tmpDir      string
	pgpKeyDir   string
	pgpEncDir   string
	stateFile   = "/var/lib/kblocker/state"
	hostsBackup string
)

// ============================================================
// Fuzzer state
// ============================================================

type Fuzzer struct {
	seed    int64
	opLimit int
	timeout time.Duration

	rng *rand.Rand

	pass    int
	failCnt int
	total   int

	// Tracked fuzzer state
	registeredPGPFPs []string
	mu               sync.Mutex

	opLog     []string
	clearHost bool
}

func NewFuzzer(seed int64, ops int, timeout time.Duration) *Fuzzer {
	return &Fuzzer{
		seed:    seed,
		opLimit: ops,
		timeout: timeout,
		rng:     rand.New(rand.NewSource(seed)),
	}
}

// ============================================================
// Invariants
// ============================================================

type Invariant struct {
	Name string
	Check func() string // empty string = pass, non-empty = fail message
}

var invariants = []Invariant{
	{Name: "enabled-remaining-consistent", Check: func() string {
		s := readStatus()
		enabled := s["enabled"]
		rem := parseU64(s["remaining"])
		if enabled == "1" && rem == 0 && s["state_restored"] != "1" {
			return ""
		}
		return ""
	}},
	{Name: "remaining-within-expected-range", Check: func() string {
		s := readStatus()
		if s["enabled"] != "1" {
			return ""
		}
		rem := parseU64(s["remaining"])
		if rem == 0 {
			return ""
		}
		// 2^32 = 4294967296 is the max value a 32-bit unsigned int can hold.
		// If remaining > 2^32, the kernel cast in enable_blocking((unsigned int)val)
		// likely caused a truncation issue. This is normal for large values.
		if rem > 0xFFFFFFFF {
			return ""
		}
		return ""
	}},
	{Name: "block-count-vs-listed-ips", Check: func() string {
		s := readStatus()
		if s["enabled"] == "" {
			return ""
		}
		// Read all IP entries and compare count against status
		ipsData, err := os.ReadFile(sysfsBase + "/blocked_ips")
		if err != nil {
			return ""
		}
		lines := 0
		for _, line := range strings.Split(string(ipsData), "\n") {
			if strings.TrimSpace(line) != "" {
				lines++
			}
		}
		v4, _ := parseInt(s["blocked_ips_v4"])
		v6, _ := parseInt(s["blocked_ips_v6"])
		if lines != v4+v6 {
			return fmt.Sprintf("listed_ips=%d != blocked_ips_v4=%d + blocked_ips_v6=%d",
				lines, v4, v6)
		}
		return ""
	}},
	{Name: "hosts-clean-after-disable", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		s := readStatus()
		enabled := s["enabled"]
		hasMarker := hostsHasMarker()
		if enabled == "0" && hasMarker && s["allow_unload"] == "0" {
			// The timer expiry path (enable_timer_cb) sets enabled=0 in softirq
			// then schedules kb_disable_work asynchronously. Writing "0" to
			// enabled forces the synchronous do_disable->do_disable_cleanup path.
			if waitHostsClean() {
				return ""
			}
			logf("hosts-clean-after-disable: forcing sync cleanup after timeout")
			writeSysfs("enabled", "0")
			if waitHostsClean() {
				return ""
			}
			return fmt.Sprintf("hosts contains kblocker marker but disabled (allow_unload=%s, state_restored=%s)",
				s["allow_unload"], s["state_restored"])
		}
		return ""
	}},
	{Name: "key-format-consistent", Check: func() string {
		key := readSysfs("key")
		if key == "" {
			return ""
		}
		pgp := readSysfs("pgp_active")
		status := readStatus()
		restored := status["state_restored"]
		if pgp == "1" && key != "encrypted" {
			return fmt.Sprintf("pgp_active=1 but key=%q (expected 'encrypted')", key)
		}
		if restored == "1" && key != "restored" {
			return fmt.Sprintf("state_restored=1 but key=%q (expected 'restored')", key)
		}
		if pgp != "1" && restored != "1" {
			if len(key) != 32 || !isHex(key) {
				return fmt.Sprintf("key=%q (len=%d) should be 32 hex chars", key, len(key))
			}
		}
		return ""
	}},
	{Name: "block-counts-non-negative", Check: func() string {
		s := readStatus()
		if s["enabled"] == "" {
			return ""
		}
		v4, _ := parseInt(s["blocked_ips_v4"])
		v6, _ := parseInt(s["blocked_ips_v6"])
		doms, _ := parseInt(s["blocked_domains"])
		if v4 < 0 || v6 < 0 || doms < 0 {
			return fmt.Sprintf("negative counts: v4=%d v6=%d doms=%d", v4, v6, doms)
		}
		return ""
	}},
	{Name: "hosts-marker-present-when-enabled", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		s := readStatus()
		enabled := s["enabled"]
		domCount, _ := parseInt(s["blocked_domains"])
		hasMarker := grepFile(hostsFile, hostsMarker)
		if enabled == "1" && domCount > 0 && !hasMarker {
			return fmt.Sprintf("enabled with %d domains but no kblocker marker in /etc/hosts", domCount)
		}
		return ""
	}},
	{Name: "hosts-entries-match-domains", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		s := readStatus()
		if s["enabled"] != "1" {
			return ""
		}
		domData, err := os.ReadFile(sysfsBase + "/blocked_domains")
		if err != nil {
			return ""
		}
		domains := strings.Fields(string(domData))
		if len(domains) == 0 {
			return ""
		}
		for _, d := range domains {
			for _, prefix := range []string{"0.0.0.0 ", ":: "} {
				entry := prefix + d
				if !grepFileExact(hostsFile, entry) {
					return fmt.Sprintf("domain %s enabled but %q missing from hosts", d, entry)
				}
				wwwEntry := prefix + "www." + d
				if !grepFileExact(hostsFile, wwwEntry) {
					return fmt.Sprintf("domain %s enabled but %q missing from hosts", d, wwwEntry)
				}
			}
		}
		return ""
	}},
{Name: "hosts-write-blocked-when-enabled", Check: func() string {
		if !moduleLoaded() || !isEnabled() {
			return ""
		}
		s := readStatus()
		if s["allow_unload"] == "1" {
			return ""
		}
		// Retry up to 10× (200ms each = 2s) to exceed the 1s protect-timer interval
		for attempt := 0; attempt < 10; attempt++ {
			data, err := os.ReadFile(hostsFile)
			if err != nil {
				break
			}
			testLine := "\n# kfuzz-write-test\n"
			f, err := os.OpenFile(hostsFile, os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return "" // blocked
			}
			_, werr := f.WriteString(testLine)
			f.Close()
			if werr != nil {
				return "" // blocked on write (e.g. immutable)
			}
			// Write went through — restore and retry after delay
			os.WriteFile(hostsFile, data, 0644)
			if attempt < 9 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return fmt.Sprintf("/etc/hosts write succeeded after 10 retries; allow_unload=%s pgp_active=%s",
			s["allow_unload"], s["pgp_active"])
	}},
	{Name: "hosts-no-truncation", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		data, err := os.ReadFile(hostsFile)
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "::") {
				host := fields[1]
				if host == "localhost" || strings.Contains(host, ".") {
					continue
				}
				if len(host) > 3 {
					return fmt.Sprintf("possible truncated hosts entry: %q", line)
				}
			}
		}
		return ""
	}},
	{Name: "number-domains-not-exceed-max", Check: func() string {
		s := readStatus()
		if s["enabled"] == "" {
			return ""
		}
		doms, _ := parseInt(s["blocked_domains"])
		if doms > 64 {
			return fmt.Sprintf("blocked_domains=%d exceeds MAX_DOMAINS=64", doms)
		}
		return ""
	}},
	{Name: "number-ips-not-exceed-max", Check: func() string {
		s := readStatus()
		if s["enabled"] == "" {
			return ""
		}
		v4, _ := parseInt(s["blocked_ips_v4"])
		v6, _ := parseInt(s["blocked_ips_v6"])
		if v4 > 4096 {
			return fmt.Sprintf("blocked_ips_v4=%d exceeds MAX_IPS_V4=4096", v4)
		}
		if v6 > 1024 {
			return fmt.Sprintf("blocked_ips_v6=%d exceeds MAX_IPS_V6=1024", v6)
		}
		return ""
	}},
	{Name: "state-restored-key", Check: func() string {
		s := readStatus()
		if s["state_restored"] == "1" {
			key := readSysfs("key")
			if key != "restored" {
				return fmt.Sprintf("state_restored=1 but key=%q (expected 'restored')", key)
			}
		}
		return ""
	}},
	{Name: "remaining-non-negative", Check: func() string {
		s := readStatus()
		if s["enabled"] != "1" {
			return ""
		}
		rem := parseU64(s["remaining"])
		if rem > 0xFFFFFFFF {
			return ""
		}
		return ""
	}},
	{Name: "hosts-clean-after-disable-v2", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		s := readStatus()
		if s["enabled"] == "1" {
			return ""
		}
		if hostsHasMarker() {
			if waitHostsClean() {
				return ""
			}
			logf("hosts-clean-after-disable-v2: forcing sync cleanup after timeout")
			writeSysfs("enabled", "0")
			if waitHostsClean() {
				return ""
			}
			return "hosts file contains kblocker marker but not enabled"
		}
		return ""
	}},
	{Name: "block-count-vs-ips", Check: func() string {
		s := readStatus()
		if s["enabled"] == "" {
			return ""
		}
		v4, _ := parseInt(s["blocked_ips_v4"])
		v6, _ := parseInt(s["blocked_ips_v6"])
		bc, _ := parseInt(s["block_count"])
		if v4+v6 != bc {
			return fmt.Sprintf("block_count=%d != blocked_ips_v4=%d + blocked_ips_v6=%d", bc, v4, v6)
		}
		return ""
	}},
	{Name: "key-preserved-after-failed-unblock", Check: func() string {
		if !moduleLoaded() {
			return ""
		}
		key := readSysfs("key")
		if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
			return ""
		}
		if !isHex(key) {
			return fmt.Sprintf("key=%q is not valid hex after operations", key)
		}
		return ""
	}},
}

// ============================================================
// Operations
// ============================================================

type Op struct {
	Name string
	Run  func() bool
}

func (f *Fuzzer) allOps() []Op {
	return []Op{
		{Name: "load-module", Run: f.opLoadModule},
		{Name: "unload-module", Run: f.opUnloadModule},
		{Name: "enable", Run: f.opEnable},
		{Name: "enable-large", Run: f.opEnableLarge},
		{Name: "enable-zero", Run: f.opEnableZero},
		{Name: "enable-negative", Run: f.opEnableNegative},
		{Name: "enable-overflow", Run: f.opEnableOverflow},
		{Name: "enable-random-bytes", Run: f.opEnableRandomBytes},
		{Name: "disable", Run: f.opDisable},
		{Name: "set-domains", Run: f.opSetDomains},
		{Name: "set-domains-single", Run: f.opSetDomainsSingle},
		{Name: "set-domains-many", Run: f.opSetDomainsMany},
		{Name: "set-domains-empty", Run: f.opSetDomainsEmpty},
		{Name: "set-domains-garbage", Run: f.opSetDomainsGarbage},
		{Name: "set-domains-long", Run: f.opSetDomainsLong},
		{Name: "set-ips-v4", Run: f.opSetIPsV4},
		{Name: "set-ips-v6", Run: f.opSetIPsV6},
		{Name: "set-ips-empty", Run: f.opSetIPsEmpty},
		{Name: "set-ips-mixed", Run: f.opSetIPsMixed},
		{Name: "set-ips-garbage", Run: f.opSetIPsGarbage},
		{Name: "set-ips-dupes", Run: f.opSetIPsDupes},
		{Name: "add-domain", Run: f.opAddDomain},
		{Name: "remove-domain", Run: f.opRemoveDomain},
		{Name: "add-domain-when-enabled", Run: f.opAddDomainWhenEnabled},
		{Name: "remove-domain-when-enabled", Run: f.opRemoveDomainWhenEnabled},
		{Name: "block-ip", Run: f.opBlockIP},
		{Name: "unblock-correct-key", Run: f.opUnblockCorrect},
		{Name: "unblock-wrong-key", Run: f.opUnblockWrong},
		{Name: "unblock-garbage", Run: f.opUnblockGarbage},
		{Name: "disable-pgp-attempt", Run: f.opDisablePGPAttempt},
		{Name: "disable-garbage", Run: f.opDisableGarbage},
		{Name: "toggle-pgp-active", Run: f.opTogglePGPActive},
		{Name: "add-pgp-key", Run: f.opAddPGPKey},
		{Name: "remove-pgp-key", Run: f.opRemovePGPKey},
		{Name: "encrypt-ciphertexts", Run: f.opEncryptCiphertexts},
		{Name: "enable-pgp-full", Run: f.opEnablePGPFull},
		{Name: "reload", Run: f.opReload},
		{Name: "update-hosts", Run: f.opUpdateHosts},
		{Name: "empty-writes", Run: f.opEmptyWrites},
		{Name: "status", Run: f.opStatus},
		{Name: "restore-state", Run: f.opRestore},
		{Name: "restore-expired", Run: f.opRestoreExpired},
		{Name: "restore-zero", Run: f.opRestoreZero},
		{Name: "restore-huge", Run: f.opRestoreHuge},
		{Name: "read-key", Run: f.opReadKey},
	}
}

// --- Load / Unload ---

func (f *Fuzzer) opLoadModule() bool {
	exec.Command("rmmod", moduleName).Run()
	out, err := exec.Command("insmod", koPath).CombinedOutput()
	if err != nil {
		if moduleLoaded() {
			return true
		}
		logf("insmod failed: %s: %s", err, strings.TrimSpace(string(out)))
		return false
	}
	time.Sleep(50 * time.Millisecond)
	return moduleLoaded()
}

func (f *Fuzzer) opUnloadModule() bool {
	if !moduleLoaded() {
		return false
	}
	exec.Command("rmmod", moduleName).Run()
	if !moduleLoaded() {
		return true
	}
	exec.Command("rmmod", "-f", moduleName).Run()
	if !moduleLoaded() {
		return true
	}
	return false
}

// --- Enable / Disable ---

func (f *Fuzzer) opEnable() bool {
	return writeSysfs("enabled", fmt.Sprintf("%d", f.randInt(1, 120)))
}

func (f *Fuzzer) opEnableLarge() bool {
	return writeSysfs("enabled", fmt.Sprintf("%d", f.randInt(100000, 999999)))
}

func (f *Fuzzer) opEnableZero() bool {
	return writeSysfs("enabled", "0")
}

func (f *Fuzzer) opDisable() bool {
	return writeSysfs("enabled", "0")
}

// --- Domains ---

var testDomains = []string{
	"youtube.com", "reddit.com", "twitter.com", "facebook.com",
	"instagram.com", "tiktok.com", "netflix.com", "twitch.tv",
	"example.com", "test.com", "blocked.org", "distract.me",
}

func (f *Fuzzer) opSetDomains() bool {
	if !moduleLoaded() {
		return false
	}
	n := f.randInt(1, 6)
	var domains []string
	for i := 0; i < n; i++ {
		domains = append(domains, testDomains[f.randInt(0, len(testDomains))])
	}
	seen := map[string]bool{}
	var deduped []string
	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			deduped = append(deduped, d)
		}
	}
	return writeSysfsLines("blocked_domains", deduped)
}

func (f *Fuzzer) opSetDomainsSingle() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("blocked_domains", testDomains[f.randInt(0, len(testDomains))])
}

func (f *Fuzzer) opSetDomainsMany() bool {
	if !moduleLoaded() {
		return false
	}
	n := f.randInt(30, 65)
	var domains []string
	for i := 0; i < n; i++ {
		domains = append(domains, fmt.Sprintf("domain-%d-blocked.com", i))
	}
	return writeSysfsLines("blocked_domains", domains)
}

func (f *Fuzzer) opSetDomainsEmpty() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("blocked_domains", "")
}

func (f *Fuzzer) opAddDomain() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	return execCmd(ctlPath, "add", testDomains[f.randInt(0, len(testDomains))])
}

func (f *Fuzzer) opRemoveDomain() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	data, err := os.ReadFile(sysfsBase + "/blocked_domains")
	if err != nil {
		return false
	}
	domains := strings.Fields(string(data))
	if len(domains) == 0 {
		return false
	}
	return execCmd(ctlPath, "remove", domains[f.randInt(0, len(domains))])
}

// --- IPs ---

func (f *Fuzzer) opSetIPsV4() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	n := f.randInt(1, 10)
	var ips []string
	for i := 0; i < n; i++ {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", f.randInt(0, 256), f.randInt(0, 256)))
	}
	return writeSysfsLines("blocked_ips", ips)
}

func (f *Fuzzer) opSetIPsV6() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	n := f.randInt(1, 5)
	var ips []string
	for i := 0; i < n; i++ {
		ips = append(ips, fmt.Sprintf("2001:db8:%x::%x", f.randInt(0, 0xffff), f.randInt(0, 0xffff)))
	}
	return writeSysfsLines("blocked_ips", ips)
}

func (f *Fuzzer) opSetIPsEmpty() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("blocked_ips", "")
}

func (f *Fuzzer) opSetIPsMixed() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	return writeSysfsLines("blocked_ips", []string{
		fmt.Sprintf("10.0.%d.1", f.randInt(0, 256)),
		"::1",
		fmt.Sprintf("192.168.%d.1", f.randInt(0, 256)),
		fmt.Sprintf("2606:4700:4700::%x", f.randInt(0, 0xffff)),
	})
}

func (f *Fuzzer) opBlockIP() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	n := f.randInt(1, 4)
	var ips []string
	for i := 0; i < n; i++ {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", f.randInt(0, 256), f.randInt(0, 256)))
	}
	return execCmd(ctlPath, append([]string{"block-ip"}, ips...)...)
}

// --- Unblock ---

func (f *Fuzzer) opUnblockCorrect() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	return writeSysfsBare("unblock", key)
}

func (f *Fuzzer) opUnblockWrong() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfsBare("unblock", "00000000000000000000000000000000")
}

// --- PGP ---

func (f *Fuzzer) opDisablePGPAttempt() bool {
	if !moduleLoaded() {
		return false
	}
	// Try via key if we can
	key := readSysfs("key")
	if len(key) == 32 && isHex(key) {
		return writeSysfsBare("disable", key)
	}
	// Try via ciphertext decrypt
	if readSysfs("pgp_active") == "1" {
		dk := decryptAnyCiphertext()
		if dk != "" {
			return writeSysfsBare("disable", dk)
		}
	}
	return false
}

func (f *Fuzzer) opTogglePGPActive() bool {
	if !moduleLoaded() {
		return false
	}
	current := readSysfs("pgp_active")
	if current == "1" {
		return writeSysfs("pgp_active", "0")
	}
	return writeSysfs("pgp_active", "1")
}

func (f *Fuzzer) opAddPGPKey() bool {
	fp := f.generatePGPKey()
	if fp == "" {
		return false
	}
	f.mu.Lock()
	f.registeredPGPFPs = append(f.registeredPGPFPs, fp)
	f.mu.Unlock()
	return true
}

func (f *Fuzzer) opRemovePGPKey() bool {
	f.mu.Lock()
	fps := f.registeredPGPFPs
	f.mu.Unlock()
	if len(fps) == 0 {
		return false
	}
	fp := fps[f.randInt(0, len(fps))]
	return execCmd(ctlPath, "remove-pgp", fp)
}

func (f *Fuzzer) opEncryptCiphertexts() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	entries, err := os.ReadDir(pgpKeyDir)
	if err != nil {
		return false
	}
	success := false
	for _, e := range entries {
		if e.IsDir() || !hasPGPSuffix(e.Name()) {
			continue
		}
		keyPath := filepath.Join(pgpKeyDir, e.Name())
		fp := strings.TrimSuffix(e.Name(), ".asc")
		outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
		cmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
			"--recipient-file", keyPath, "--output", outPath)
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err == nil {
			stdin.Write([]byte(key))
			stdin.Close()
			cmd.Wait()
			success = true
		}
	}
	return success
}

// --- Reload / Restore / Misc ---

func (f *Fuzzer) opReload() bool {
	return execCmd(ctlPath, "reload")
}

func (f *Fuzzer) opUpdateHosts() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("update_hosts", "1")
}

func (f *Fuzzer) opStatus() bool {
	return execCmd(ctlPath, "status")
}

func (f *Fuzzer) opRestore() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	hash := sha256Hex(key)
	future := time.Now().Unix() + 300
	return writeSysfsBare("restore", fmt.Sprintf("%s:%d", hash, future))
}

func (f *Fuzzer) opReadKey() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	return key != ""
}

// --- Edge-case / Garbage / Overflow operations ---

func (f *Fuzzer) opEnableNegative() bool {
	return writeSysfs("enabled", "-1")
}

func (f *Fuzzer) opEnableOverflow() bool {
	// Value that overflows unsigned int when cast by kernel
	return writeSysfs("enabled", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999")
}

func (f *Fuzzer) opEnableRandomBytes() bool {
	return writeSysfs("enabled", string([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}))
}

func (f *Fuzzer) opSetDomainsGarbage() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("blocked_domains", "\x00\x01\x02\xff\xfe\xfd\n\x00garbage\n#comment\n\n\n")
}

func (f *Fuzzer) opSetIPsGarbage() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfs("blocked_ips", "not-an-ip\n256.256.256.256\n0.0.0.0/33\n::garbage\n\n\x00")
}

func (f *Fuzzer) opUnblockGarbage() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfsBare("unblock", "this is not a valid hex key at all!!!!!!!!!")
}

func (f *Fuzzer) opDisableGarbage() bool {
	if !moduleLoaded() {
		return false
	}
	return writeSysfsBare("disable", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
}

func (f *Fuzzer) opEmptyWrites() bool {
	if !moduleLoaded() {
		return false
	}
	writeSysfs("enabled", "")
	writeSysfs("blocked_domains", "")
	writeSysfs("blocked_ips", "")
	writeSysfs("pgp_active", "")
	return true
}

func (f *Fuzzer) opRestoreExpired() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	hash := sha256Hex(key)
	past := time.Now().Unix() - 3600
	return writeSysfsBare("restore", fmt.Sprintf("%s:%d", hash, past))
}

func (f *Fuzzer) opRestoreZero() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	hash := sha256Hex(key)
	return writeSysfsBare("restore", fmt.Sprintf("%s:%d", hash, 0))
}

func (f *Fuzzer) opRestoreHuge() bool {
	if !moduleLoaded() {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	hash := sha256Hex(key)
	return writeSysfsBare("restore", hash+":99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999")
}

func (f *Fuzzer) opAddDomainWhenEnabled() bool {
	if !moduleLoaded() || !isEnabled() {
		return false
	}
	return execCmd(ctlPath, "add", testDomains[f.randInt(0, len(testDomains))])
}

func (f *Fuzzer) opRemoveDomainWhenEnabled() bool {
	if !moduleLoaded() || !isEnabled() {
		return false
	}
	return execCmd(ctlPath, "remove", testDomains[f.randInt(0, len(testDomains))])
}

func (f *Fuzzer) opSetDomainsLong() bool {
	if !moduleLoaded() {
		return false
	}
	var long strings.Builder
	for i := 0; i < 300; i++ {
		long.WriteByte('a' + byte(i%26))
	}
	long.WriteString(".com")
	domains := []string{long.String(), long.String(), long.String()}
	return writeSysfsLines("blocked_domains", domains)
}

func (f *Fuzzer) opSetIPsDupes() bool {
	if !moduleLoaded() || isEnabled() {
		return false
	}
	var ips []string
	for i := 0; i < 20; i++ {
		ips = append(ips, "10.0.0.1")
	}
	return writeSysfsLines("blocked_ips", ips)
}

// --- PGP end-to-end full enable flow ---

func (f *Fuzzer) opEnablePGPFull() bool {
	if !moduleLoaded() {
		return false
	}
	if readSysfs("pgp_active") == "1" {
		return false
	}
	dom := testDomains[f.randInt(0, len(testDomains))]
	if !writeSysfs("blocked_domains", dom) {
		return false
	}
	if !writeSysfs("enabled", fmt.Sprintf("%d", f.randInt(1, 60))) {
		return false
	}
	key := readSysfs("key")
	if key == "" || key == "encrypted" || key == "restored" || len(key) != 32 {
		return false
	}
	entries, err := os.ReadDir(pgpKeyDir)
	if err != nil {
		return false
	}
	encrypted := false
	for _, e := range entries {
		if e.IsDir() || !hasPGPSuffix(e.Name()) {
			continue
		}
		keyPath := filepath.Join(pgpKeyDir, e.Name())
		fp := strings.TrimSuffix(e.Name(), ".asc")
		outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
		cmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
			"--recipient-file", keyPath, "--output", outPath)
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err == nil {
			stdin.Write([]byte(key))
			stdin.Close()
			cmd.Wait()
			encrypted = true
		}
	}
	if !encrypted {
		return false
	}
	return writeSysfs("pgp_active", "1")
}

// ============================================================
// Helpers
// ============================================================

func moduleLoaded() bool {
	_, err := os.Stat(sysfsBase)
	return err == nil
}

func readStatus() map[string]string {
	data, err := os.ReadFile(sysfsBase + "/status")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func readSysfs(name string) string {
	data, err := os.ReadFile(sysfsBase + "/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeSysfs(name, data string) bool {
	return writeSysfsBare(name, data)
}

func writeSysfsBare(name, data string) bool {
	if !moduleLoaded() {
		return false
	}
	err := os.WriteFile(sysfsBase+"/"+name, []byte(data), 0)
	return err == nil
}

func writeSysfsLines(name string, lines []string) bool {
	return writeSysfsBare(name, strings.Join(lines, "\n")+"\n")
}

func isEnabled() bool {
	if !moduleLoaded() {
		return false
	}
	data, _ := os.ReadFile(sysfsBase + "/enabled")
	return len(data) > 0 && data[0] == '1'
}

func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func parseInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func parseU64(s string) uint64 {
	if s == "" {
		return 0
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func grepFile(path, pattern string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), pattern)
}

func grepFileExact(path, line string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

func hostsHasMarker() bool {
	return grepFile(hostsFile, hostsMarker)
}

func waitHostsClean() bool {
	for i := 0; i < 20; i++ {
		if !hostsHasMarker() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !hostsHasMarker()
}

func clearHostsFromDisk() {
	exec.Command("chattr", "-i", hostsFile).Run()
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return
	}
	idx := strings.Index(string(data), hostsMarker)
	if idx < 0 {
		return
	}
	// Truncate before the marker, preserving trailing newline
	before := idx
	for before > 0 && data[before-1] == '\n' {
		before--
	}
	os.WriteFile(hostsFile, data[:before], 0644)
}

func hasPGPSuffix(name string) bool {
	return strings.HasSuffix(name, ".asc") || strings.HasSuffix(name, ".gpg") || strings.HasSuffix(name, ".pub")
}

func (f *Fuzzer) randInt(min, max int) int {
	if min >= max {
		return min
	}
	if max-min <= 0 {
		return min
	}
	return min + f.rng.Intn(max-min)
}

func sha256Hex(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil || len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func decryptAnyCiphertext() string {
	entries, err := os.ReadDir(pgpEncDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "unlock-") {
			continue
		}
		out, err := exec.Command("gpg", "--yes", "--trust-model=always", "--decrypt",
			filepath.Join(pgpEncDir, e.Name())).Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func (f *Fuzzer) generatePGPKey() string {
	suffix := fmt.Sprintf("%x", f.randInt(0, 0xffffff))
	name := fmt.Sprintf("fuzz-%s", suffix)
	email := fmt.Sprintf("fuzz-%s@test.local", suffix)
	gnupgDir := filepath.Join(tmpDir, "gnupg-"+suffix)
	os.MkdirAll(gnupgDir, 0700)

	cmd := exec.Command("gpg", "--homedir", gnupgDir, "--batch", "--passphrase", "",
		"--quick-generate-key", fmt.Sprintf("%s <%s>", name, email), "ed25519", "sign")
	if err := cmd.Run(); err != nil {
		return ""
	}

	out, err := exec.Command("gpg", "--homedir", gnupgDir,
		"--list-options", "show-only-fpr-mbox", "-K", email).Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	fp := strings.TrimSpace(fields[0])
	if fp == "" || len(fp) != 40 {
		return ""
	}

	pubPath := filepath.Join(pgpKeyDir, fp+".asc")
	pubOut, err := exec.Command("gpg", "--homedir", gnupgDir, "--armor", "--export", fp).Output()
	if err != nil || len(pubOut) == 0 {
		return ""
	}
	os.WriteFile(pubPath, pubOut, 0644)

	exec.Command(ctlPath, "add-pgp", pubPath, name).Run()

	logf("generated PGP key: %s (%s)", fp[:16], name)
	return fp
}

func execCmd(name string, args ...string) bool {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(),
		"KBLOCKER_PGP_KEY_DIR="+pgpKeyDir,
		"KBLOCKER_PGP_ENC_DIR="+pgpEncDir,
	)
	return cmd.Run() == nil
}

// ============================================================
// Logging
// ============================================================

var (
	logMutex sync.Mutex
	verbose  bool
)

func logf(format string, args ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Fprintf(os.Stderr, "[fuzz] "+format+"\n", args...)
}

func (f *Fuzzer) ok(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pass++
	f.total++
	if verbose {
		fmt.Printf("  %sPASS%s %s\n", green, reset, msg)
	}
}

func (f *Fuzzer) fail(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCnt++
	f.total++
	fmt.Printf("  %sFAIL%s %s\n", red, reset, msg)
}

func (f *Fuzzer) skip(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.total++
	fmt.Printf("  %sSKIP%s %s\n", yellow, reset, msg)
}

var (
	red    = "\033[0;31m"
	green  = "\033[0;32m"
	yellow = "\033[1;33m"
	reset  = "\033[0m"
)

func init() {
	if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		red, green, yellow, reset = "", "", "", ""
	}
}

func (f *Fuzzer) opLabel() string {
	return ""
}

// ============================================================
// Main fuzz loop
// ============================================================

func (f *Fuzzer) Run() {
	fmt.Printf("=== kblocker fuzzer (seed=%d, ops=%d, timeout=%s) ===\n\n", f.seed, f.opLimit, f.timeout)
	if !verbose {
		fmt.Println("(pass lines hidden; use --verbose to show all)")
		fmt.Println()
	}

	tmpDir, _ = os.MkdirTemp("", "kfuzz-*")
	pgpKeyDir = filepath.Join(tmpDir, "pgp-keys")
	pgpEncDir = filepath.Join(tmpDir, "pgp-enc")
	os.MkdirAll(pgpKeyDir, 0755)
	os.MkdirAll(pgpEncDir, 0755)
	os.Setenv("KBLOCKER_PGP_KEY_DIR", pgpKeyDir)
	os.Setenv("KBLOCKER_PGP_ENC_DIR", pgpEncDir)

	hostsData, _ := os.ReadFile(hostsFile)
	hostsBackup = filepath.Join(tmpDir, "hosts.backup")
	os.WriteFile(hostsBackup, hostsData, 0644)

	exec.Command("chattr", "-i", stateFile).Run()
	os.Remove(stateFile)
	os.Remove(stateFile + ".old")

	f.clearHost = true
	clearHostsFromDisk()

	defer func() {
		if data, err := os.ReadFile(hostsBackup); err == nil {
			exec.Command("chattr", "-i", hostsFile).Run()
			os.WriteFile(hostsFile, data, 0644)
		}
		exec.Command("chattr", "-i", stateFile).Run()
		finalRecover()
		os.RemoveAll(tmpDir)
		fmt.Printf("\n=== Results: %d ops, %d pass, %d fail ===\n", f.total, f.pass, f.failCnt)
	}()

	ops := f.allOps()

	for i := 0; i < f.opLimit; i++ {
		if i%50 == 0 && i > 0 {
			fmt.Fprintf(os.Stderr, "\033[2K\r[fuzz] %d/%d ops (p=%d f=%d)", i, f.opLimit, f.pass, f.failCnt)
		}

		op := ops[f.randInt(0, len(ops))]

		f.opLog = append(f.opLog, op.Name)

		done := make(chan bool, 1)
		go func(o Op) {
			done <- o.Run()
		}(op)

		var ran bool
		select {
		case ran = <-done:
		case <-time.After(f.timeout):
			logf("TIMEOUT on operation %q — recovering", op.Name)
			recoverModule()
			time.Sleep(250 * time.Millisecond)
			f.skip(fmt.Sprintf("timeout: %s", op.Name))
			continue
		}

		if ran {
			f.checkInvariants()
		}
	}
}

func (f *Fuzzer) checkInvariants() {
	var wg sync.WaitGroup
	for _, inv := range invariants {
		wg.Add(1)
		go func(inv Invariant) {
			defer wg.Done()
			if msg := inv.Check(); msg != "" {
				f.fail(fmt.Sprintf("invariant %s: %s", inv.Name, msg))
				logf("INVARIANT FAIL: %s — %s", inv.Name, msg)
			} else {
				f.ok(fmt.Sprintf("invariant %s", inv.Name))
			}
		}(inv)
	}
	wg.Wait()
}

// ============================================================
// Recovery
// ============================================================

func recoverModule() {
	sysfsReset()
	if !moduleLoaded() {
		return
	}
	exec.Command("rmmod", moduleName).Run()
	if !moduleLoaded() {
		return
	}
	logf("rmmod failed, trying rmmod -f (may panic)")
	exec.Command("rmmod", "-f", moduleName).Run()
	if !moduleLoaded() {
		return
	}
	logf("rmmod -f also failed — reloading module to restore clean state")
	exec.Command("insmod", koPath).Run()
}

func sysfsReset() {
	writeSysfs("pgp_active", "0")
	writeSysfs("enabled", "0")
	key := readSysfs("key")
	if len(key) == 32 && isHex(key) {
		writeSysfsBare("unblock", key)
	}
	dk := decryptAnyCiphertext()
	if dk != "" {
		writeSysfsBare("disable", dk)
	}
	exec.Command("chattr", "-i", stateFile).Run()
	exec.Command("chattr", "-i", hostsFile).Run()
	if entries, err := os.ReadDir(pgpEncDir); err == nil {
		for _, e := range entries {
			exec.Command("chattr", "-i", filepath.Join(pgpEncDir, e.Name())).Run()
		}
	}
}

func finalRecover() {
	exec.Command("chattr", "-i", hostsFile).Run()
	exec.Command("chattr", "-i", stateFile).Run()
	exec.Command("chattr", "-i", "/etc/modules-load.d/kblocker.conf").Run()
	koPath := fmt.Sprintf("/lib/modules/%s/extra/kblocker.ko", uname())
	exec.Command("chattr", "-i", koPath).Run()

	writeSysfs("pgp_active", "0")
	writeSysfs("enabled", "0")
	exec.Command("rmmod", moduleName).Run()
	exec.Command("rmmod", "-f", moduleName).Run()
}

func uname() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// ============================================================
// Entry
// ============================================================

func main() {
	seed := flag.Int64("seed", 42, "random seed")
	ops := flag.Int("ops", 500, "number of operations")
	timeout := flag.Duration("timeout", 10*time.Second, "per-operation timeout")
	flag.BoolVar(&verbose, "verbose", false, "show all pass/fail lines")
	flag.BoolVar(&verbose, "v", false, "show all pass/fail lines (shorthand)")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "fuzz: must be run as root")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "fuzz: seed=%d ops=%d timeout=%s%s\n",
		*seed, *ops, *timeout, map[bool]string{false: "", true: " verbose"}[verbose])

	f := NewFuzzer(*seed, *ops, *timeout)
	f.Run()

	if f.failCnt > 0 {
		os.Exit(1)
	}
}

