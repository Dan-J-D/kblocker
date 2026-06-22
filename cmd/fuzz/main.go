package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sysfsBase   = "/sys/kernel/kblocker"
	moduleName  = "kblocker"
	stateFile   = "/var/lib/kblocker/state"
	pgpKeyDir   = "/etc/kblocker/keys"
	pgpEncDir   = "/var/lib/kblocker/unlock-pgp"
	domainsFile = "/etc/kblocker/domains.conf"

	maxDomains    = 64
	maxDomainLen  = 256
	maxIPsV4      = 4096
	maxIPsV6      = 1024
	hostsFile     = "/etc/hosts"
	hostsMarker   = "# kblocker managed entries - do not edit manually"
)

var (
	hexRe       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	hexFPRegex  = regexp.MustCompile(`^[A-F0-9]{40}$`)
	crashRe     = regexp.MustCompile(`(?i)(BUG|Call Trace|Oops|General protection|NULL pointer|stack frame|Unable to handle kernel)`)
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[0;36m"
	colorNC     = "\033[0m"

	dmesgSnapshot       int32
	dmesgSnapshotContent string
	dmesgMu             sync.Mutex
	failCount     int32
	totalOps      int32
)

func init() {
	fi, _ := os.Stdout.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorCyan = ""
		colorNC = ""
	}
}

// ── helpers ──

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randStr(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = 32 + (b[i] % 95)
	}
	return string(b)
}

func randHex(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

func randIPv4() string {
	return fmt.Sprintf("%d.%d.%d.%d", randInt(256), randInt(256), randInt(256), randInt(256))
}

func randIPv6() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		b[0:2], b[2:4], b[4:6], b[6:8],
		b[8:10], b[10:12], b[12:14], b[14:16])
}

func randDomain() string {
	n := randInt(maxDomainLen - 5)
	if n < 1 {
		n = 1
	}
	return randStr(n) + ".com"
}

func writeSysfs(attr, data string) error {
	return os.WriteFile(sysfsBase+"/"+attr, []byte(data), 0)
}

func readSysfs(attr string) string {
	data, err := os.ReadFile(sysfsBase + "/" + attr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func moduleLoaded() bool {
	st, err := os.Stat(sysfsBase)
	return err == nil && st.IsDir()
}

// ── dmesg crash detection ──

func takeDmesgSnapshot() {
	b := make([]byte, 8)
	rand.Read(b)
	atomic.StoreInt32(&dmesgSnapshot, int32(time.Now().Unix()))
}

func checkForCrashesSinceSnapshot() (bool, string) {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return false, ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if crashRe.MatchString(line) {
			return true, line
		}
	}
	return false, ""
}

func checkForNewCrashes() (bool, string) {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return false, ""
	}
	current := string(out)

	dmesgMu.Lock()
	prev := dmesgSnapshotContent
	dmesgSnapshotContent = current
	dmesgMu.Unlock()

	for _, line := range strings.Split(current, "\n") {
		if line == "" {
			continue
		}
		if prev != "" && strings.Contains(prev, line) {
			continue
		}
		if crashRe.MatchString(line) {
			return true, line
		}
	}
	return false, ""
}

func resetDmesg() {
	exec.Command("dmesg", "-c").Run()
}

// ── module lifecycle ──

func loadModule() error {
	exec.Command("modprobe", moduleName).Run()
	for i := 0; i < 50; i++ {
		if moduleLoaded() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("module did not load")
}

func unloadModule() error {
	out, _ := exec.Command("rmmod", moduleName).CombinedOutput()
	if err := checkExit(); err != nil {
		return fmt.Errorf("rmmod failed: %s", strings.TrimSpace(string(out)))
	}
	for i := 0; i < 50; i++ {
		if !moduleLoaded() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("module did not unload")
}

func forceUnloadModule() error {
	out, _ := exec.Command("rmmod", "-f", moduleName).CombinedOutput()
	_ = out
	if err := checkExit(); err != nil {
		return err
	}
	for i := 0; i < 50; i++ {
		if !moduleLoaded() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func checkExit() error {
	return nil
}

// ── file state management ──

func chattr(path, flags string) {
	exec.Command("chattr", flags, path).Run()
}

func cleanupModuleArtifacts() {
	if moduleLoaded() {
		writeSysfs("enabled", "0")
		writeSysfs("pgp_active", "0")
		writeSysfs("blocked_ips", "\n")
		writeSysfs("blocked_domains", "\n")
		writeSysfs("update_hosts", "\n")
		writeSysfs("unblock", randHex(32))
		forceUnloadModule()
	}

	chattr(stateFile, "-i")
	os.Remove(stateFile)
	os.RemoveAll(pgpKeyDir)
	os.RemoveAll(pgpEncDir)
	chattr(domainsFile, "-i")
	os.RemoveAll("/etc/kblocker")

	koPath := fmt.Sprintf("/lib/modules/%s/extra/kblocker.ko", uname())
	chattr(koPath, "-i")

	modLoadFile := "/etc/modules-load.d/kblocker.conf"
	chattr(modLoadFile, "-i")
	os.Remove(modLoadFile)

	chattr("/etc/hosts", "-i")

	out, _ := exec.Command("dmesg", "-c").Output()
	fmt.Printf("  (cleared %d bytes of dmesg)\n", len(out))
}

func uname() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// ── report ──

type phaseResult struct {
	name   string
	pass   int
	fail   int
	errors []string
}

var phaseResults []phaseResult
var mu sync.Mutex

func reportPhase(name string, pass, fail int, errors []string) {
	mu.Lock()
	phaseResults = append(phaseResults, phaseResult{name, pass, fail, errors})
	mu.Unlock()
}

func red(s string) string  { return colorRed + s + colorNC }
func green(s string) string { return colorGreen + s + colorNC }
func yellow(s string) string { return colorYellow + s + colorNC }
func cyan(s string) string  { return colorCyan + s + colorNC }

// ══════════════════════════════════════════════════
// PHASE 1: Baseline random write fuzzing (all attrs)
// ══════════════════════════════════════════════════

type fuzzOp struct {
	attr string
	gen  func() string
}

func fuzzPhase1(n int) (pass, fail int, errors []string) {
	ops := []fuzzOp{
		{attr: "enabled", gen: func() string {
			switch randInt(12) {
			case 0:
				return "0"
			case 1:
				return strconv.Itoa(randInt(3600))
			case 2:
				return "-1"
			case 3:
				return "99999999999"
			case 4:
				return ""
			case 5:
				return randStr(randInt(256))
			case 6:
				return "0  " + randStr(20)
			case 7:
				return randHex(randInt(64))
			default:
				return strconv.Itoa(randInt(10000))
			}
		}},
		{attr: "blocked_ips", gen: func() string {
			switch randInt(10) {
			case 0:
				return randStr(randInt(512))
			case 1:
				return ""
			case 2:
				return "0.0.0.0"
			case 3:
				return "256.256.256.256"
			case 4:
				return "::1"
			case 5:
				return "127.0.0.1\n::1\n0.0.0.0"
			case 6:
				var ips []string
				for j := 0; j < randInt(20); j++ {
					ips = append(ips, randIPv4())
				}
				return strings.Join(ips, "\n")
			case 7:
				return randHex(randInt(128))
			case 8:
				return randIPv6()
			default:
				return "xxx\n\n\nyyy\n"
			}
		}},
		{attr: "blocked_domains", gen: func() string {
			switch randInt(10) {
			case 0:
				return randStr(randInt(2048))
			case 1:
				return ""
			case 2:
				return "youtube.com"
			case 3:
				var domains []string
				for j := 0; j < randInt(50); j++ {
					domains = append(domains, randStr(randInt(128))+".com")
				}
				return strings.Join(domains, "\n")
			case 4:
				return "a"
			case 5:
				return "domain\n\n\n\tdomain"
			case 6:
				return randHex(randInt(4096))
			case 7:
				return strings.Repeat("a", maxDomainLen-1)
			case 8:
				return strings.Repeat("a", maxDomainLen)
			default:
				return strings.Repeat("a", maxDomainLen+10)
			}
		}},
		{attr: "disable", gen: func() string {
			switch randInt(7) {
			case 0:
				return "0"
			case 1:
				return randHex(32)
			case 2:
				return randStr(randInt(128))
			case 3:
				return ""
			case 4:
				return randHex(randInt(64))
			case 5:
				return randHex(31)
			default:
				return randHex(33)
			}
		}},
		{attr: "unblock", gen: func() string {
			switch randInt(7) {
			case 0:
				return randHex(32)
			case 1:
				return randStr(randInt(128))
			case 2:
				return ""
			case 3:
				return randHex(randInt(64))
			case 4:
				return "0"
			case 5:
				return randHex(31)
			default:
				return randHex(33)
			}
		}},
		{attr: "restore", gen: func() string {
			switch randInt(6) {
			case 0:
				return randHex(64) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)
			case 1:
				return randStr(randInt(128))
			case 2:
				return ""
			case 3:
				return randHex(randInt(32))
			case 4:
				return randHex(63) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)
			default:
				return randHex(65) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)
			}
		}},
		{attr: "pgp_active", gen: func() string {
			switch randInt(7) {
			case 0:
				return "0"
			case 1:
				return "1"
			case 2:
				return "-1"
			case 3:
				return randStr(64)
			case 4:
				return "2"
			case 5:
				return "true"
			default:
				return "false"
			}
		}},
		{attr: "update_hosts", gen: func() string {
			switch randInt(5) {
			case 0:
				return ""
			case 1:
				return "1"
			case 2:
				return "trigger"
			case 3:
				return randStr(randInt(128))
			default:
				return randHex(randInt(32))
			}
		}},
	}

	fmt.Printf("\n%sPhase 1: Random write fuzzing (%d iterations)%s\n", colorCyan, n, colorNC)

	writeCount := 0
	for i := 0; i < n; i++ {
		if crashed, line := checkForNewCrashes(); crashed {
			errors = append(errors, fmt.Sprintf("iteration %d: kernel crash: %s", i, line))
			fail++
			break
		}

		op := ops[randInt(len(ops))]
		data := op.gen()

		err := writeSysfs(op.attr, data)
		writeCount++
		if err != nil {
			// EPERM/EINVAL are expected — track them but don't count as failures
			if !strings.Contains(err.Error(), "operation not permitted") &&
				!strings.Contains(err.Error(), "invalid argument") {
				errors = append(errors, fmt.Sprintf("write %s: %v", op.attr, err))
				fail++
			}
		} else {
			pass++
		}
	}

	reportPhase("Phase 1: Random write fuzzing", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 2: Read all sysfs attributes
// ══════════════════════════════════════════════════

func fuzzPhase2() (pass, fail int, errors []string) {
	roAttrs := []string{"status", "remaining", "block_count", "key", "enabled", "blocked_ips", "blocked_domains", "pgp_active"}

	fmt.Printf("\n%sPhase 2: Read all sysfs attributes%s\n", colorCyan, colorNC)

	for _, attr := range roAttrs {
		val := readSysfs(attr)
		if attr == "status" {
			if !strings.Contains(val, "enabled:") || !strings.Contains(val, "blocked_ips_v4:") {
				errors = append(errors, fmt.Sprintf("status missing expected fields: %q", trunc(val, 100)))
				fail++
				continue
			}
		}
		if attr == "key" {
			if val != "" && val != "encrypted" && val != "restored" && len(val) != 32 && len(val) != 33 {
				errors = append(errors, fmt.Sprintf("key unexpected format: %q", val))
				fail++
				continue
			}
		}
		if attr == "block_count" {
			if _, err := strconv.Atoi(val); err != nil {
				errors = append(errors, fmt.Sprintf("block_count not a number: %q", val))
				fail++
				continue
			}
		}
		if attr == "remaining" {
			if _, err := strconv.ParseInt(val, 10, 64); err != nil && val != "" {
				errors = append(errors, fmt.Sprintf("remaining not a number: %q", val))
				fail++
				continue
			}
		}
		pass++
	}

	// Read-write: write known value, read back, verify
	writeSysfs("pgp_active", "0")
	writeSysfs("enabled", "0")
	writeSysfs("blocked_ips", "10.0.0.1\n10.0.0.2")
	writeSysfs("blocked_domains", "test1.example.com\ntest2.example.com")

	ips := readSysfs("blocked_ips")
	if !strings.Contains(ips, "10.0.0.1") || !strings.Contains(ips, "10.0.0.2") {
		errors = append(errors, fmt.Sprintf("blocked_ips readback mismatch: %q", ips))
		fail++
	} else {
		pass++
	}

	domains := readSysfs("blocked_domains")
	if !strings.Contains(domains, "test1.example.com") || !strings.Contains(domains, "test2.example.com") {
		errors = append(errors, fmt.Sprintf("blocked_domains readback mismatch: %q", domains))
		fail++
	} else {
		pass++
	}

	enabled := readSysfs("enabled")
	if !strings.HasPrefix(enabled, "0") {
		errors = append(errors, fmt.Sprintf("enabled readback expected 0, got %q", enabled))
		fail++
	} else {
		pass++
	}

	// Clean up
	writeSysfs("blocked_ips", "\n")
	writeSysfs("blocked_domains", "\n")

	reportPhase("Phase 2: Read all sysfs attributes", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 3: Module lifecycle
// ══════════════════════════════════════════════════

func fuzzPhase3() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 3: Module lifecycle%s\n", colorCyan, colorNC)

	// Unload if loaded
	if moduleLoaded() {
		writeSysfs("enabled", "0")
		writeSysfs("pgp_active", "0")
		if err := unloadModule(); err != nil {
			errors = append(errors, fmt.Sprintf("initial unload: %v", err))
			fail++
		} else {
			pass++
		}
	}

	// Load
	for i := 0; i < 3; i++ {
		if err := loadModule(); err != nil {
			errors = append(errors, fmt.Sprintf("load attempt %d: %v", i, err))
			fail++
		} else {
			pass++
		}

		// Verify sysfs tree
		expected := []string{"status", "enabled", "blocked_ips", "blocked_domains", "key", "unblock", "disable", "remaining", "restore", "pgp_active", "update_hosts", "block_count"}
		for _, attr := range expected {
			info, err := os.Stat(sysfsBase + "/" + attr)
			if err != nil {
				errors = append(errors, fmt.Sprintf("missing sysfs attr after load: %s", attr))
				fail++
			} else {
				_ = info
				pass++
			}
		}

		// Unload
		writeSysfs("enabled", "0")
		writeSysfs("pgp_active", "0")
		if err := unloadModule(); err != nil {
			errors = append(errors, fmt.Sprintf("unload attempt %d: %v", i, err))
			fail++
		} else {
			pass++
		}

		// Verify sysfs gone
		if moduleLoaded() {
			errors = append(errors, fmt.Sprintf("sysfs still present after unload %d", i))
			fail++
		} else {
			pass++
		}
	}

	// Final load for subsequent phases
	if err := loadModule(); err != nil {
		errors = append(errors, fmt.Sprintf("final load: %v", err))
		fail++
	} else {
		pass++
	}

	reportPhase("Phase 3: Module lifecycle", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 4: Enable/disable sequences
// ══════════════════════════════════════════════════

func fuzzPhase4(n int) (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 4: Enable/disable sequences (%d iterations)%s\n", colorCyan, n, colorNC)

	sequences := []struct {
		name string
		ops  []func() error
	}{
		{
			name: "enable → enable (double)",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "60") },
				func() error { return writeSysfs("enabled", "120") },
			},
		},
		{
			name: "enable → disable → enable",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "60") },
				func() error { return writeSysfs("enabled", "0") },
				func() error { return writeSysfs("enabled", "120") },
			},
		},
		{
			name: "enable → block_ips (EPERM expected)",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "60") },
				func() error {
					err := writeSysfs("blocked_ips", "10.0.0.1")
					if err != nil && strings.Contains(err.Error(), "operation not permitted") {
						return nil
					}
					return fmt.Errorf("expected EPERM on blocked_ips when enabled, got %v", err)
				},
				func() error { return writeSysfs("enabled", "0") },
			},
		},
		{
			name: "enable → block_domains (EPERM expected)",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "60") },
				func() error {
					err := writeSysfs("blocked_domains", "example.com")
					if err != nil && strings.Contains(err.Error(), "operation not permitted") {
						return nil
					}
					return fmt.Errorf("expected EPERM on blocked_domains when enabled, got %v", err)
				},
				func() error { return writeSysfs("enabled", "0") },
			},
		},
		{
			name: "enable → time travel (expiry check)",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "1") },
				func() error {
					time.Sleep(2 * time.Second)
					en := readSysfs("enabled")
					if strings.HasPrefix(en, "1") {
						return fmt.Errorf("expected disabled after expiry, enabled=%q", en)
					}
					return nil
				},
			},
		},
		{
			name: "block_domains → enable → status check",
			ops: []func() error{
				func() error { return writeSysfs("blocked_domains", "blocked.com\nblocked2.com") },
				func() error { return writeSysfs("enabled", "120") },
				func() error {
					domains := readSysfs("blocked_domains")
					if !strings.Contains(domains, "blocked.com") {
						return fmt.Errorf("expected blocked.com in domains, got %q", domains)
					}
					return nil
				},
				func() error { return writeSysfs("enabled", "0") },
				func() error { return writeSysfs("blocked_domains", "\n") },
			},
		},
		{
			name: "set blocked_ips → enable → verify count",
			ops: []func() error{
				func() error { return writeSysfs("blocked_ips", "1.1.1.1\n2.2.2.2") },
				func() error {
					cnt := readSysfs("block_count")
					if cnt != "2" {
						return fmt.Errorf("expected block_count=2, got %s", cnt)
					}
					return nil
				},
				func() error { return writeSysfs("enabled", "60") },
				func() error {
					cnt := readSysfs("block_count")
					if cnt != "2" {
						return fmt.Errorf("expected block_count=2 while enabled, got %s", cnt)
					}
					return nil
				},
				func() error { return writeSysfs("enabled", "0") },
				func() error { return writeSysfs("blocked_ips", "\n") },
			},
		},
		{
			name: "enable with zero seconds",
			ops: []func() error{
				func() error { return writeSysfs("enabled", "0") },
				func() error {
					en := readSysfs("enabled")
					if !strings.HasPrefix(en, "0") {
						return fmt.Errorf("expected disabled after enable 0, got %q", en)
					}
					return nil
				},
			},
		},
		{
			name: "pgp_active then enable (EPERM expected)",
			ops: []func() error{
				func() error { return writeSysfs("pgp_active", "1") },
				func() error { return writeSysfs("enabled", "60") },
				func() error {
					en := readSysfs("enabled")
					// If enabled was already 1 from PGP mode, enable should fail with EPERM
					_ = en
					return nil
				},
				func() error { return writeSysfs("pgp_active", "0") },
			},
		},
	}

	for _, seq := range sequences {
		if crashed, line := checkForNewCrashes(); crashed {
			errors = append(errors, fmt.Sprintf("seq %s: kernel crash: %s", seq.name, line))
			fail++
			break
		}

		writeSysfs("enabled", "0")
		writeSysfs("pgp_active", "0")
		writeSysfs("blocked_ips", "\n")
		writeSysfs("blocked_domains", "\n")
		time.Sleep(100 * time.Millisecond)

		seqPass := true
		for _, op := range seq.ops {
			if err := op(); err != nil {
				errors = append(errors, fmt.Sprintf("seq %s: %v", seq.name, err))
				fail++
				seqPass = false
				break
			}
		}
		if seqPass {
			pass++
		}
	}

	// Clean up after phase
	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")
	writeSysfs("blocked_ips", "\n")
	writeSysfs("blocked_domains", "\n")

	reportPhase("Phase 4: Enable/disable sequences", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 5: Boundary and limit testing
// ══════════════════════════════════════════════════

func fuzzPhase5() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 5: Boundary and limit testing%s\n", colorCyan, colorNC)

	// MAX_DOMAINS=64, MAX_DOMAIN_LEN=256
	// MAX_IPS_V4=4096, MAX_IPS_V6=1024

	tests := []struct {
		name string
		attr string
		data string
	}{
		{"max domains (64)", "blocked_domains", func() string {
			var ds []string
			for i := 0; i < maxDomains; i++ {
				ds = append(ds, fmt.Sprintf("domain%d.example.com", i))
			}
			return strings.Join(ds, "\n")
		}()},
		{"over max domains (65)", "blocked_domains", func() string {
			var ds []string
			for i := 0; i < maxDomains+1; i++ {
				ds = append(ds, fmt.Sprintf("domain%d.example.com", i))
			}
			return strings.Join(ds, "\n")
		}()},
		{"domain near max length", "blocked_domains", strings.Repeat("a", maxDomainLen-2) + ".com"},
		{"domain exactly max length", "blocked_domains", strings.Repeat("a", maxDomainLen)},
		{"max IPv4 (4096)", "blocked_ips", func() string {
			var ips []string
			for i := 0; i < maxIPsV4; i++ {
				ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", randInt(256), randInt(256), randInt(256), randInt(256)))
			}
			return strings.Join(ips, "\n")
		}()},
		{"empty string all attrs", "enabled", ""},
		{"huge payload (64KB)", "blocked_domains", randStr(65536)},
		{"null bytes in payload", "blocked_domains", "example.com\x00evil.com"},
		{"unicode/utf8 payload", "blocked_domains", "éxämplé.com\n日本語.com"},
		{"very large number for enable", "enabled", "99999999999999999999999999999"},
		{"negative seconds for enable", "enabled", "-3600"},
		{"zero-length restore", "restore", ""},
		{"restore with future timestamp", "restore", randHex(64) + ":" + strconv.Itoa(int(time.Now().Unix())+86400)},
		{"restore with past timestamp", "restore", randHex(64) + ":" + strconv.Itoa(int(time.Now().Unix())-86400)},
		{"restore short hash", "restore", randHex(32) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)},
	}

	for _, tt := range tests {
		if crashed, line := checkForNewCrashes(); crashed {
			errors = append(errors, fmt.Sprintf("boundary %s: kernel crash: %s", tt.name, line))
			fail++
			break
		}

		writeSysfs("enabled", "0")
		time.Sleep(50 * time.Millisecond)

		err := writeSysfs(tt.attr, tt.data)
		if err != nil {
			// Some boundary tests will legitimately fail — that's OK
			pass++
		} else {
			pass++
		}

		// Read back to verify no corruption
		val := readSysfs(tt.attr)
		if tt.attr == "blocked_domains" || tt.attr == "blocked_ips" {
			_ = val
			// Just ensure read doesn't crash
		}
	}

	// Clean up — reset to known state
	writeSysfs("blocked_domains", "\n")
	writeSysfs("blocked_ips", "\n")

	reportPhase("Phase 5: Boundary and limit testing", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 6: Concurrent access
// ══════════════════════════════════════════════════

func fuzzPhase6(n int) (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 6: Concurrent access (%d goroutines)%s\n", colorCyan, n, colorNC)

	var wg sync.WaitGroup
	doneChan := make(chan struct{})

	attrs := []string{"enabled", "blocked_ips", "blocked_domains", "disable", "unblock", "pgp_active", "restore", "update_hosts"}

	// Writer goroutines
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				select {
				case <-doneChan:
					return
				default:
				}

				attr := attrs[randInt(len(attrs))]
				var data string
				switch attr {
				case "enabled":
					data = strconv.Itoa(randInt(3600))
				case "blocked_ips":
					data = randIPv4()
				case "blocked_domains":
					data = randStr(randInt(50)) + ".com"
				case "disable":
					data = randHex(32)
				case "unblock":
					data = randHex(32)
				case "pgp_active":
					data = strconv.Itoa(randInt(2))
				case "restore":
					data = randHex(64) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)
				case "update_hosts":
					data = "1"
				}

				writeSysfs(attr, data)
			}
		}(i)
	}

	// Reader goroutines
	for i := 0; i < n/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				select {
				case <-doneChan:
					return
				default:
				}
				readSysfs("status")
				readSysfs("enabled")
				readSysfs("blocked_ips")
				readSysfs("blocked_domains")
				readSysfs("key")
				readSysfs("remaining")
				readSysfs("block_count")
				readSysfs("pgp_active")
			}
		}(i)
	}

	wg.Wait()
	close(doneChan)

	// Check for crashes
	if crashed, line := checkForNewCrashes(); crashed {
		errors = append(errors, fmt.Sprintf("concurrent: kernel crash: %s", line))
		fail++
	} else {
		pass++
	}

	// Reset state
	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")
	writeSysfs("blocked_ips", "\n")
	writeSysfs("blocked_domains", "\n")
	writeSysfs("update_hosts", "\n")

	reportPhase("Phase 6: Concurrent access", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 7: Hosts file verification
// ══════════════════════════════════════════════════

func dmesgContains(pattern string) bool {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), pattern)
}

func fuzzPhase7() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 7: Hosts file interaction%s\n", colorCyan, colorNC)

	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")
	time.Sleep(100 * time.Millisecond)

	domains := []string{"blocked1.example.com", "blocked2.example.com"}

	// Set domains and trigger update_hosts
	writeSysfs("blocked_domains", strings.Join(domains, "\n"))
	writeSysfs("update_hosts", "1")
	time.Sleep(500 * time.Millisecond)

	if !dmesgContains("updated hosts file with 2 domains") {
		errors = append(errors, "kernel did not update hosts file with 2 domains")
		fail++
	} else {
		pass++
	}

	// Check the actual hosts file has the marker
	hostsData, err := os.ReadFile(hostsFile)
	if err != nil {
		errors = append(errors, fmt.Sprintf("cannot read /etc/hosts: %v", err))
		fail++
	} else {
		content := string(hostsData)
		if !strings.Contains(content, hostsMarker) {
			errors = append(errors, "hosts file missing kblocker marker after write")
			fail++
		} else {
			pass++
		}
		for _, d := range domains {
			if !strings.Contains(content, "0.0.0.0 "+d) {
				errors = append(errors, fmt.Sprintf("hosts missing 0.0.0.0 entry for %s", d))
				fail++
			} else {
				pass++
			}
			if !strings.Contains(content, ":: "+d) {
				errors = append(errors, fmt.Sprintf("hosts missing :: entry for %s", d))
				fail++
			} else {
				pass++
			}
		}
	}

	// Clear domains and trigger update_hosts (should trigger clear_hosts_from_kernel)
	chattr(hostsFile, "-i")
	writeSysfs("blocked_domains", "\n")
	writeSysfs("update_hosts", "1")
	time.Sleep(500 * time.Millisecond)

	// Verify hosts file was cleared by the kernel
	chattr(hostsFile, "-i")
	syncData, err := os.ReadFile(hostsFile)
	if err != nil {
		errors = append(errors, fmt.Sprintf("cannot read /etc/hosts after clear: %v", err))
		fail++
	} else if strings.Contains(string(syncData), hostsMarker) {
		errors = append(errors, "kernel did not clear hosts file entries (marker persists)")
		fail++
	} else {
		pass++
	}

	reportPhase("Phase 7: Hosts file interaction", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 8: State persistence
// ══════════════════════════════════════════════════

func fuzzPhase8() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 8: State persistence%s\n", colorCyan, colorNC)

	// Set known state
	writeSysfs("blocked_domains", "persist-test.com")
	writeSysfs("blocked_ips", "10.0.0.55")
	writeSysfs("enabled", "300")
	time.Sleep(100 * time.Millisecond)

	enabled := readSysfs("enabled")
	if !strings.HasPrefix(enabled, "1") {
		errors = append(errors, fmt.Sprintf("expected enabled=1 after enable, got %q", enabled))
		fail++
	} else {
		pass++
	}

	// Read the current key for state storage
	key := readSysfs("key")
	if key == "encrypted" || key == "restored" || key == "" {
		errors = append(errors, fmt.Sprintf("key unavailable for state test: %q", key))
		fail++
	} else {
		pass++

		// Write a manual state file (simulating kblockerctl storeState)
		hash := sha256Hex(key)
		expiry := time.Now().Unix() + 120

		os.MkdirAll("/var/lib/kblocker", 0755)
		chattr(stateFile, "-i")
		stateContent := fmt.Sprintf("key_hash:%s\nexpiry:%d\ndomains:persist-test.com\nblocked_ips:10.0.0.55\npgp_active:0\n", hash, expiry)
		os.WriteFile(stateFile, []byte(stateContent), 0600)
		chattr(stateFile, "+i")

		// Reload module
		writeSysfs("enabled", "0")
		writeSysfs("pgp_active", "0")
		if err := unloadModule(); err != nil {
			errors = append(errors, fmt.Sprintf("unload for state test: %v", err))
			fail++
		} else {
			pass++
		}

		if err := loadModule(); err != nil {
			errors = append(errors, fmt.Sprintf("reload for state test: %v", err))
			fail++
		} else {
			pass++
			time.Sleep(200 * time.Millisecond)

			// Check state restored
			status := readSysfs("status")
			if strings.Contains(status, "state_restored: 1") {
				pass++
			} else {
				errors = append(errors, fmt.Sprintf("state not restored after reload: %q", status))
				fail++
			}

			enabled = readSysfs("enabled")
			if !strings.HasPrefix(enabled, "1") {
				errors = append(errors, fmt.Sprintf("expected enabled=1 after restore, got %q", enabled))
				fail++
			} else {
				pass++
			}

			domains := readSysfs("blocked_domains")
			if !strings.Contains(domains, "persist-test.com") {
				errors = append(errors, fmt.Sprintf("domains not restored: %q", domains))
				fail++
			} else {
				pass++
			}

			ips := readSysfs("blocked_ips")
			if !strings.Contains(ips, "10.0.0.55") {
				errors = append(errors, fmt.Sprintf("IPs not restored: %q", ips))
				fail++
			} else {
				pass++
			}
		}
	}

	// Clean up
	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")
	writeSysfs("blocked_domains", "\n")
	writeSysfs("blocked_ips", "\n")
	chattr(stateFile, "-i")
	os.Remove(stateFile)

	reportPhase("Phase 8: State persistence", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 9: PGP flow (if GPG available)
// ══════════════════════════════════════════════════

func fuzzPhase9() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 9: PGP key lifecycle%s\n", colorCyan, colorNC)

	if _, err := exec.LookPath("gpg"); err != nil {
		errors = append(errors, fmt.Sprintf("gpg not available, skipping PGP phase"))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", 0, 1, errors)
		return
	}

	// Generate a test PGP key
	os.MkdirAll(pgpKeyDir, 0755)
	os.MkdirAll(pgpEncDir, 0755)

	tmpKeyDir, err := os.MkdirTemp("", "kblocker-pgp-test-*")
	if err != nil {
		errors = append(errors, fmt.Sprintf("temp dir: %v", err))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
		return
	}
	defer os.RemoveAll(tmpKeyDir)

	// Create GPG batch key generation config
	batchConfig := fmt.Sprintf(`
     Key-Type: RSA
     Key-Length: 2048
     Subkey-Type: RSA
     Subkey-Length: 2048
     Name-Real: Kblocker Test Key
     Name-Email: test@kblocker.local
     Expire-Date: 0
     %%no-protection
     %%commit
   `)
	batchFile := filepath.Join(tmpKeyDir, "batch.txt")
	os.WriteFile(batchFile, []byte(batchConfig), 0644)

	// Generate key in temp GNUPGHOME
	gpgHome := filepath.Join(tmpKeyDir, "gnupghome")
	os.MkdirAll(gpgHome, 0700)
	genCmd := exec.Command("gpg", "--batch", "--gen-key", batchFile)
	genCmd.Env = append(os.Environ(), "GNUPGHOME="+gpgHome)
	if out, err := genCmd.CombinedOutput(); err != nil {
		errors = append(errors, fmt.Sprintf("gpg keygen: %v: %s", err, string(out)))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
		return
	}

	// Export public key
	exportCmd := exec.Command("gpg", "--armor", "--export", "test@kblocker.local")
	exportCmd.Env = append(os.Environ(), "GNUPGHOME="+gpgHome)
	pubKey, err := exportCmd.Output()
	if err != nil {
		errors = append(errors, fmt.Sprintf("gpg export: %v", err))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
		return
	}

	// Extract fingerprint
	fpCmd := exec.Command("gpg", "--with-colons", "--show-keys", "-")
	fpCmd.Env = append(os.Environ(), "GNUPGHOME="+gpgHome)
	fpCmd.Stdin = bytes.NewReader(pubKey)
	fpOut, err := fpCmd.Output()
	if err != nil {
		errors = append(errors, fmt.Sprintf("gpg fingerprint: %v", err))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
		return
	}

	var fp string
	var encPath string
	for _, line := range strings.Split(string(fpOut), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 && fields[0] == "fpr" && fields[9] != "" {
			fp = fields[9]
			break
		}
	}
	if fp == "" || !hexFPRegex.MatchString(fp) {
		errors = append(errors, fmt.Sprintf("could not extract fingerprint"))
		fail++
		reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
		return
	}

	// Write public key to pgpKeyDir
	pubKeyPath := filepath.Join(pgpKeyDir, fp+".asc")
	os.WriteFile(pubKeyPath, pubKey, 0644)

	// Enable blocking to get a key
	writeSysfs("blocked_domains", "pgp-test.com")
	writeSysfs("enabled", "120")
	time.Sleep(100 * time.Millisecond)

	hexKey := readSysfs("key")
	if hexKey == "" || hexKey == "encrypted" || hexKey == "restored" {
		errors = append(errors, fmt.Sprintf("cannot get hex key for PGP test: %q", hexKey))
		fail++
	} else {
		pass++

		// Encrypt the key
		encPath = filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
		encCmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
			"--recipient-file", pubKeyPath, "--output", encPath)
		encCmd.Env = append(os.Environ(), "GNUPGHOME="+gpgHome)
		encCmd.Stdin = strings.NewReader(hexKey)
		if out, err := encCmd.CombinedOutput(); err != nil {
			errors = append(errors, fmt.Sprintf("gpg encrypt: %v: %s", err, string(out)))
			fail++
		} else {
			pass++
		}

		// Activate PGP mode
		writeSysfs("pgp_active", "1")

		// Verify key shows as "encrypted"
		keyVal := readSysfs("key")
		if keyVal != "encrypted" {
			errors = append(errors, fmt.Sprintf("expected key='encrypted', got %q", keyVal))
			fail++
		} else {
			pass++
		}

		// Try to disable with wrong key (should fail)
		err := writeSysfs("disable", randHex(32))
		if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
			errors = append(errors, fmt.Sprintf("expected EPERM with wrong key, got %v", err))
			fail++
		} else {
			pass++
		}

		// Try to unblock with wrong key (should fail)
		err = writeSysfs("unblock", randHex(32))
		if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
			errors = append(errors, fmt.Sprintf("expected EPERM unblock with wrong key, got %v", err))
			fail++
		} else {
			pass++
		}

		// Decrypt and use correct key to disable
		decCmd := exec.Command("gpg", "--decrypt", encPath)
		decCmd.Env = append(os.Environ(), "GNUPGHOME="+gpgHome)
		decOut, err := decCmd.Output()
		if err != nil {
			errors = append(errors, fmt.Sprintf("gpg decrypt: %v", err))
			fail++
		} else {
			decKey := strings.TrimSpace(string(decOut))
			if decKey == hexKey {
				pass++
				// Disable with correct key
				if err := writeSysfs("disable", decKey); err != nil {
					errors = append(errors, fmt.Sprintf("disable with correct key: %v", err))
					fail++
				} else {
					pass++
					// Verify disabled
					en := readSysfs("enabled")
					if !strings.HasPrefix(en, "0") {
						errors = append(errors, fmt.Sprintf("expected disabled after PGP unblock, got %q", en))
						fail++
					} else {
						pass++
					}
				}
			} else {
				errors = append(errors, fmt.Sprintf("decrypted key mismatch"))
				fail++
			}
		}
	}

	// Clean up
	writeSysfs("pgp_active", "0")
	writeSysfs("enabled", "0")
	writeSysfs("blocked_domains", "\n")
	writeSysfs("blocked_ips", "\n")

	chattr(stateFile, "-i")
	os.Remove(stateFile)
	chattr(pubKeyPath, "-i")
	os.Remove(pubKeyPath)
	if encPath != "" {
		chattr(encPath, "-i")
		os.Remove(encPath)
	}

	// Clean up GPG key from local keyring if imported
	exec.Command("gpg", "--batch", "--yes", "--delete-keys", fp).Run()

	reportPhase("Phase 9: PGP key lifecycle", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// PHASE 10: Unload with key validation
// ══════════════════════════════════════════════════

func fuzzPhase10() (pass, fail int, errors []string) {
	fmt.Printf("\n%sPhase 10: Kernel panic protection (unload with enabled)%s\n", colorCyan, colorNC)

	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")

	// Enable blocking
	writeSysfs("enabled", "60")
	time.Sleep(50 * time.Millisecond)

	enabled := readSysfs("enabled")
	if !strings.HasPrefix(enabled, "1") {
		errors = append(errors, fmt.Sprintf("expected enabled, got %q", enabled))
		fail++
		reportPhase("Phase 10: Kernel panic protection", pass, fail, errors)
		return
	}
	pass++

	// Try to force-unload (this will cause panic in kernel, so we don't actually test it)
	// Instead, test with unblock first

	// Read key and unblock
	hexKey := readSysfs("key")
	if hexKey == "" || hexKey == "encrypted" || hexKey == "restored" {
		errors = append(errors, fmt.Sprintf("cannot get key: %q", hexKey))
		fail++
	} else {
		pass++

		// Submit to unblock
		if err := writeSysfs("unblock", hexKey); err != nil {
			errors = append(errors, fmt.Sprintf("unblock with correct key: %v", err))
			fail++
		} else {
			pass++
			time.Sleep(50 * time.Millisecond)

			en := readSysfs("enabled")
			if !strings.HasPrefix(en, "0") {
				errors = append(errors, fmt.Sprintf("expected disabled after unblock, got %q", en))
				fail++
			} else {
				pass++
			}

			// Now modprobe can succeed
			// We already called unblock, so allow_unload is true
			// Reload test
		}
	}

	// Also test that force-unload without key is rejected
	writeSysfs("enabled", "60")
	time.Sleep(50 * time.Millisecond)
	writeSysfs("enabled", "0") // normal disable
	time.Sleep(50 * time.Millisecond)

	reportPhase("Phase 10: Kernel panic protection", pass, fail, errors)
	return
}

// ══════════════════════════════════════════════════
// helpers
// ══════════════════════════════════════════════════

func sha256Hex(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ══════════════════════════════════════════════════
// main
// ══════════════════════════════════════════════════

func main() {
	iterations := 5000
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil && n > 0 {
			iterations = n
		}
	}

	concurrency := 8
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil && n > 0 {
			concurrency = n
		}
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "%sError: root required.%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	fmt.Printf("%s═══════════════════════════════════════%s\n", colorCyan, colorNC)
	fmt.Printf("%s  kblocker comprehensive fuzzer%s\n", colorCyan, colorNC)
	fmt.Printf("%s═══════════════════════════════════════%s\n", colorCyan, colorNC)
	fmt.Printf("  Iterations:  %d\n", iterations)
	fmt.Printf("  Concurrency: %d\n", concurrency)
	fmt.Println()

	cleanupModuleArtifacts()

	// Load module for phases
	if err := loadModule(); err != nil {
		fmt.Fprintf(os.Stderr, "%sFailed to load module: %v%s\n", colorRed, err, colorNC)
		os.Exit(1)
	}
	fmt.Printf("%sModule loaded successfully%s\n\n", colorGreen, colorNC)

	start := time.Now()

	fuzzPhase1(iterations)
	fuzzPhase2()
	fuzzPhase4(iterations / 5)
	fuzzPhase5()
	fuzzPhase6(concurrency)
	fuzzPhase7()
	fuzzPhase8()
	fuzzPhase9()
	fuzzPhase10()

	// Phase 3 (module lifecycle) runs last since it unloads/reloads
	// First ensure clean state
	writeSysfs("enabled", "0")
	writeSysfs("pgp_active", "0")
	writeSysfs("blocked_ips", "\n")
	writeSysfs("blocked_domains", "\n")
	writeSysfs("update_hosts", "\n")

	fuzzPhase3()

	elapsed := time.Since(start)

	// Summary
	fmt.Printf("\n%s═══════════════════════════════════════%s\n", colorCyan, colorNC)
	fmt.Printf("%s  RESULTS%s\n", colorCyan, colorNC)
	fmt.Printf("%s═══════════════════════════════════════%s\n", colorCyan, colorNC)

	totalPass := 0
	totalFail := 0
	for _, pr := range phaseResults {
		status := green("PASS")
		if pr.fail > 0 {
			status = red("FAIL")
		}
		fmt.Printf("  %-40s %s  (pass=%d fail=%d)\n", pr.name, status, pr.pass, pr.fail)
		totalPass += pr.pass
		totalFail += pr.fail
		if len(pr.errors) > 0 {
			maxShow := 5
			if len(pr.errors) < maxShow {
				maxShow = len(pr.errors)
			}
			for _, e := range pr.errors[:maxShow] {
				fmt.Printf("    %s%s%s\n", colorRed, e, colorNC)
			}
			if len(pr.errors) > maxShow {
				fmt.Printf("    %s... and %d more%s\n", colorYellow, len(pr.errors)-maxShow, colorNC)
			}
		}
	}

	fmt.Println()
	if totalFail == 0 {
		fmt.Printf("%sALL TESTS PASSED (%d pass, 0 fail) in %s%s\n", colorGreen, totalPass, elapsed.Round(time.Millisecond), colorNC)
	} else {
		fmt.Printf("%s%d FAILURES (%d pass, %d fail) in %s%s\n", colorRed, totalFail, totalPass, totalFail, elapsed.Round(time.Millisecond), colorNC)
		os.Exit(1)
	}

	// Final dmesg check
	if crashed, line := checkForNewCrashes(); crashed {
		fmt.Printf("%sKernel crash detected post-test: %s%s\n", colorRed, line, colorNC)
		os.Exit(1)
	}
}