package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	sysfsBase          = "/sys/kernel/kblocker"
	moduleName         = "kblocker"
	stateFile          = "/var/lib/kblocker/state"
	blockedDomainsFile = "/etc/kblocker/domains.conf"
)

var (
	pgpKeyDir = getEnvDefault("KBLOCKER_PGP_KEY_DIR", "/etc/kblocker/keys")
	pgpEncDir = getEnvDefault("KBLOCKER_PGP_ENC_DIR", "/var/lib/kblocker/unlock-pgp")
)

var (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[0;36m"
	colorNC     = "\033[0m"
)

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func init() {
	// Disable colors if stdout is not a terminal
	fi, _ := os.Stdout.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorCyan = ""
		colorNC = ""
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "enable":
		doEnable(args)
	case "disable":
		doDisable()
	case "block":
		doBlock(args)
	case "unblock":
		doUnblock(args)
	case "unload":
		doUnload(args)
	case "status":
		doStatus()
	case "reload":
		doReload()
	case "add":
		doAdd(args)
	case "remove":
		doRemove(args)
	case "block-ip":
		doBlockIP(args)
	case "list":
		doList()
	case "key":
		doKey()
	case "add-pgp":
		doAddPGP(args)
	case "remove-pgp":
		doRemovePGP(args)
	case "list-pgp":
		doListPGP()
	case "pgp-cipher":
		doPGPCipher(args)
	case "crash":
		doCrash()
	case "add-pgp-web":
		doWeb(args)
	case "unblock-web":
		doUnblockWeb(args)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`kblockerctl - kblocker control tool

Usage:
  kblockerctl enable [minutes] [--insecure]
      Enable blocking. Default: 60 minutes.
      Requires registered PGP keys unless --insecure is set.

  kblockerctl disable
      Disable blocking. Module stays loaded.

  kblockerctl block <domain> [<domain>...]
      Configure domains to block (does NOT enable).

  kblockerctl unblock [--key <hex>]
      Disable blocking (same as disable). Module stays loaded.

  kblockerctl unload [--key <hex>]
      Remove module (needs key via PGP decrypt or --key).

  kblockerctl add <domain>
      Add a domain to the block list.

  kblockerctl remove <domain>
      Remove a domain from the block list.

  kblockerctl status
      Show current status.

  kblockerctl reload
      Re-write all configured domains to kernel module.

  kblockerctl block-ip <ip> [<ip>...]
      Manually set blocked IPs (replaces existing list).

  kblockerctl list
      Show blocked IPs and configured domains.

  kblockerctl key
      Show unload key and PGP key fingerprints.

  kblockerctl add-pgp <pubkey.asc> [name]
      Register a PGP public key for unlock encryption.
      Optionally assign a name (e.g. "alice") to identify it later.

  kblockerctl remove-pgp <fingerprint>
      Remove a registered PGP key.

  kblockerctl list-pgp
      List registered PGP keys.

  kblockerctl pgp-cipher <fingerprint>
      Print the PGP-encrypted unload key for a registered key.

  kblockerctl crash
      Trigger kernel panic (for emergency willpower).

  kblockerctl add-pgp-web [--port <port>] [--bind <ip>]
      Start web UI for PGP key management (browser-based key generation).
      Default: random port on 127.0.0.1.

  kblockerctl unblock-web [--port <port>] [--bind <ip>]
      Start web UI to unblock via PGP private key in browser.
      Decrypts the ciphertext client-side and submits the key.
      Default: random port on 127.0.0.1.

`)
}

func requiresRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: this command requires root.")
		os.Exit(1)
	}
}

func moduleLoaded() bool {
	st, err := os.Stat(sysfsBase)
	return err == nil && st.IsDir()
}

func requireModule() {
	if !moduleLoaded() {
		fmt.Fprintln(os.Stderr, "Error: kblocker module not loaded.")
		fmt.Fprintln(os.Stderr, "Run 'sudo modprobe kblocker' or 'sudo make install' first.")
		os.Exit(1)
	}
}

func requireDisabled() {
	data, err := os.ReadFile(sysfsBase + "/enabled")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 && fields[0] == "1" {
		fmt.Fprintf(os.Stderr, "%sError: cannot modify domains while blocking is active.%s\n", colorRed, colorNC)
		fmt.Fprintln(os.Stderr, "  Disable first: kblockerctl disable")
		os.Exit(1)
	}
}

func requireNoPGP() {
	data, err := os.ReadFile(sysfsBase + "/pgp_active")
	if err != nil {
		return
	}
	if strings.TrimSpace(string(data)) == "1" {
		fmt.Fprintf(os.Stderr, "%sError: PGP mode active. Use unblock with --key or PGP decrypt.%s\n", colorRed, colorNC)
		os.Exit(1)
	}
}

func readSysfs(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeSysfs(path string, data string) error {
	return os.WriteFile(path, []byte(data), 0)
}

func writeSysfsLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0)
}

func readFileLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func chattr(path string, flags string) error {
	if _, err := exec.LookPath("chattr"); err != nil {
		return nil
	}
	return exec.Command("chattr", flags, path).Run()
}

func hasImmutable(path string) bool {
	if _, err := exec.LookPath("lsattr"); err != nil {
		return false
	}
	out, err := exec.Command("lsattr", path).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "i")
}

func gpgShowKeys(path string) (fingerprint, user string, err error) {
	cmd := exec.Command("gpg", "--with-colons", "--show-keys", path)
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("gpg --show-keys failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 {
			if fields[0] == "fpr" {
				fingerprint = fields[9]
			}
			if fields[0] == "uid" {
				user = fields[9]
			}
		}
	}
	if fingerprint == "" {
		return "", "", fmt.Errorf("no fingerprint found in key file")
	}
	return fingerprint, user, nil
}

func gpgEncrypt(hexKey string, recipientFile string, outputFile string) error {
	cmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
		"--recipient-file", recipientFile,
		"--output", outputFile)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	io.WriteString(stdin, hexKey)
	stdin.Close()
	errOut, _ := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		if len(errOut) > 0 {
			return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(errOut)))
		}
		return err
	}
	return nil
}

func gpgDecrypt(encFile string) (string, error) {
	out, err := exec.Command("gpg", "--decrypt", encFile).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func pgpKeyFingerprints(dir string) []string {
	var fps []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fps
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
			continue
		}
		fp := fpFromFilename(name)
		if fp != "" && hexFPRegex.MatchString(fp) {
			fps = append(fps, fp)
		}
	}
	return fps
}

func pgpKeyName(fp string) string {
	data, err := os.ReadFile(filepath.Join(pgpKeyDir, fp+".name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func fpFromFilename(name string) string {
	for _, ext := range []string{".asc", ".gpg", ".pub"} {
		if strings.HasSuffix(name, ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return ""
}

func pgpCount(dir string) int {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".asc") || strings.HasSuffix(name, ".gpg") || strings.HasSuffix(name, ".pub") {
			count++
		}
	}
	return count
}

func readKeyFromSysfs() string {
	key, err := readSysfs(sysfsBase + "/key")
	if err != nil {
		return ""
	}
	if key == "encrypted" || key == "restored" {
		return ""
	}
	return key
}

func readKeyFromDmesg() string {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`unload key ([0-9a-f]{32})`)
	matches := re.FindAllStringSubmatch(string(out), -1)
	if len(matches) > 0 {
		return matches[len(matches)-1][1]
	}
	return ""
}

func readDomainConfigFile() []string {
	lines, err := readFileLines(blockedDomainsFile)
	if err != nil {
		return nil
	}
	return lines
}

func readKernelDomains() []string {
	data, err := os.ReadFile(sysfsBase + "/blocked_domains")
	if err != nil {
		return nil
	}
	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains
}

func syncConfigFromKernel() {
	domains := readKernelDomains()
	os.MkdirAll("/etc/kblocker", 0755)
	chattr(blockedDomainsFile, "-i")
	if len(domains) > 0 {
		os.WriteFile(blockedDomainsFile, []byte(strings.Join(domains, "\n")+"\n"), 0644)
	} else {
		os.WriteFile(blockedDomainsFile, nil, 0644)
	}
	chattr(blockedDomainsFile, "+i")
}

func sha256Hex(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func stateExpiry(minutes int) int64 {
	return time.Now().Unix() + int64(minutes)*60
}

func storeState(hexKey string, expiry int64) error {
	os.MkdirAll("/var/lib/kblocker", 0755)
	chattr(stateFile, "-i")

	hashHex := sha256Hex(hexKey)
	if hashHex == "" {
		fmt.Fprintf(os.Stderr, "%sWarning: could not compute key hash for state persistence%s\n", colorYellow, colorNC)
		return fmt.Errorf("hash computation failed")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("key_hash:%s\n", hashHex))
	sb.WriteString(fmt.Sprintf("expiry:%d\n", expiry))

	domains, err := readSysfs(sysfsBase + "/blocked_domains")
	if err == nil && domains != "" {
		domains = strings.ReplaceAll(strings.TrimSpace(domains), "\n", ",")
		sb.WriteString(fmt.Sprintf("domains:%s\n", domains))
	}

	ips, err := readSysfs(sysfsBase + "/blocked_ips")
	if err == nil && ips != "" {
		ips = strings.ReplaceAll(strings.TrimSpace(ips), "\n", ",")
		sb.WriteString(fmt.Sprintf("blocked_ips:%s\n", ips))
	}

	if err := os.WriteFile(stateFile, []byte(sb.String()), 0600); err != nil {
		return err
	}
	chattr(stateFile, "+i")
	return nil
}

func restoreStateFromFile() bool {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	var hashHex, expiry string
	for _, line := range lines {
		if strings.HasPrefix(line, "key_hash:") {
			hashHex = strings.TrimPrefix(line, "key_hash:")
		}
		if strings.HasPrefix(line, "expiry:") {
			expiry = strings.TrimPrefix(line, "expiry:")
		}
	}
	if hashHex == "" || expiry == "" {
		return false
	}
	if err := writeSysfs(sysfsBase+"/restore", hashHex+":"+expiry); err != nil {
		return false
	}
	return true
}

func resolveToIPs(domain string) []string {
	out, err := exec.Command("getent", "ahosts", domain).Output()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var ips []string
	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ip := fields[0]
			if re.MatchString(ip) && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func red(s string) string { return colorRed + s + colorNC }
func green(s string) string { return colorGreen + s + colorNC }
func yellow(s string) string { return colorYellow + s + colorNC }
func cyan(s string) string { return colorCyan + s + colorNC }

// ---- Command implementations ----

func doEnable(args []string) {
	requiresRoot()
	requireModule()

	insecure := false
	minutes := 60

	// Check if already enabled while PGP is active
	enabledRaw, _ := readSysfs(sysfsBase + "/enabled")
	if enabledRaw != "" {
		enabledFields := strings.Fields(enabledRaw)
		if len(enabledFields) > 0 && enabledFields[0] == "1" {
			pgpRaw, _ := readSysfs(sysfsBase + "/pgp_active")
			if strings.TrimSpace(pgpRaw) == "1" {
				fmt.Fprintf(os.Stderr, "%sError: blocking is already active with PGP mode.%s\n", colorRed, colorNC)
				fmt.Fprintln(os.Stderr, "  Disable first: kblockerctl unblock")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "%sError: blocking is already active.%s\n", colorRed, colorNC)
			fmt.Fprintln(os.Stderr, "  Disable first: kblockerctl disable")
			os.Exit(1)
		}
	}

	for _, a := range args {
		if a == "--insecure" {
			insecure = true
		} else if n, err := strconv.Atoi(a); err == nil && n > 0 {
			minutes = n
		}
	}

	domains := readDomainConfigFile()
	if len(domains) > 0 {
		fmt.Printf("%sWriting %d domains to kernel...%s\n", colorCyan, len(domains), colorNC)
		writeSysfsLines(sysfsBase+"/blocked_domains", domains)
	}

	var numPGP int
	if !insecure {
		numPGP = pgpCount(pgpKeyDir)
		if numPGP == 0 {
			fmt.Fprintf(os.Stderr, "%sNo PGP keys registered.%s\n", colorRed, colorNC)
			fmt.Fprintln(os.Stderr, "  Register a PGP public key first:")
			fmt.Fprintln(os.Stderr, "    kblockerctl add-pgp <pubkey.asc>")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  Or use --insecure to print the key to stdout")
			fmt.Fprintf(os.Stderr, "  (you must save it yourself):\n")
			fmt.Fprintf(os.Stderr, "    kblockerctl enable %d --insecure\n", minutes)
			os.Exit(1)
		}

		fmt.Printf("%sPre-arming PGP mode...%s\n", colorCyan, colorNC)
		if err := writeSysfs(sysfsBase+"/pgp_active", "1"); err != nil {
			fmt.Fprintf(os.Stderr, "%sFailed to arm PGP mode.%s\n", colorRed, colorNC)
			os.Exit(1)
		}
	}

	if err := writeSysfs(sysfsBase+"/enabled", fmt.Sprintf("%d", minutes*60)); err != nil {
		fmt.Fprintf(os.Stderr, "%sFailed to enable blocking%s\n", colorRed, colorNC)
		fmt.Fprintln(os.Stderr, "  If PGP mode is active, disable first: kblockerctl unblock")
		os.Exit(1)
	}

	hexKey := readKeyFromSysfs()
	if hexKey == "" {
		hexKey = readKeyFromDmesg()
	}

	if hexKey == "" {
		fmt.Printf("%sWarning: could not read unload key.%s\n", colorYellow, colorNC)
	} else {
		if !insecure {
			fmt.Printf("%sEncrypting key for %d PGP recipients...%s\n", colorCyan, numPGP, colorNC)
			os.MkdirAll(pgpEncDir, 0755)

			successCount := 0
			entries, err := os.ReadDir(pgpKeyDir)
			if err == nil {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
						continue
					}
					fp := fpFromFilename(name)
					if fp == "" || !hexFPRegex.MatchString(fp) {
						continue
					}
					keyPath := filepath.Join(pgpKeyDir, name)
				outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
				chattr(outPath, "-i")
				os.Remove(outPath)
				if err := gpgEncrypt(hexKey, keyPath, outPath); err != nil {
						fmt.Fprintf(os.Stderr, "  Failed to encrypt for %s: %v\n", fp, err)
						continue
					}
					os.Chmod(outPath, 0644)
					chattr(outPath, "+i")
					fmt.Printf("  Encrypted for %s\n", fp)
					successCount++
				}
			}

			if successCount == 0 {
				fmt.Fprintf(os.Stderr, "%sError: failed to encrypt key for any recipient.%s\n", colorRed, colorNC)
				fmt.Fprintln(os.Stderr, "  Check that your PGP keys are valid and compatible.")
				fmt.Fprintln(os.Stderr, "  File format must be ASCII-armored public key (.asc).")
				os.Exit(1)
			}

			// Only now, after confirming all new ciphertexts are written,
			// delete the old ones from any prior session
			cleanupPGPCiphertextsExcept(successCount > 0)

			fmt.Printf("%sKey encrypted for %d recipient(s) (raw key never written to disk).%s\n", colorGreen, successCount, colorNC)
		} else {
			fmt.Printf("%sINSECURE MODE: key will not be saved to disk.%s\n", colorYellow, colorNC)
			fmt.Printf("  Unload key: %s\n", hexKey)
			fmt.Println("  Write this down or send it to your unlockers via PGP.")
			fmt.Println("  Without it, you will need to reboot to remove the module.")
		}
	}

	if !insecure && hexKey != "" {
		expiry := stateExpiry(minutes)
		if err := storeState(hexKey, expiry); err == nil {
			fmt.Printf("%sState saved (survives reboot).%s\n", colorGreen, colorNC)
		}
	}

	fmt.Printf("%sBlocking enabled for %d minutes.%s\n", colorGreen, minutes, colorNC)
}

func cleanupPGPCiphertexts() {
	entries, err := os.ReadDir(pgpEncDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(pgpEncDir, e.Name())
		chattr(p, "-i")
		os.Remove(p)
	}
}

func cleanupPGPCiphertextsExcept(keepNew bool) {
	if keepNew {
		// Remove only ciphertexts for keys that are no longer registered.
		// New ones were already written by gpgEncrypt above.
		entries, err := os.ReadDir(pgpEncDir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				fp := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".asc"), "unlock-")
				if _, err := os.Stat(filepath.Join(pgpKeyDir, fp+".asc")); os.IsNotExist(err) {
					p := filepath.Join(pgpEncDir, e.Name())
					chattr(p, "-i")
					os.Remove(p)
				}
			}
		}
	} else {
		cleanupPGPCiphertexts()
	}
}

func doDisable() {
	requiresRoot()

	if !moduleLoaded() {
		fmt.Println("Module not loaded.")
		return
	}

	/* Use the disable sysfs, which handles both PGP and non-PGP modes.
	 * When PGP is not active, it disables immediately.
	 * When PGP is active, it requires the key — so tell the user. */
	pgpOn, _ := readSysfs(sysfsBase + "/pgp_active")
	if pgpOn == "1" {
		fmt.Fprintf(os.Stderr, "%sPGP mode active — use 'kblockerctl unblock' instead.%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	if err := writeSysfs(sysfsBase+"/disable", "0"); err != nil {
		fmt.Fprintf(os.Stderr, "%sFailed to disable: %v%s\n", colorRed, err, colorNC)
		os.Exit(1)
	}
	chattr(stateFile, "-i")
	os.Remove(stateFile)
	cleanupPGPCiphertexts()

	fmt.Printf("%sBlocking disabled. Module still loaded.%s\n", colorGreen, colorNC)
}

func doBlock(args []string) {
	requiresRoot()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify at least one domain to block.")
		os.Exit(1)
	}

	requireModule()
	requireDisabled()

	fmt.Printf("%sWriting %d domains to kernel module...%s\n", colorCyan, len(args), colorNC)
	writeSysfsLines(sysfsBase+"/blocked_domains", args)

	fmt.Printf("%sSaving domain configuration...%s\n", colorCyan, colorNC)
	syncConfigFromKernel()

	fmt.Printf("%sConfigured %d domains. Run 'kblockerctl enable' to activate.%s\n", colorGreen, len(args), colorNC)
}

func doUnblock(args []string) {
	requiresRoot()

	if !moduleLoaded() {
		fmt.Println("Module not loaded.")
		return
	}

	providedKey := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" || args[i] == "-k" {
			if i+1 < len(args) {
				providedKey = args[i+1]
				i++
			}
		}
	}

	pgpOn, _ := readSysfs(sysfsBase + "/pgp_active")

	if pgpOn == "1" {
		key := providedKey
		if key == "" {
			// Try PGP decrypt
			entries, err := os.ReadDir(pgpEncDir)
			if err == nil {
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
						if k, err := gpgDecrypt(filepath.Join(pgpEncDir, e.Name())); err == nil && k != "" {
							key = k
							break
						}
					}
				}
			}
		}

		if key != "" {
			fmt.Printf("%sKey verified via PGP%s\n", colorGreen, colorNC)
		}

		if key == "" {
			fmt.Fprintf(os.Stderr, "%sPGP mode active — unblock requires the unload key.%s\n", colorRed, colorNC)
			fmt.Fprintf(os.Stderr, "  Provide it via --key <hex> or ensure PGP-encrypted\n")
			fmt.Fprintf(os.Stderr, "  key is available in %s\n", pgpEncDir)
			os.Exit(1)
		}

		if err := writeSysfs(sysfsBase+"/disable", key); err != nil {
			fmt.Fprintf(os.Stderr, "%sFailed to authorize disable. Invalid key?%s\n", colorRed, colorNC)
			os.Exit(1)
		}
	} else {
		if err := writeSysfs(sysfsBase+"/disable", "0"); err != nil {
			fmt.Fprintf(os.Stderr, "%sFailed to disable: %v%s\n", colorRed, err, colorNC)
			os.Exit(1)
		}
	}

	chattr(stateFile, "-i")
	os.Remove(stateFile)
	cleanupPGPCiphertexts()

	fmt.Printf("%sBlocking disabled. Module still loaded.%s\n", colorGreen, colorNC)
}

func doUnload(args []string) {
	requiresRoot()

	key := ""
	providedKey := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--key" || args[i] == "-k" {
			if i+1 < len(args) {
				providedKey = args[i+1]
				i++
			}
		}
	}

	if providedKey != "" {
		key = providedKey
	} else {
		// Try PGP decrypt
		entries, err := os.ReadDir(pgpEncDir)
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
					if k, err := gpgDecrypt(filepath.Join(pgpEncDir, e.Name())); err == nil && k != "" {
						key = k
						fmt.Printf("%sDecrypted key via PGP%s\n", colorGreen, colorNC)
						break
					}
				}
			}
		}

		if key == "" {
			fmt.Printf("%sUnload key not found. Checking dmesg...%s\n", colorYellow, colorNC)
			key = readKeyFromDmesg()
			if key == "" {
				fmt.Fprintf(os.Stderr, "%sCould not find unload key.%s\n", colorRed, colorNC)
				fmt.Fprintln(os.Stderr, "  Provide it via --key <hex> or ensure the PGP-encrypted")
				fmt.Fprintf(os.Stderr, "  key is available in %s\n", pgpEncDir)
				fmt.Fprintln(os.Stderr, "  Or reboot to force-remove the module.")
				os.Exit(1)
			}
		}
	}

	fmt.Printf("%sAuthorizing module unload...%s\n", colorCyan, colorNC)
	if err := writeSysfs(sysfsBase+"/unblock", key); err != nil {
		fmt.Fprintf(os.Stderr, "%sFailed to authorize unload. Invalid key?%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	fmt.Printf("%sRemoving kernel module...%s\n", colorCyan, colorNC)
	if err := exec.Command("rmmod", moduleName).Run(); err != nil {
		exec.Command("rmmod", "-f", moduleName).Run()
	}

	chattr(stateFile, "-i")
	os.Remove(stateFile)

	entries, _ := os.ReadDir(pgpEncDir)
	for _, e := range entries {
		p := filepath.Join(pgpEncDir, e.Name())
		chattr(p, "-i")
	}
	os.RemoveAll(pgpEncDir)

	chattr("/etc/kblocker/domains.conf", "-i")
	os.RemoveAll("/etc/kblocker")

	fmt.Printf("%sUnblocked. Module removed.%s\n", colorGreen, colorNC)
}

func doStatus() {
	if !moduleLoaded() {
		fmt.Println("kblocker: NOT LOADED")
		return
	}

	statusData, err := os.ReadFile(sysfsBase + "/status")
	if err != nil {
		fmt.Println("kblocker: unknown (cannot read status)")
		return
	}

	parseField := func(prefix string) string {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, prefix) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
		return ""
	}

	enabledState := parseField("enabled")

	remaining := parseField("remaining")
	countV4 := parseField("blocked_ips_v4")
	countV6 := parseField("blocked_ips_v6")
	domainCount := parseField("blocked_domains")
	protectCount := parseField("protected_files")
	restoredState := parseField("state_restored")

	count1, _ := strconv.Atoi(countV4)
	count2, _ := strconv.Atoi(countV6)
	totalIPs := count1 + count2

	var remSecs int64
	if remaining != "" {
		remSecs, _ = strconv.ParseInt(remaining, 10, 64)
	}

	if enabledState == "1" {
		mins := remSecs / 60
		secs := remSecs % 60
		fmt.Printf("%sBlocking: ACTIVE%s\n", colorGreen, colorNC)
		fmt.Printf("  Time remaining: %dm %ds\n", mins, secs)
	} else {
		fmt.Printf("%sBlocking: DISABLED%s\n", colorYellow, colorNC)
		fmt.Println("  Run 'kblockerctl enable <minutes>' to activate")
	}
	fmt.Printf("  Blocked IPs: %d\n", totalIPs)
	fmt.Printf("  Blocked domains: %s\n", domainCount)
	fmt.Printf("  Protected files: %s\n", protectCount)

	if restoredState == "1" {
		fmt.Println("  State: restored from disk")
	}

	koFile := fmt.Sprintf("/lib/modules/%s/extra/kblocker.ko", uname())
	if _, err := os.Stat(koFile); err == nil {
		if hasImmutable(koFile) {
			fmt.Println("  Module file: immutable")
		} else {
			fmt.Println("  Module file: mutable")
		}
	} else {
		fmt.Println("  Module file: MISSING")
	}

	modLoadFile := "/etc/modules-load.d/kblocker.conf"
	if _, err := os.Stat(modLoadFile); err == nil {
		if hasImmutable(modLoadFile) {
			fmt.Println("  Auto-load: immutable (persistent)")
		} else {
			fmt.Println("  Auto-load: present")
		}
	} else {
		fmt.Println("  Auto-load config: MISSING")
	}

	if _, err := os.Stat(blockedDomainsFile); err == nil {
		fmt.Println("  Configured domains:")
		domains, _ := readFileLines(blockedDomainsFile)
		for _, d := range domains {
			fmt.Printf("    - %s\n", d)
		}
	}

	fmt.Println("  Key:")
	encDir, err := os.ReadDir(pgpEncDir)
	if err == nil && len(encDir) > 0 {
		fmt.Println("    Type: PGP-encrypted (in memory only)")
		for _, e := range encDir {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				fp := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".asc"), "unlock-")
				fmt.Printf("    Recipient: %s\n", fp)
			}
		}
	} else {
		fmt.Println("    Type: in-kernel hash (read via: kblockerctl key)")
	}
}

func uname() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func doReload() {
	requiresRoot()
	requireModule()

	domains := readDomainConfigFile()
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "No configured domains found.")
		os.Exit(1)
	}

	fmt.Printf("%sRe-writing %d domains to kernel module...%s\n", colorCyan, len(domains), colorNC)
	writeSysfsLines(sysfsBase+"/blocked_domains", domains)

	numPGP := pgpCount(pgpKeyDir)
	if numPGP > 0 {
		hexKey := readKeyFromSysfs()
		if hexKey == "" {
			hexKey = readKeyFromDmesg()
		}
		if hexKey == "" {
			fmt.Printf("%sWarning: no unload key available to re-encrypt.%s\n", colorYellow, colorNC)
			goto skipEnc
		}
		fmt.Printf("%sRefreshing PGP ciphertexts for %d keys...%s\n", colorCyan, numPGP, colorNC)
		os.MkdirAll(pgpEncDir, 0755)
		entries, _ := os.ReadDir(pgpKeyDir)
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
				continue
			}
			fp := fpFromFilename(name)
			if fp == "" || !hexFPRegex.MatchString(fp) {
				continue
			}
			keyPath := filepath.Join(pgpKeyDir, name)
			outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
			chattr(outPath, "-i")
			os.Remove(outPath)
			gpgEncrypt(hexKey, keyPath, outPath)
			os.Chmod(outPath, 0644)
			chattr(outPath, "+i")
		}
	}
skipEnc:

	if restoreStateFromFile() {
		fmt.Printf("%sBlocking state restored from disk.%s\n", colorGreen, colorNC)
	}

	fmt.Printf("%sReload complete.%s\n", colorGreen, colorNC)
}

func doAdd(args []string) {
	requiresRoot()
	requireModule()
	requireDisabled()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a domain to add.")
		os.Exit(1)
	}
	domain := args[0]

	domains := readKernelDomains()
	for _, d := range domains {
		if d == domain {
			fmt.Printf("%s is already blocked.\n", domain)
			return
		}
	}

	domains = append(domains, domain)
	writeSysfsLines(sysfsBase+"/blocked_domains", domains)
	syncConfigFromKernel()

	fmt.Printf("Added %s. Run 'kblockerctl enable' to activate.\n", domain)
}

func doRemove(args []string) {
	requiresRoot()
	requireModule()
	requireDisabled()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a domain to remove.")
		os.Exit(1)
	}
	domain := args[0]

	domains := readKernelDomains()
	var newDomains []string
	found := false
	for _, d := range domains {
		if d == domain {
			found = true
		} else {
			newDomains = append(newDomains, d)
		}
	}

	if !found {
		fmt.Printf("%s is not in the block list.\n", domain)
		return
	}

	if len(newDomains) == 0 {
		writeSysfs(sysfsBase+"/blocked_domains", "")
	} else {
		writeSysfsLines(sysfsBase+"/blocked_domains", newDomains)
	}
	syncConfigFromKernel()

	fmt.Printf("Removed %s. Run 'kblockerctl enable' to activate.\n", domain)
}

func doBlockIP(args []string) {
	requiresRoot()
	requireModule()
	requireDisabled()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify at least one IP to block.")
		os.Exit(1)
	}

	if err := writeSysfsLines(sysfsBase+"/blocked_ips", args); err != nil {
		fmt.Fprintf(os.Stderr, "%sFailed to write IPs to kernel module%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	count, _ := readSysfs(sysfsBase + "/block_count")
	fmt.Printf("%sBlocked %d IPs (total in kernel: %s).%s\n", colorGreen, len(args), count, colorNC)
}

func doList() {
	if !moduleLoaded() {
		fmt.Println("kblocker: NOT LOADED")
		return
	}

	fmt.Println("=== Blocked IPs ===")
	ips, err := os.ReadFile(sysfsBase + "/blocked_ips")
	if err != nil {
		fmt.Println("(empty)")
	} else if len(strings.TrimSpace(string(ips))) == 0 {
		fmt.Println("(empty)")
	} else {
		fmt.Print(string(ips))
	}
	fmt.Println()

	fmt.Println("=== Blocked Domains ===")
	domains, err := os.ReadFile(sysfsBase + "/blocked_domains")
	if err != nil {
		fmt.Println("(empty)")
	} else if len(strings.TrimSpace(string(domains))) == 0 {
		fmt.Println("(empty)")
	} else {
		fmt.Print(string(domains))
	}
	fmt.Println()

	if _, err := os.Stat(blockedDomainsFile); err == nil {
		fmt.Println("=== Configured Domains ===")
		data, _ := os.ReadFile(blockedDomainsFile)
		fmt.Print(string(data))
	}
}

func doKey() {
	requiresRoot()

	hexKey := readKeyFromSysfs()
	if hexKey == "" {
		hexKey = readKeyFromDmesg()
	}
	if hexKey == "" {
		entries, _ := os.ReadDir(pgpEncDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				if k, err := gpgDecrypt(filepath.Join(pgpEncDir, e.Name())); err == nil && k != "" {
					hexKey = k
					break
				}
			}
		}
	}

	if hexKey != "" {
		fmt.Printf("kblocker unload key: %s\n", hexKey)
		fmt.Println()
	}

	numPGP := pgpCount(pgpKeyDir)
	if numPGP > 0 {
		fmt.Println("Registered PGP keys:")
		for _, fp := range pgpKeyFingerprints(pgpKeyDir) {
			encStatus := "no"
			if _, err := os.Stat(filepath.Join(pgpEncDir, "unlock-"+fp+".asc")); err == nil {
				encStatus = "yes"
			}
			name := pgpKeyName(fp)
			label := ""
			if name != "" {
				label = fmt.Sprintf(" (%s)", name)
			}
			fmt.Printf("  %s%s  (encrypted: %s)\n", fp, label, encStatus)
		}
	} else {
		fmt.Println("No PGP keys registered.")
		fmt.Println("  Add with: kblockerctl add-pgp <pubkey.asc>")
		fmt.Println("  Or use:   kblockerctl enable --insecure")
	}

	if ents, err := os.ReadDir(pgpEncDir); err == nil {
		encCount := 0
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				encCount++
			}
		}
		fmt.Printf("PGP-encrypted copies: %d\n", encCount)
	}

	if hexKey == "" {
		fmt.Fprintln(os.Stderr, "No unload key found.")
		os.Exit(1)
	}
}

func doAddPGP(args []string) {
	requiresRoot()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a PGP public key file.")
		os.Exit(1)
	}
	keyFile := args[0]
	keyName := ""
	if len(args) > 1 {
		keyName = args[1]
	}

	if _, err := os.Stat(keyFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: file not found: %s\n", keyFile)
		os.Exit(1)
	}

	os.MkdirAll(pgpKeyDir, 0755)

	fp, _, err := gpgShowKeys(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not read PGP key from %s: %v\n", keyFile, err)
		os.Exit(1)
	}

	dest := filepath.Join(pgpKeyDir, fp+".asc")
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("PGP key %s already registered.\n", fp)
		return
	}

	input, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}
	os.WriteFile(dest, input, 0644)

	if keyName != "" {
		os.WriteFile(filepath.Join(pgpKeyDir, fp+".name"), []byte(keyName+"\n"), 0644)
	}

	if moduleLoaded() {
		hexKey := readKeyFromSysfs()
		if hexKey == "" {
			hexKey = readKeyFromDmesg()
		}
		if hexKey != "" {
			fmt.Printf("%sEncrypting existing key for new recipient...%s\n", colorCyan, colorNC)
			os.MkdirAll(pgpEncDir, 0755)
			outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
			chattr(outPath, "-i")
			os.Remove(outPath)
			if err := gpgEncrypt(hexKey, dest, outPath); err == nil {
				os.Chmod(outPath, 0644)
				chattr(outPath, "+i")
			}
		}
	}

	label := keyName
	if label == "" {
		label = fp
	}
	fmt.Printf("%sAdded PGP key: %s%s\n", colorGreen, label, colorNC)
}

func doRemovePGP(args []string) {
	requiresRoot()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a fingerprint or filename to remove.")
		os.Exit(1)
	}
	target := args[0]

	if _, err := os.Stat(pgpKeyDir); err != nil {
		fmt.Println("No PGP keys registered.")
		return
	}

	entries, err := os.ReadDir(pgpKeyDir)
	if err != nil {
		fmt.Println("No PGP keys registered.")
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
			continue
		}
		fp := fpFromFilename(name)
		if fp == "" || !hexFPRegex.MatchString(fp) {
			continue
		}
		matched := strings.EqualFold(name, target+".asc") || strings.EqualFold(name, target+".gpg") || strings.EqualFold(name, target+".pub") || strings.EqualFold(fp, target)
		if !matched {
			// Fallback: try GPG-based fingerprint extraction (the filename
			// may differ from what GPG reports for the same key, e.g. when
			// the key was uploaded via the web UI with openpgp.js)
			keyPath := filepath.Join(pgpKeyDir, name)
			if gpgFP, _, err := gpgShowKeys(keyPath); err == nil {
				matched = strings.EqualFold(gpgFP, target)
			}
		}
		if matched {
			encFile := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
			chattr(encFile, "-i")
			os.Remove(encFile)
			os.Remove(filepath.Join(pgpKeyDir, name))
			os.Remove(filepath.Join(pgpKeyDir, fp+".name"))
			fmt.Printf("Removed PGP key: %s\n", fp)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "No matching PGP key found: %s\n", target)
	os.Exit(1)
}

func doListPGP() {
	requiresRoot()

	if _, err := os.Stat(pgpKeyDir); err != nil {
		fmt.Println("No PGP keys registered.")
		return
	}

	entries, err := os.ReadDir(pgpKeyDir)
	if err != nil {
		fmt.Println("No PGP keys registered.")
		return
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
			continue
		}
		keyPath := filepath.Join(pgpKeyDir, name)
		fp, user, err := gpgShowKeys(keyPath)
		if err != nil {
			continue
		}
		n := pgpKeyName(fp)
		enc := "no"
		if _, err := os.Stat(filepath.Join(pgpEncDir, "unlock-"+fp+".asc")); err == nil {
			enc = "yes"
		}
		label := ""
		if n != "" {
			label = fmt.Sprintf(" (%s)", n)
		}
		fmt.Printf("Fingerprint: %s%s\n", fp, label)
		fmt.Printf("  User:       %s\n", user)
		fmt.Printf("  Encrypted:  %s\n", enc)
		fmt.Println()
		count++
	}

	if count == 0 {
		fmt.Println("No PGP keys registered.")
	}
}

func doPGPCipher(args []string) {
	requiresRoot()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a PGP key fingerprint (or prefix).")
		fmt.Fprintln(os.Stderr, "Usage: kblockerctl pgp-cipher <fingerprint>")
		os.Exit(1)
	}
	needle := args[0]

	if _, err := os.Stat(pgpEncDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error: no encrypted keys found in %s\n", pgpEncDir)
		os.Exit(1)
	}

	entries, err := os.ReadDir(pgpEncDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no encrypted keys found in %s\n", pgpEncDir)
		os.Exit(1)
	}

	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "unlock-") || !strings.HasSuffix(e.Name(), ".asc") {
			continue
		}
		fp := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".asc"), "unlock-")
		if strings.HasPrefix(fp, needle) {
			data, err := os.ReadFile(filepath.Join(pgpEncDir, e.Name()))
			if err != nil {
				continue
			}
			os.Stdout.Write(data)
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Error: no encrypted key matching '%s'.\n", needle)
	os.Exit(1)
}

func doCrash() {
	requiresRoot()
	requireModule()

	fmt.Println("Force-removing kblocker module. This will trigger a kernel panic.")
	fmt.Println("System will crash and require a reboot.")
	fmt.Println()
	fmt.Print("Are you sure? (yes/NO): ")

	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)
	if confirm != "yes" {
		fmt.Println("Aborted.")
		return
	}

	// Set up signal handling to print an extra warning before we go
	signal.Notify(make(chan os.Signal, 1), syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Triggering panic in 3 seconds...")
	time.Sleep(3 * time.Second)
	exec.Command("rmmod", "-f", moduleName).Run()
}

func doWeb(args []string) {
	bind := "127.0.0.1"
	port := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			port = args[i+1]
			i++
		} else if args[i] == "--bind" && i+1 < len(args) {
			bind = args[i+1]
			i++
		}
	}

	if port == "" {
		listener, err := net.Listen("tcp", bind+":0")
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		port = fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
	}

	addr := bind + ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/keys", handleAddKeyOnly)
	mux.HandleFunc("/api/status", handleAPISStatus)
	mux.HandleFunc("/api/kblocker-key", handleAPIKey)
	mux.HandleFunc("/api/refresh-encryption", handleAPIRefreshEnc)

	fmt.Printf("Kblocker web UI on http://%s\n", addr)
	if bind == "127.0.0.1" {
		fmt.Println("WARNING: Binds to localhost only. Do not expose publicly.")
	}
	if os.Geteuid() != 0 {
		fmt.Println("WARNING: Not root — PGP key writes will fail.")
	}

	fmt.Printf("%sKblocker unblock-web UI on http://%s%s\n", colorCyan, addr, colorNC)
	if bind == "127.0.0.1" {
		fmt.Println("  Binds to localhost only. Do not expose publicly.")
	}
	if os.Geteuid() != 0 {
		fmt.Println("  WARNING: Not root — unblock writes will fail.")
	}

	log.Fatal(http.Serve(listener, withCORS(mux)))
}

func doUnblockWeb(args []string) {
	bind := "127.0.0.1"
	port := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			port = args[i+1]
			i++
		} else if args[i] == "--bind" && i+1 < len(args) {
			bind = args[i+1]
			i++
		}
	}

	if port == "" {
		listener, err := net.Listen("tcp", bind+":0")
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		port = fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
	}

	addr := bind + ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveUnblockIndex)
	mux.HandleFunc("/api/ciphertext-by-key", handleAPICiphertextByKey)
	mux.HandleFunc("/api/unblock", handleAPIUnblock)
	mux.HandleFunc("/api/status", handleAPISStatus)

	fmt.Printf("%sKblocker unblock-web UI on http://%s%s\n", colorCyan, addr, colorNC)
	if bind == "127.0.0.1" {
		fmt.Println("  Binds to localhost only. Do not expose publicly.")
	}

	log.Fatal(http.Serve(listener, withCORS(mux)))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Web server handlers ----

var webHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kblocker — PGP Key Management</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 800px; margin: 0 auto; }
h1 { color: #58a6ff; margin-bottom: 8px; }
.subtitle { color: #8b949e; margin-bottom: 24px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.card h2 { color: #58a6ff; font-size: 16px; margin-bottom: 12px; }
label { display: block; margin-bottom: 4px; color: #8b949e; font-size: 13px; }
input[type="text"], input[type="email"] { width: 100%; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; margin-bottom: 12px; }
input:focus { outline: none; border-color: #58a6ff; }
.btn { display: inline-block; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; }
.btn-primary { background: #238636; color: #fff; }
.btn-primary:hover { background: #2ea043; }
.btn-primary:disabled { background: #23863680; cursor: not-allowed; }
.btn-danger { background: #da3633; color: #fff; }
.btn-danger:hover { background: #f85149; }
.btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
.btn-secondary:hover { background: #30363d; }
.key-list { list-style: none; }
.key-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #21262d; }
.key-item:last-child { border-bottom: none; }
.key-info { flex: 1; }
.key-fp { font-family: monospace; font-size: 13px; color: #c9d1d9; word-break: break-all; }
.key-user { color: #8b949e; font-size: 12px; margin-top: 2px; }
.key-name { color: #58a6ff; font-size: 12px; }
.key-enc { font-size: 11px; padding: 2px 8px; border-radius: 10px; }
.key-enc-yes { background: #23863620; color: #3fb950; border: 1px solid #238636; }
.key-enc-no { background: #da363320; color: #f85149; border: 1px solid #da3633; }
.empty-msg { color: #8b949e; font-style: italic; }
.loading { text-align: center; padding: 20px; color: #8b949e; }
.error { color: #f85149; background: #da363320; border: 1px solid #da3633; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 13px; }
.success { color: #3fb950; background: #23863620; border: 1px solid #238636; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 13px; }
.status-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 14px; }
.status-label { color: #8b949e; }
.status-value { color: #c9d1d9; font-family: monospace; }
.hidden { display: none; }
.blocker-status { margin-bottom: 24px; }
.download-note { font-size: 13px; color: #d29922; background: #d2992220; border: 1px solid #d29922; border-radius: 6px; padding: 10px 14px; margin: 12px 0; }
</style>
</head>
<body>
<div class="container">
  <h1>Kblocker</h1>
  <p class="subtitle">PGP Key Management Web UI</p>

  <div id="status-container" class="card blocker-status">
    <h2>Blocker Status</h2>
    <div id="status-content" class="loading">Loading...</div>
  </div>

  <div id="error-container" class="hidden"></div>
  <div id="success-container" class="hidden"></div>

  <div class="card">
    <h2>Generate a New PGP Key</h2>
    <p style="color:#8b949e;font-size:13px;margin-bottom:12px;">
      Generate a key pair in your browser. The private key is never sent to the server.
      Download and save it — you'll need it to decrypt the unload key later.
    </p>
    <form id="keygen-form">
      <label for="key-name">Your Name</label>
      <input type="text" id="key-name" name="name" placeholder="e.g. Alice" required>
      <label for="key-email">Email (optional)</label>
      <input type="email" id="key-email" name="email" placeholder="alice@example.com">
      <label for="key-cipher">Cipher</label>
      <select id="key-cipher" style="width:100%;padding:8px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px;margin-bottom:12px;">
        <option value="curve25519">ECC Curve25519 (default)</option>
        <option value="nistP256">ECC NIST P-256</option>
        <option value="nistP384">ECC NIST P-384</option>
        <option value="nistP521">ECC NIST P-521</option>
        <option value="secp256k1">ECC secp256k1</option>
        <option value="rsa2048">RSA 2048</option>
        <option value="rsa4096">RSA 4096</option>
      </select>
      <button type="submit" class="btn btn-primary" id="generate-btn">Generate Key Pair</button>
    </form>
    <div id="generate-result" class="hidden">
      <div class="download-note">
        <strong>Important:</strong> Download your private key now. It will not be stored on the server.
        Without it, you won't be able to decrypt the unload key.
      </div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn btn-secondary" id="download-priv-btn">Download Private Key</button>
        <button class="btn btn-secondary" id="download-pub-btn">Download Public Key</button>
      </div>
      <p style="color:#8b949e;font-size:12px;margin-top:8px;" id="key-fingerprint-display"></p>
    </div>
  </div>

</div>

<script src="https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js"></script>
<script>
let generatedPrivKey = '';
let generatedPubKey = '';
let generatedFP = '';

function showError(msg) {
  const el = document.getElementById('error-container');
  el.className = 'error';
  el.textContent = msg;
}

function showSuccess(msg) {
  const el = document.getElementById('success-container');
  el.className = 'success';
  el.textContent = msg;
}

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

async function loadStatus() {
  try {
    const data = await fetchJSON('/api/status');
    const c = document.getElementById('status-content');
    const rem = parseInt(data.remaining) || 0;
    const mins = Math.floor(rem / 60);
    const secs = rem % 60;
    c.innerHTML =
      '<div class="status-row"><span class="status-label">Blocker</span><span class="status-value">' +
      (data.enabled === '1'
        ? '<span style="color:#3fb950">ACTIVE</span> \u2014 ' + mins + 'm ' + secs + 's remaining</span></div>'
        : '<span style="color:#f85149">DISABLED</span></span></div>') +
      '<div class="status-row"><span class="status-label">Blocked Domains</span><span class="status-value">' + (data.blocked_domains || 0) + '</span></div>' +
      '<div class="status-row"><span class="status-label">Protected Files</span><span class="status-value">' + (data.protected_files || 0) + '</span></div>';
  } catch (e) {
    document.getElementById('status-content').innerHTML = '<span class="error">Failed: ' + e.message + '</span>';
  }
}


document.getElementById('keygen-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  var btn = document.getElementById('generate-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  var name = document.getElementById('key-name').value.trim();
  var email = document.getElementById('key-email').value.trim();
  var cipher = document.getElementById('key-cipher').value;

  try {
    var keyOpts = { userIDs: [{ name: name, email: email || undefined }], format: 'armored' };

    if (cipher === 'rsa2048') {
      keyOpts.type = 'rsa';
      keyOpts.rsaBits = 2048;
    } else if (cipher === 'rsa4096') {
      keyOpts.type = 'rsa';
      keyOpts.rsaBits = 4096;
    } else {
      keyOpts.type = 'ecc';
      keyOpts.curve = cipher;
    }

    var pair = await openpgp.generateKey(keyOpts);

    generatedPrivKey = pair.privateKey;
    generatedPubKey = pair.publicKey;
    var pubKey = await openpgp.readKey({ armoredKey: generatedPubKey });
    var fp = pubKey.getFingerprint().toUpperCase();

    document.getElementById('generate-result').className = '';
    showSuccess('Key pair generated! Uploading to server...');

    var resp = await fetch('/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_key: generatedPubKey, name: name, fingerprint: fp })
    });
    if (!resp.ok) {
      var err = await resp.text();
      showError('Upload failed: ' + err);
      return;
    }
    var result = await resp.json();
    generatedFP = result.fingerprint;
    document.getElementById('key-fingerprint-display').textContent = 'Fingerprint: ' + generatedFP;
    showSuccess('Key uploaded and registered!');
  } catch (err) {
    showError('Failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Key Pair';
  }
});

document.getElementById('download-priv-btn').addEventListener('click', function() {
  if (!generatedPrivKey) return;
  var blob = new Blob([generatedPrivKey], { type: 'application/pgp-keys' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'kblocker-private.asc';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showSuccess('Private key downloaded!');
});

document.getElementById('download-pub-btn').addEventListener('click', function() {
  if (!generatedPubKey) return;
  var blob = new Blob([generatedPubKey], { type: 'application/pgp-keys' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'kblocker-public.asc';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showSuccess('Public key downloaded! Save it somewhere safe to decrypt the unload key later.');
});

loadStatus();
setInterval(loadStatus, 5000);
</script>
</body>
</html>`

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("index").Parse(webHTML))
	tmpl.Execute(w, nil)
}

type keyEntry struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	User        string `json:"user"`
	Encrypted   string `json:"encrypted"`
}

func readPGPKeyInfo(path string) (*keyEntry, error) {
	cmd := exec.Command("gpg", "--with-colons", "--show-keys", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gpg --show-keys failed: %w", err)
	}

	entry := &keyEntry{Encrypted: "no"}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 {
			if fields[0] == "fpr" && fields[9] != "" {
				entry.Fingerprint = fields[9]
			}
			if fields[0] == "uid" && fields[9] != "" {
				entry.User = fields[9]
			}
		}
	}

	nameFile := filepath.Join(pgpKeyDir, entry.Fingerprint+".name")
	if data, err := os.ReadFile(nameFile); err == nil {
		entry.Name = strings.TrimSpace(string(data))
	}

	if entry.Fingerprint != "" {
		if _, err := os.Stat(filepath.Join(pgpEncDir, "unlock-"+entry.Fingerprint+".asc")); err == nil {
			entry.Encrypted = "yes"
		}
	}

	return entry, nil
}

func handleAPISStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{"module_loaded": false}
	data, err := os.ReadFile(sysfsBase + "/status")
	if err == nil {
		status["module_loaded"] = true
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				status[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		listKeys(w, r)
	case "POST":
		addKey(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func listKeys(w http.ResponseWriter, r *http.Request) {
	os.MkdirAll(pgpKeyDir, 0755)

	var keys []*keyEntry
	entries, err := os.ReadDir(pgpKeyDir)
	if err != nil {
		keys = []*keyEntry{}
	} else {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
				continue
			}
			entry, err := readPGPKeyInfo(filepath.Join(pgpKeyDir, name))
			if err != nil || entry.Fingerprint == "" {
				continue
			}
			keys = append(keys, entry)
		}
	}

	if keys == nil {
		keys = []*keyEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
}

func handleAddKeyOnly(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addKey(w, r)
}

var hexFPRegex = regexp.MustCompile(`^[A-F0-9]{40}$`)

func addKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		PublicKey   string `json:"public_key"`
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		http.Error(w, "public_key is required", http.StatusBadRequest)
		return
	}

	tmpFile, err := os.CreateTemp("", "kblocker-pgp-*.asc")
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.WriteString(req.PublicKey); err != nil {
		tmpFile.Close()
		http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	cmd := exec.Command("gpg", "--with-colons", "--show-keys", tmpPath)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Invalid PGP public key", http.StatusBadRequest)
		return
	}

	var gpgFP string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 && fields[0] == "fpr" && fields[9] != "" {
			gpgFP = fields[9]
			break
		}
	}
	if gpgFP == "" || !hexFPRegex.MatchString(gpgFP) {
		http.Error(w, "Could not read valid fingerprint from key", http.StatusBadRequest)
		return
	}

	// Always use GPG-extracted fingerprint for the filename — the
	// client-provided fingerprint (from openpgp.js) may differ from
	// what GPG reports for the same key, causing filename mismatch
	// with list-pgp and remove-pgp.
	fp := gpgFP

	os.MkdirAll(pgpKeyDir, 0755)
	dest := filepath.Join(pgpKeyDir, fp+".asc")
	if _, err := os.Stat(dest); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Key already registered", "fingerprint": fp})
		return
	}

	if err := os.WriteFile(dest, []byte(req.PublicKey), 0644); err != nil {
		http.Error(w, "Failed to save key", http.StatusInternalServerError)
		return
	}
	if req.Name != "" {
		os.WriteFile(filepath.Join(pgpKeyDir, fp+".name"), []byte(req.Name+"\n"), 0644)
	}

	// Encrypt existing unload key for new recipient (only if key is available)
	keyStatus, _ := os.ReadFile(sysfsBase + "/key")
	keyRaw := strings.TrimSpace(string(keyStatus))
	if moduleLoaded() && keyRaw != "" && keyRaw != "encrypted" && keyRaw != "restored" {
		hexKey := keyRaw
		if len(hexKey) != 32 {
			hexKey = readKeyFromDmesg()
		}
		if hexKey != "" && len(hexKey) == 32 {
			os.MkdirAll(pgpEncDir, 0755)
			outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
			encCmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
				"--recipient-file", dest, "--output", outPath)
			stdin, _ := encCmd.StdinPipe()
			if err := encCmd.Start(); err == nil {
				io.WriteString(stdin, hexKey)
				stdin.Close()
				encCmd.Wait()
				os.Chmod(outPath, 0644)
			}
		}
	}

	entry, _ := readPGPKeyInfo(dest)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(entry)
}

func handleKeyByFP(w http.ResponseWriter, r *http.Request) {
	fp := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if fp == "" {
		http.Error(w, "Fingerprint required", http.StatusBadRequest)
		return
	}
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyFile := filepath.Join(pgpKeyDir, fp+".asc")
	if _, err := os.Stat(keyFile); err != nil {
		entries, _ := os.ReadDir(pgpKeyDir)
		found := false
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
				continue
			}
			cmd := exec.Command("gpg", "--with-colons", "--show-keys", filepath.Join(pgpKeyDir, name))
			out, _ := cmd.Output()
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Split(line, ":")
				if len(fields) >= 10 && fields[0] == "fpr" && fields[9] == fp {
					keyFile = filepath.Join(pgpKeyDir, name)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			http.Error(w, "Key not found", http.StatusNotFound)
			return
		}
	}

	encFile := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
	os.Remove(encFile)
	os.Remove(keyFile)
	os.Remove(filepath.Join(pgpKeyDir, fp+".name"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "fingerprint": fp})
}

func handleAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := readKeyFromSysfs()
	if key == "" {
		key = readKeyFromDmesg()
	}
	if key == "" {
		entries, _ := os.ReadDir(pgpEncDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				out, err := exec.Command("gpg", "--decrypt", filepath.Join(pgpEncDir, e.Name())).Output()
				if err == nil {
					key = strings.TrimSpace(string(out))
					break
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"key": key})
}

func handleAPIRefreshEnc(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hexKey := readKeyFromSysfs()
	if hexKey == "" {
		hexKey = readKeyFromDmesg()
	}
	if hexKey == "" {
		http.Error(w, "No unload key available", http.StatusNotFound)
		return
	}

	os.MkdirAll(pgpEncDir, 0755)
	count := 0

	entries, _ := os.ReadDir(pgpKeyDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pub") {
			continue
		}
		fp := fpFromFilename(name)
		if fp == "" || !hexFPRegex.MatchString(fp) {
			continue
		}
		keyPath := filepath.Join(pgpKeyDir, name)
		outPath := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
		cmd := exec.Command("gpg", "--yes", "--trust-model=always", "--encrypt", "--armor",
			"--recipient-file", keyPath, "--output", outPath)
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err == nil {
			io.WriteString(stdin, hexKey)
			stdin.Close()
			cmd.Wait()
			os.Chmod(outPath, 0644)
			count++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"encrypted": count})
}

var unblockHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kblocker — Unblock via PGP</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 800px; margin: 0 auto; }
h1 { color: #58a6ff; margin-bottom: 8px; }
.subtitle { color: #8b949e; margin-bottom: 24px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.card h2 { color: #58a6ff; font-size: 16px; margin-bottom: 12px; }
label { display: block; margin-bottom: 4px; color: #8b949e; font-size: 13px; }
textarea { width: 100%; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 13px; font-family: monospace; margin-bottom: 12px; resize: vertical; }
textarea:focus { outline: none; border-color: #58a6ff; }
.btn { display: inline-block; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; }
.btn-primary { background: #238636; color: #fff; }
.btn-primary:hover { background: #2ea043; }
.btn-primary:disabled { background: #23863680; cursor: not-allowed; }
.btn-danger { background: #da3633; color: #fff; }
.btn-danger:hover { background: #f85149; }
.btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
.btn-secondary:hover { background: #30363d; }
.btn-warning { background: #d29922; color: #fff; }
.btn-warning:hover { background: #e3b341; }
.loading { text-align: center; padding: 40px; color: #8b949e; }
.error { color: #f85149; background: #da363320; border: 1px solid #da3633; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 13px; white-space: pre-wrap; }
.success { color: #3fb950; background: #23863620; border: 1px solid #238636; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 13px; }
.info { color: #58a6ff; background: #58a6ff20; border: 1px solid #58a6ff; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 13px; }
.hidden { display: none; }
.step { margin-bottom: 8px; color: #8b949e; font-size: 13px; }
.step span { color: #58a6ff; font-weight: 600; }
.fingerprint-display { font-family: monospace; color: #58a6ff; word-break: break-all; margin: 8px 0; }
</style>
</head>
<body>
<div class="container">
  <h1>Kblocker</h1>
  <p class="subtitle">Unblock via PGP Private Key</p>

  <div id="error-container" class="hidden"></div>
  <div id="success-container" class="hidden"></div>

  <div class="card">
    <h2>Enter Your PGP Private Key</h2>
    <p class="step"><span>1.</span> Load or paste your armored private key</p>
    <div style="margin-bottom:12px;">
      <input type="file" id="key-file-input" accept="*/*" style="width:100%;padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px;margin-bottom:8px;" onchange="loadKeyFile(event)">
      <span style="color:#8b949e;font-size:13px;">or paste below</span>
    </div>
    <textarea id="privkey-input" rows="12" placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----

xsBNBGQ..."></textarea>
    <button class="btn btn-primary" id="decrypt-btn" onclick="doUnblock()">Decrypt &amp; Unblock</button>
    <div id="progress" class="hidden loading">Working...</div>
    <div id="fingerprint" class="fingerprint-display hidden"></div>
  </div>

  <div class="card">
    <h2>Blocker Status</h2>
    <div id="status-content" class="loading">Loading...</div>
  </div>
</div>

<script src="https://unpkg.com/openpgp@5.11.2/dist/openpgp.min.js"></script>
<script>
function loadKeyFile(event) {
  var file = event.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById('privkey-input').value = e.target.result;
  };
  reader.readAsText(file);
}

async function doUnblock() {
  var btn = document.getElementById('decrypt-btn');
  var progress = document.getElementById('progress');
  var fpEl = document.getElementById('fingerprint');
  var errorEl = document.getElementById('error-container');
  var successEl = document.getElementById('success-container');

  errorEl.className = 'hidden';
  successEl.className = 'hidden';
  fpEl.className = 'hidden';

  var armored = document.getElementById('privkey-input').value.trim();
  if (!armored) {
    showUnblockError('Please paste your private key or load a key file.');
    return;
  }

  btn.disabled = true;
  progress.className = 'loading';
  progress.textContent = 'Reading private key...';

  try {
    var privKey = await openpgp.readPrivateKey({ armoredKey: armored });

    progress.textContent = 'Extracting public key...';

    var pubKey = privKey.toPublic();
    var pubArmored = await pubKey.armor();
    var fp = pubKey.getFingerprint().toUpperCase();

    progress.textContent = 'Looking up ciphertext for this key (' + fp.substring(0,16) + '...)...';

    var cipherResp = await fetch('/api/ciphertext-by-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_key: pubArmored, fingerprint: fp })
    });
    if (!cipherResp.ok) {
      var errText = await cipherResp.text();
      throw new Error('No ciphertext found for this key: ' + errText);
    }
    var cipherArmored = await cipherResp.text();

    progress.textContent = 'Decrypting...';

    var message = await openpgp.readMessage({ armoredMessage: cipherArmored });
    var decrypted = await openpgp.decrypt({ message: message, decryptionKeys: privKey });
    var hexKey = decrypted.data.trim();

    if (!hexKey || hexKey.length !== 32) {
      throw new Error('Decrypted key looks invalid (expected 32 hex chars, got ' + hexKey.length + ')');
    }

    progress.textContent = 'Submitting unblock key...';

    var unblockResp = await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: hexKey })
    });

    if (!unblockResp.ok) {
      var unblockErr = await unblockResp.text();
      throw new Error('Unblock failed: ' + unblockErr);
    }

    var result = await unblockResp.json();
    progress.className = 'hidden';
    showUnblockSuccess('Blocking disabled! ' + (result.message || ''));
    btn.disabled = false;

    loadUnblockStatus();
  } catch (e) {
    progress.className = 'hidden';
    showUnblockError(e.message);
    btn.disabled = false;
  }
}

function showUnblockError(msg) {
  var el = document.getElementById('error-container');
  el.className = 'error';
  el.textContent = msg;
}

function showUnblockSuccess(msg) {
  var el = document.getElementById('success-container');
  el.className = 'success';
  el.textContent = msg;
}

async function loadUnblockStatus() {
  try {
    var res = await fetch('/api/status');
    var data = await res.json();
    var c = document.getElementById('status-content');
    var rem = parseInt(data.remaining) || 0;
    var mins = Math.floor(rem / 60);
    var secs = rem % 60;
    c.innerHTML =
      '<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px;">' +
        '<span style="color:#8b949e;">Blocker</span>' +
        '<span style="color:#c9d1d9;font-family:monospace;">' +
        (data.enabled === '1'
          ? '<span style="color:#3fb950">ACTIVE</span> &mdash; ' + mins + 'm ' + secs + 's remaining'
          : '<span style="color:#f85149">DISABLED</span>') +
        '</span></div>' +
      '<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:14px;">' +
        '<span style="color:#8b949e;">Domains</span>' +
        '<span style="color:#c9d1d9;font-family:monospace;">' + (data.blocked_domains || 0) + '</span></div>';
  } catch (e) {
    document.getElementById('status-content').innerHTML = '<span class="error">' + e.message + '</span>';
  }
}

loadUnblockStatus();
</script>
</body>
</html>`

func serveUnblockIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("unblock").Parse(unblockHTML))
	tmpl.Execute(w, nil)
}

func handleAPICiphertextByKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		http.Error(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// If client provided a fingerprint, use it directly
	if req.Fingerprint != "" && hexFPRegex.MatchString(strings.ToUpper(req.Fingerprint)) {
		fp := strings.ToUpper(req.Fingerprint)
		encFile := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
		data, err := os.ReadFile(encFile)
		if err == nil {
			w.Header().Set("Content-Type", "application/pgp-encrypted")
			w.Write(data)
			return
		}
		// File not found — fall through to GPG extraction
	}

	// Fall back to GPG-based fingerprint extraction
	tmpFile, err := os.CreateTemp("", "kblocker-unlock-*.asc")
	if err != nil {
		http.Error(w, "Failed to process key", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	tmpFile.WriteString(req.PublicKey)
	tmpFile.Close()

	cmd := exec.Command("gpg", "--with-colons", "--show-keys", tmpPath)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Invalid PGP public key", http.StatusBadRequest)
		return
	}

	var fp string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 && fields[0] == "fpr" && fields[9] != "" {
			fp = fields[9]
			break
		}
	}
	if fp == "" || !hexFPRegex.MatchString(fp) {
		http.Error(w, "Could not read valid fingerprint from key", http.StatusBadRequest)
		return
	}

	encFile := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
	data, err := os.ReadFile(encFile)
	if err != nil {
		// List available fingerprints so the user can compare
		avail := ""
		entries, _ := os.ReadDir(pgpEncDir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "unlock-") && strings.HasSuffix(e.Name(), ".asc") {
				f := strings.TrimPrefix(strings.TrimSuffix(e.Name(), ".asc"), "unlock-")
				if avail != "" {
					avail += ", "
				}
				avail += f
			}
		}
		msg := fmt.Sprintf("No ciphertext found for this key (looked for %s", fp)
		if avail != "" {
			msg += fmt.Sprintf("; available: %s", avail)
		}
		msg += ")"
		log.Printf("unblock-web: %s (read err: %v)", msg, err)
		http.Error(w, msg, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pgp-encrypted")
	w.Write(data)
}

func handleAPICiphertext(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fp := strings.TrimPrefix(r.URL.Path, "/api/ciphertext/")
	if fp == "" {
		http.Error(w, "Fingerprint required", http.StatusBadRequest)
		return
	}

	encFile := filepath.Join(pgpEncDir, "unlock-"+fp+".asc")
	data, err := os.ReadFile(encFile)
	if err != nil {
		http.Error(w, "No ciphertext found for fingerprint", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pgp-encrypted")
	w.Write(data)
}

func handleAPIUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		http.Error(w, "Key is required", http.StatusBadRequest)
		return
	}

	if !moduleLoaded() {
		http.Error(w, "Module not loaded", http.StatusNotFound)
		return
	}

	if err := writeSysfs(sysfsBase+"/disable", req.Key); err != nil {
		http.Error(w, "Failed to unblock — invalid key or system error", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "message": "Blocking disabled."})
}