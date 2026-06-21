package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	sysfsBase = "/sys/kernel/kblocker"
)

var (
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	crashRe  = regexp.MustCompile(`(?i)(BUG|Call Trace|Oops|General protection|NULL pointer|stack frame|kblocker.*error)`)
	colorRed = "\033[0;31m"
	green    = "\033[0;32m"
	yellow   = "\033[1;33m"
	reset    = "\033[0m"
)

func init() {
	fi, _ := os.Stdout.Stat()
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		colorRed = ""
		green = ""
		yellow = ""
		reset = ""
	}
}

func randInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randStr(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = 32 + (b[i] % 95)
	}
	return string(b)
}

func randHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func writeSysfs(attr, data string) error {
	return os.WriteFile(sysfsBase+"/"+attr, []byte(data), 0)
}

func checkDmesg(lastLines int) (bool, string) {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return false, ""
	}
	lines := strings.Split(string(out), "\n")
	if lastLines > 0 && lastLines < len(lines) {
		lines = lines[len(lines)-lastLines:]
	}
	for _, line := range lines {
		if crashRe.MatchString(line) {
			return true, line
		}
	}
	return false, ""
}

type fuzzOp struct {
	attr string
	gen  func() string
}

var fuzzOps = []fuzzOp{
	{attr: "enabled", gen: func() string {
		switch randInt(10) {
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
		default:
			return strconv.Itoa(randInt(10000))
		}
	}},
	{attr: "blocked_ips", gen: func() string {
		switch randInt(8) {
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
			var ips []string
			for j := 0; j < randInt(20); j++ {
				ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", randInt(256), randInt(256), randInt(256), randInt(256)))
			}
			return strings.Join(ips, "\n")
		case 6:
			return randHex(randInt(128))
		default:
			return "xxx\n\n\nyyy\n"
		}
	}},
	{attr: "blocked_domains", gen: func() string {
		switch randInt(8) {
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
		default:
			return strings.Repeat("a", 256)
		}
	}},
	{attr: "disable", gen: func() string {
		switch randInt(5) {
		case 0:
			return "0"
		case 1:
			return randHex(32)
		case 2:
			return randStr(randInt(128))
		case 3:
			return ""
		default:
			return randHex(randInt(64))
		}
	}},
	{attr: "unblock", gen: func() string {
		switch randInt(5) {
		case 0:
			return randHex(32)
		case 1:
			return randStr(randInt(128))
		case 2:
			return ""
		case 3:
			return randHex(randInt(64))
		default:
			return "0"
		}
	}},
	{attr: "restore", gen: func() string {
		switch randInt(4) {
		case 0:
			return randHex(64) + ":" + strconv.Itoa(int(time.Now().Unix())+3600)
		case 1:
			return randStr(randInt(128))
		case 2:
			return ""
		default:
			return randHex(randInt(32))
		}
	}},
	{attr: "pgp_active", gen: func() string {
		switch randInt(5) {
		case 0:
			return "0"
		case 1:
			return "1"
		case 2:
			return "-1"
		case 3:
			return randStr(64)
		default:
			return "2"
		}
	}},
}

func main() {
	iterations := 5000
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil && n > 0 {
			iterations = n
		}
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "%sError: root required.%s\n", colorRed, reset)
		os.Exit(1)
	}

	if _, err := os.Stat(sysfsBase); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: module not loaded.%s\n", colorRed, reset)
		os.Exit(1)
	}

	fmt.Printf("%s=== kblocker fuzzer ===%s\n", yellow, reset)
	fmt.Printf("Iterations: %d\n\n", iterations)

	pass, fail := 0, 0

	for i := 0; i < iterations; i++ {
		op := fuzzOps[randInt(len(fuzzOps))]
		data := op.gen()

		if ok, line := checkDmesg(5); ok {
			fmt.Printf("%s[FAIL] iteration %d: kernel oops detected%s\n", colorRed, i, reset)
			fmt.Printf("  attr=%s data=%q\n", op.attr, trunc(data, 120))
			fmt.Printf("  dmesg: %s\n", line)
			fail++
			break
		}

		writeSysfs(op.attr, data)
		pass++

		if i > 0 && i%1000 == 0 {
			fmt.Printf("  %d iterations... (no oops)\n", i)
		}
	}

	fmt.Println()
	if fail == 0 {
		fmt.Printf("%s%d passed, 0 failed — no kernel errors%s\n", green, pass, reset)
	} else {
		fmt.Printf("%s%d passed, %d failed — kernel errors detected%s\n", yellow, pass, fail, reset)
		os.Exit(1)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
