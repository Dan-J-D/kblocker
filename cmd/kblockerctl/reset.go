package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// defaultDomains is the starter list that make install and the .deb block
var defaultDomains = []string{
	"facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
	"x.com", "twitter.com", "twimg.com", "tiktok.com", "tiktokcdn.com",
	"reddit.com", "redd.it", "snapchat.com", "threads.net", "bsky.app",
}

// doReset puts the configuration back to how a fresh install leaves it:
// the starter site list, no allowed networks or blocked IPs, no schedule
// and the default key holder page address. History and key holders are
// only removed when asked for. Refused during a block, since it would
// otherwise be a way out of one.
func doReset(args []string) {
	var history, holders, yes bool
	for _, a := range args {
		switch a {
		case "--history":
			history = true
		case "--key-holders":
			holders = true
		case "--yes", "-y":
			yes = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown option: %s\n", a)
			fmt.Fprintln(os.Stderr, "Usage: kblockerctl reset [--history] [--key-holders] [--yes]")
			os.Exit(1)
		}
	}

	requiresRoot()
	if blockingEnabled() {
		fmt.Fprintf(os.Stderr, "%sError: cannot reset while blocking is active.%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	fmt.Println("This resets kblocker to its defaults:")
	fmt.Printf("  - Sites: back to the %d starter social media sites\n", len(defaultDomains))
	fmt.Println("  - Allowed networks and blocked IPs: removed")
	fmt.Println("  - Schedule: every scheduled block removed")
	fmt.Println("  - Key holder pages: back to this computer only")
	if history {
		fmt.Println("  - History: every past block deleted")
	}
	if holders {
		fmt.Println("  - Key holders: every registered key removed")
	}
	if !yes && !confirmReset() {
		fmt.Println("Nothing was changed.")
		os.Exit(1)
	}

	var failed []string
	step := func(name string, err error) {
		if err != nil {
			failed = append(failed, name)
			fmt.Fprintf(os.Stderr, "%s  %s: %v%s\n", colorRed, name, err, colorNC)
		} else {
			fmt.Printf("%s  %s reset%s\n", colorGreen, name, colorNC)
		}
	}

	step("Sites", resetSites())
	step("Allowed networks", resetAllowed())
	step("Schedule", resetSchedule())
	step("Key holder pages", resetWebPages())
	if history {
		step("History", removeFiles(historyFile, historyOpenFile))
	}
	if holders {
		step("Key holders", resetKeyHolders())
	}

	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "%sReset incomplete: %s.%s\n", colorRed, strings.Join(failed, ", "), colorNC)
		os.Exit(1)
	}
	fmt.Printf("%sReset to defaults.%s\n", colorGreen, colorNC)
}

// confirmReset asks on a terminal; without one (scripts, the desktop
// app) --yes is required, so a reset never happens by accident.
func confirmReset() bool {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "Pass --yes to reset without a terminal.")
		return false
	}
	fmt.Print("Type reset to continue: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == "reset"
}

func resetSites() error {
	if moduleLoaded() {
		if err := writeSysfsLines(sysfsBase+"/blocked_domains", defaultDomains); err != nil {
			return err
		}
		if err := writeSysfs(sysfsBase+"/blocked_ips", "\n"); err != nil {
			return err
		}
	}
	os.MkdirAll("/etc/kblocker", 0755)
	chattr(blockedDomainsFile, "-i")
	err := os.WriteFile(blockedDomainsFile, []byte(strings.Join(defaultDomains, "\n")+"\n"), 0644)
	chattr(blockedDomainsFile, "+i")
	return err
}

func resetAllowed() error {
	if moduleLoaded() {
		if err := writeSysfs(sysfsBase+"/allowed_ips", "\n"); err != nil {
			return err
		}
	}
	chattr(allowedIPsFile, "-i")
	return removeFiles(allowedIPsFile)
}

func resetSchedule() error {
	if err := writeSchedule(&schedule{Blocks: []scheduleBlock{}}); err != nil {
		return err
	}
	return removeFiles(scheduleStateFile)
}

func resetWebPages() error {
	if _, err := os.Stat(webDropIn); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := removeFiles(webDropIn); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
	}
	if out, err := exec.Command("systemctl", "try-restart", schedulerUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("restarting %s: %v: %s", schedulerUnit, err, out)
	}
	return nil
}

// resetKeyHolders removes every registered public key and the encrypted
// unload keys made for them.
func resetKeyHolders() error {
	var paths []string
	if entries, err := os.ReadDir(pgpKeyDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(pgpKeyDir, e.Name()))
			}
		}
	}
	if matches, err := filepath.Glob(filepath.Join(pgpEncDir, "unlock-*.asc")); err == nil {
		paths = append(paths, matches...)
	}
	for _, p := range paths {
		chattr(p, "-i")
	}
	return removeFiles(paths...)
}

// removeFiles deletes each path, ignoring ones that don't exist
func removeFiles(paths ...string) error {
	var errs []error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
