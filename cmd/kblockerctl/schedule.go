package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	scheduleFile      = "/etc/kblocker/schedule.json"
	scheduleStateFile = "/var/lib/kblocker/schedule-state"
	scheduleTick      = 5 * time.Second
)

// A recurring block window. Days use time.Weekday numbering (0 = Sunday).
// An end at or before the start runs past midnight into the next day; the
// window belongs to the day it starts on.
type scheduleBlock struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Days    []int  `json:"days"`
	Start   string `json:"start"`
	End     string `json:"end"`
	Enabled bool   `json:"enabled"`
}

type schedule struct {
	Blocks []scheduleBlock `json:"blocks"`
}

// One occurrence of a block on a particular date
type scheduleWindow struct {
	Block scheduleBlock
	Start time.Time
	End   time.Time
}

// Identifies an occurrence, so the daemon starts each one at most once
func (w scheduleWindow) key() string {
	return w.Block.ID + "@" + w.Start.Format("2006-01-02T15:04")
}

var hhmmRegex = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

func parseHHMM(s string) (int, error) {
	m := hhmmRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid time %q (want HH:MM)", s)
	}
	h, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return h*60 + min, nil
}

func (s *schedule) validate() error {
	seen := make(map[string]bool)
	for i, b := range s.Blocks {
		if b.ID == "" {
			return fmt.Errorf("block %d: missing id", i+1)
		}
		if seen[b.ID] {
			return fmt.Errorf("block %d: duplicate id %q", i+1, b.ID)
		}
		seen[b.ID] = true
		if len(b.Days) == 0 {
			return fmt.Errorf("block %d: no days selected", i+1)
		}
		for _, d := range b.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("block %d: invalid day %d", i+1, d)
			}
		}
		start, err := parseHHMM(b.Start)
		if err != nil {
			return fmt.Errorf("block %d: %v", i+1, err)
		}
		end, err := parseHHMM(b.End)
		if err != nil {
			return fmt.Errorf("block %d: %v", i+1, err)
		}
		if start == end {
			return fmt.Errorf("block %d: start and end are the same", i+1)
		}
	}
	return nil
}

func readSchedule() (*schedule, error) {
	data, err := os.ReadFile(scheduleFile)
	if os.IsNotExist(err) {
		return &schedule{Blocks: []scheduleBlock{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s schedule
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %v", scheduleFile, err)
	}
	if s.Blocks == nil {
		s.Blocks = []scheduleBlock{}
	}
	return &s, nil
}

func writeSchedule(s *schedule) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll("/etc/kblocker", 0755)
	tmp := scheduleFile + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, scheduleFile)
}

// windowsAt returns the windows of b that contain t, checking occurrences
// that started today or (for overnight blocks) yesterday.
func (b scheduleBlock) windowsAt(t time.Time) []scheduleWindow {
	start, err1 := parseHHMM(b.Start)
	end, err2 := parseHHMM(b.End)
	if err1 != nil || err2 != nil {
		return nil
	}
	length := time.Duration(end-start) * time.Minute
	if end <= start {
		length += 24 * time.Hour
	}

	var out []scheduleWindow
	for _, offset := range []int{-1, 0} {
		day := time.Date(t.Year(), t.Month(), t.Day()+offset, 0, 0, 0, 0, t.Location())
		if !containsInt(b.Days, int(day.Weekday())) {
			continue
		}
		ws := time.Date(day.Year(), day.Month(), day.Day(), start/60, start%60, 0, 0, t.Location())
		we := ws.Add(length)
		if !t.Before(ws) && t.Before(we) {
			out = append(out, scheduleWindow{Block: b, Start: ws, End: we})
		}
	}
	return out
}

// activeWindow returns the enabled window containing t that ends last
func (s *schedule) activeWindow(t time.Time) (scheduleWindow, bool) {
	var best scheduleWindow
	found := false
	for _, b := range s.Blocks {
		if !b.Enabled {
			continue
		}
		for _, w := range b.windowsAt(t) {
			if !found || w.End.After(best.End) {
				best = w
				found = true
			}
		}
	}
	return best, found
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

var dayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

func formatDays(days []int) string {
	sorted := append([]int(nil), days...)
	// Monday-first, matching how people read a work week
	sort.Slice(sorted, func(i, j int) bool { return (sorted[i]+6)%7 < (sorted[j]+6)%7 })
	names := make([]string, len(sorted))
	for i, d := range sorted {
		names[i] = dayNames[d]
	}
	return strings.Join(names, " ")
}

// ---- Commands ----

func doSchedule(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			doScheduleSet(args[1:])
			return
		case "clear":
			doScheduleClear()
			return
		case "--json":
			s, err := readSchedule()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(s)
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown schedule command: %s\n", args[0])
			os.Exit(1)
		}
	}

	s, err := readSchedule()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if len(s.Blocks) == 0 {
		fmt.Println("No scheduled blocks.")
		fmt.Println("  Set one with: kblockerctl schedule set <schedule.json>")
		return
	}
	for _, b := range s.Blocks {
		state := green("on")
		if !b.Enabled {
			state = yellow("off")
		}
		name := b.Name
		if name == "" {
			name = b.ID
		}
		fmt.Printf("%s  %s-%s  %s  [%s]\n", formatDays(b.Days), b.Start, b.End, name, state)
	}
	if w, ok := s.activeWindow(time.Now()); ok {
		fmt.Printf("%sIn a scheduled block until %s.%s\n", colorCyan, w.End.Format("15:04"), colorNC)
	}
}

func doScheduleSet(args []string) {
	requiresRoot()
	requireDisabledForSchedule()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: specify a schedule file, or - for stdin.")
		os.Exit(1)
	}

	var data []byte
	var err error
	if args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading schedule: %v\n", err)
		os.Exit(1)
	}

	var s schedule
	if err := json.Unmarshal(data, &s); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid schedule JSON: %v\n", err)
		os.Exit(1)
	}
	if s.Blocks == nil {
		s.Blocks = []scheduleBlock{}
	}
	if err := s.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := writeSchedule(&s); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing schedule: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%sSaved %d scheduled block(s).%s\n", colorGreen, len(s.Blocks), colorNC)
}

func doScheduleClear() {
	requiresRoot()
	requireDisabledForSchedule()

	if err := writeSchedule(&schedule{Blocks: []scheduleBlock{}}); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing schedule: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%sSchedule cleared.%s\n", colorGreen, colorNC)
}

// Changing the schedule mid-block would let you shorten the commitment
// you are inside of, so it is held to the same rule as the domain list.
func requireDisabledForSchedule() {
	enabledRaw, err := readSysfs(sysfsBase + "/enabled")
	if err != nil {
		return
	}
	fields := strings.Fields(enabledRaw)
	if len(fields) > 0 && fields[0] == "1" {
		fmt.Fprintf(os.Stderr, "%sError: cannot change the schedule while blocking is active.%s\n", colorRed, colorNC)
		os.Exit(1)
	}
}

func blockingEnabled() bool {
	raw, err := readSysfs(sysfsBase + "/enabled")
	if err != nil {
		return false
	}
	fields := strings.Fields(raw)
	return len(fields) > 0 && fields[0] == "1"
}

// doScheduleDaemon starts a block whenever a scheduled window is open and
// blocking is off, and records every block in the history. Each window
// occurrence is started at most once: if the block is lifted early with the
// unload key, the daemon leaves it lifted until the next window.
func doScheduleDaemon() {
	requiresRoot()

	self, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot locate own executable: %v", err)
	}

	log.SetFlags(0)
	log.Printf("kblocker scheduler running (schedule: %s)", scheduleFile)
	startDaemonWeb()

	warned := make(map[string]bool)
	warnOnce := func(key, format string, a ...interface{}) {
		if !warned[key] {
			warned[key] = true
			log.Printf(format, a...)
		}
	}

	history := newHistoryTracker()
	for {
		started := scheduleDaemonTick(self, warnOnce)
		history.observe(time.Now().Unix(), readModuleState(), started)
		time.Sleep(scheduleTick)
	}
}

// scheduleDaemonTick returns the name of the scheduled block it started,
// or "" if it started none.
func scheduleDaemonTick(self string, warnOnce func(key, format string, a ...interface{})) string {
	s, err := readSchedule()
	if err != nil {
		warnOnce("read:"+err.Error(), "cannot read schedule: %v", err)
		return ""
	}

	now := time.Now()
	w, ok := s.activeWindow(now)
	if !ok {
		return ""
	}
	if !moduleLoaded() {
		warnOnce("module:"+w.key(), "scheduled block %q is due but the module is not loaded", w.Block.Name)
		return ""
	}
	if blockingEnabled() {
		return ""
	}

	last, _ := os.ReadFile(scheduleStateFile)
	if strings.TrimSpace(string(last)) == w.key() {
		// Already started and since lifted with the key
		return ""
	}

	// Round up so the block never ends before the window does
	minutes := int((w.End.Sub(now) + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		return ""
	}

	out, err := exec.Command(self, "enable", strconv.Itoa(minutes)).CombinedOutput()
	if err != nil {
		warnOnce("enable:"+w.key(), "could not start scheduled block %q: %v\n%s",
			w.Block.Name, err, strings.TrimSpace(string(out)))
		return ""
	}

	os.MkdirAll("/var/lib/kblocker", 0755)
	os.WriteFile(scheduleStateFile, []byte(w.key()+"\n"), 0644)
	log.Printf("started scheduled block %q until %s (%d min)", w.Block.Name, w.End.Format("15:04"), minutes)
	if w.Block.Name == "" {
		return "Scheduled block"
	}
	return w.Block.Name
}
