package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Block history, recorded by the scheduler daemon as it watches the module.
// Finished blocks are appended to historyFile, one JSON object per line;
// the block in progress lives in historyOpenFile so a daemon restart or a
// reboot picks it back up.
const (
	historyFile     = "/var/lib/kblocker/history.jsonl"
	historyOpenFile = "/var/lib/kblocker/history-open.json"
)

const (
	outcomeOpen        = "open"
	outcomeCompleted   = "completed"   // ran until its timer expired
	outcomeUnlocked    = "unlocked"    // ended early with the key
	outcomeInterrupted = "interrupted" // gone without a trace, e.g. an unlocked block lost to a reboot
)

type historyEntry struct {
	Start      int64  `json:"start"`
	End        int64  `json:"end,omitempty"`
	PlannedEnd int64  `json:"planned_end"`
	Locked     bool   `json:"locked"`
	Scheduled  string `json:"scheduled,omitempty"`
	Outcome    string `json:"outcome"`
}

type moduleState struct {
	loaded    bool
	enabled   bool
	remaining int64
	pgp       bool
}

func readModuleState() moduleState {
	data, err := os.ReadFile(sysfsBase + "/status")
	if err != nil {
		return moduleState{}
	}
	st := moduleState{loaded: true}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "enabled":
			st.enabled = v == "1"
		case "remaining":
			st.remaining, _ = strconv.ParseInt(v, 10, 64)
		case "pgp_active":
			st.pgp = v == "1"
		}
	}
	return st
}

type historyTracker struct {
	record        func(historyEntry)
	open          *historyEntry
	lastRemaining int64
	lastSaved     int64
}

func newHistoryTracker() *historyTracker {
	t := &historyTracker{record: appendHistory}
	if data, err := os.ReadFile(historyOpenFile); err == nil {
		var e historyEntry
		if json.Unmarshal(data, &e) == nil && e.Start > 0 {
			t.open = &e
		}
	}
	return t
}

// observe updates the record from the module's current state. startedBy
// names the scheduled block the daemon started this tick, if any.
func (t *historyTracker) observe(now int64, st moduleState, startedBy string) {
	if !st.loaded {
		return
	}
	if st.enabled {
		if t.open == nil {
			t.open = &historyEntry{Start: now, Locked: st.pgp, Scheduled: startedBy, Outcome: outcomeOpen}
			t.lastSaved = 0
		} else if t.open.Scheduled == "" && startedBy != "" && now-t.open.Start < 60 {
			t.open.Scheduled = startedBy
		}
		// Re-derived every tick: after a reboot the end moves later,
		// since time powered off doesn't count towards a block
		t.open.PlannedEnd = now + st.remaining
		t.lastRemaining = st.remaining
		if now-t.lastSaved >= 60 {
			t.saveOpen()
			t.lastSaved = now
		}
		return
	}

	if t.open == nil {
		return
	}
	e := *t.open
	switch {
	case t.lastRemaining == 0 && now >= e.PlannedEnd:
		// Picked up after a restart with the block already over
		e.Outcome, e.End = outcomeCompleted, e.PlannedEnd
	case t.lastRemaining == 0:
		e.Outcome, e.End = outcomeInterrupted, now
	case t.lastRemaining <= int64(2*scheduleTick/time.Second):
		e.Outcome, e.End = outcomeCompleted, e.PlannedEnd
	default:
		e.Outcome, e.End = outcomeUnlocked, now
	}
	if e.End > e.Start {
		t.record(e)
	}
	t.open = nil
	t.lastRemaining = 0
	os.Remove(historyOpenFile)
}

func (t *historyTracker) saveOpen() {
	data, err := json.Marshal(t.open)
	if err != nil {
		return
	}
	os.MkdirAll("/var/lib/kblocker", 0755)
	tmp := historyOpenFile + ".tmp"
	if os.WriteFile(tmp, data, 0644) == nil {
		os.Rename(tmp, historyOpenFile)
	}
}

func appendHistory(e historyEntry) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	os.MkdirAll("/var/lib/kblocker", 0755)
	f, err := os.OpenFile(historyFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

func readHistory() []historyEntry {
	var out []historyEntry
	f, err := os.Open(historyFile)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e historyEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Start > 0 {
			out = append(out, e)
		}
	}
	return out
}

func doHistory(args []string) {
	entries := readHistory()
	if len(args) > 0 && args[0] == "--json" {
		if entries == nil {
			entries = []historyEntry{}
		}
		json.NewEncoder(os.Stdout).Encode(entries)
		return
	}
	if len(entries) == 0 {
		fmt.Println("No blocks recorded yet.")
		fmt.Println("  History is recorded by kblocker-scheduler.service.")
		return
	}

	var total time.Duration
	completed := 0
	for _, e := range entries {
		total += time.Duration(e.End-e.Start) * time.Second
		if e.Outcome == outcomeCompleted {
			completed++
		}
	}
	start := len(entries) - 20
	if start < 0 {
		start = 0
	}
	for _, e := range entries[start:] {
		from := time.Unix(e.Start, 0)
		label := e.Scheduled
		if label == "" {
			label = "manual"
		}
		fmt.Printf("%s  %s-%s  %-7s  %-11s  %s\n", from.Format("Mon Jan _2"), from.Format("15:04"),
			time.Unix(e.End, 0).Format("15:04"), formatHM(time.Duration(e.End-e.Start)*time.Second), e.Outcome, label)
	}
	fmt.Printf("\n%d blocks, %s blocked, %d%% ran to the end.\n", len(entries), formatHM(total), completed*100/len(entries))
}

func formatHM(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%02dm", h, m)
}
