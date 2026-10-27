package main

import "testing"

func TestTrackerOutcomes(t *testing.T) {
	on := func(rem int64) moduleState {
		return moduleState{loaded: true, enabled: true, remaining: rem, pgp: true}
	}
	off := moduleState{loaded: true}
	run := func(steps func(tr *historyTracker)) []historyEntry {
		var got []historyEntry
		tr := &historyTracker{record: func(e historyEntry) { got = append(got, e) }, lastSaved: 1 << 60}
		steps(tr)
		return got
	}

	g := run(func(tr *historyTracker) {
		tr.observe(1000, on(600), "am")
		tr.observe(1597, on(3), "")
		tr.observe(1602, off, "")
	})
	if len(g) != 1 || g[0].Outcome != outcomeCompleted || g[0].End != 1600 || g[0].Scheduled != "am" || !g[0].Locked {
		t.Fatalf("ran to the end: %+v", g)
	}

	g = run(func(tr *historyTracker) {
		tr.observe(1000, on(600), "")
		tr.observe(1200, on(400), "")
		tr.observe(1205, off, "")
	})
	if len(g) != 1 || g[0].Outcome != outcomeUnlocked || g[0].End != 1205 {
		t.Fatalf("unlocked early: %+v", g)
	}

	// Powered off between 1200 and 5000: the planned end moves later
	g = run(func(tr *historyTracker) {
		tr.observe(1000, on(600), "")
		tr.observe(5000, on(300), "")
		tr.observe(5298, on(2), "")
		tr.observe(5303, off, "")
	})
	if len(g) != 1 || g[0].Outcome != outcomeCompleted || g[0].End != 5300 {
		t.Fatalf("restored after reboot: %+v", g)
	}

	g = run(func(tr *historyTracker) {
		tr.open = &historyEntry{Start: 1000, PlannedEnd: 1600, Outcome: outcomeOpen}
		tr.observe(2000, off, "")
	})
	if len(g) != 1 || g[0].Outcome != outcomeCompleted || g[0].End != 1600 {
		t.Fatalf("stale record, already over: %+v", g)
	}

	g = run(func(tr *historyTracker) {
		tr.open = &historyEntry{Start: 1000, PlannedEnd: 1600, Outcome: outcomeOpen}
		tr.observe(1300, off, "")
	})
	if len(g) != 1 || g[0].Outcome != outcomeInterrupted {
		t.Fatalf("stale record, cut short: %+v", g)
	}

	g = run(func(tr *historyTracker) { tr.observe(1000, on(600), ""); tr.observe(1005, moduleState{}, "") })
	if len(g) != 0 {
		t.Fatalf("module unloaded: %+v", g)
	}
}
