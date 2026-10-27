package main

import (
	"testing"
	"time"
)

func TestWindows(t *testing.T) {
	s := &schedule{Blocks: []scheduleBlock{
		{ID: "a", Name: "am", Days: []int{1, 2, 3, 4, 5}, Start: "09:00", End: "12:00", Enabled: true},
		{ID: "b", Name: "pm", Days: []int{1, 2, 3, 4, 5}, Start: "13:00", End: "17:00", Enabled: true},
		{ID: "n", Name: "night", Days: []int{5}, Start: "23:00", End: "02:00", Enabled: true},
	}}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	loc := time.Local
	cases := []struct {
		at  time.Time
		ok  bool
		end string
	}{
		{time.Date(2026, 10, 26, 9, 0, 0, 0, loc), true, "12:00"}, // Mon
		{time.Date(2026, 10, 26, 12, 0, 0, 0, loc), false, ""},
		{time.Date(2026, 10, 26, 12, 30, 0, 0, loc), false, ""},
		{time.Date(2026, 10, 26, 16, 59, 0, 0, loc), true, "17:00"},
		{time.Date(2026, 10, 31, 10, 0, 0, 0, loc), false, ""},      // Sat
		{time.Date(2026, 10, 30, 23, 30, 0, 0, loc), true, "02:00"}, // Fri night
		{time.Date(2026, 10, 31, 1, 30, 0, 0, loc), true, "02:00"},  // into Sat
		{time.Date(2026, 10, 31, 2, 0, 0, 0, loc), false, ""},
	}
	for _, c := range cases {
		w, ok := s.activeWindow(c.at)
		if ok != c.ok || (ok && w.End.Format("15:04") != c.end) {
			t.Errorf("%v: got %v %v", c.at, ok, w.End)
		}
	}
}
