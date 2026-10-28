package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The installers block the same starter list that reset restores
func TestDefaultDomainsMatchInstallers(t *testing.T) {
	re := regexp.MustCompile(`kblockerctl block ((?:[a-z0-9.-]+[\s\\]+)+)`)
	for _, path := range []string{"../../Makefile", "../../debian/postinst"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(data)
		if m == nil {
			t.Fatalf("%s: no kblockerctl block line", path)
		}
		got := strings.Fields(strings.ReplaceAll(string(m[1]), "\\", " "))
		if !slices.Equal(got, defaultDomains) {
			t.Errorf("%s blocks %v, reset restores %v", path, got, defaultDomains)
		}
	}
}
