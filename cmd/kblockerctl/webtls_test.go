package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testWebCert(t *testing.T) *webCert {
	dir := t.TempDir()
	return loadWebCert(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
}

func TestSniffListenerServesTLSAndPlainOnOnePort(t *testing.T) {
	cert := testWebCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sl := newSniffListener(ln, &tls.Config{GetCertificate: cert.get})
	defer sl.Close()
	go http.Serve(sl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "tls=%v", r.TLS != nil)
	}))
	addr := ln.Addr().String()

	get := func(c *http.Client, url string) string {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	if got := get(http.DefaultClient, "http://"+addr+"/"); got != "tls=false" {
		t.Errorf("plain http: got %q", got)
	}

	// trust only the certificate the listener hands out, checking it names 127.0.0.1
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	if got := get(client, "https://"+addr+"/"); got != "tls=true" {
		t.Errorf("https: got %q", got)
	}

	// a client that connects and says nothing doesn't hold up others
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	if got := get(http.DefaultClient, "http://"+addr+"/"); got != "tls=false" {
		t.Errorf("plain http beside an idle connection: got %q", got)
	}
}

func TestSniffListenerCloseEndsServe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sl := newSniffListener(ln, &tls.Config{})
	done := make(chan error, 1)
	go func() { done <- http.Serve(sl, http.NotFoundHandler()) }()
	sl.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("http.Serve still running after Close")
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	h := redirectToHTTPS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	cases := []struct {
		host     string
		port     int
		tls      bool
		location string // empty: served, not redirected
	}{
		{"192.168.1.5:8737", 8737, false, "https://192.168.1.5:8737/unblock?x=1"},
		{"192.168.1.5", 80, false, "https://192.168.1.5:80/unblock?x=1"},
		{"192.168.1.5", 443, false, "https://192.168.1.5/unblock?x=1"},
		{"[fd00::1]:8737", 8737, false, "https://[fd00::1]:8737/unblock?x=1"},
		{"192.168.1.5:8737", 8737, true, ""},
		{"127.0.0.1:8737", 8737, false, ""},
		{"localhost:8737", 8737, false, ""},
		{"[::1]:8737", 8737, false, ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/unblock?x=1", nil)
		r.Host = c.host
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{Port: c.port}))
		if !c.tls {
			r.TLS = nil
		} else {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if c.location == "" {
			if w.Code != http.StatusTeapot {
				t.Errorf("%s tls=%v: got %d, want it served", c.host, c.tls, w.Code)
			}
			continue
		}
		if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != c.location {
			t.Errorf("%s port %d: got %d to %q, want redirect to %q", c.host, c.port, w.Code, w.Header().Get("Location"), c.location)
		}
	}
}

func TestWebCertKeptAcrossRestartsAndRenewed(t *testing.T) {
	cert := testWebCert(t)
	lan := net.ParseIP("192.0.2.10")
	first, err := cert.ensure(lan)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Leaf.VerifyHostname("192.0.2.10"); err != nil {
		t.Errorf("certificate doesn't name the address it was made for: %v", err)
	}
	if err := first.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("certificate doesn't name localhost: %v", err)
	}
	if info, err := os.Stat(cert.keyPath); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("private key file: %v, mode %v", err, info.Mode().Perm())
	}

	// a restart loads the same certificate, so devices needn't accept a new one
	reloaded := loadWebCert(cert.certPath, cert.keyPath)
	again, err := reloaded.ensure(lan)
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(again.Leaf) != certFingerprint(first.Leaf) {
		t.Error("certificate replaced on reload")
	}

	// a new address gets a certificate naming it
	moved, err := reloaded.ensure(net.ParseIP("192.0.2.77"))
	if err != nil {
		t.Fatal(err)
	}
	if err := moved.Leaf.VerifyHostname("192.0.2.77"); err != nil {
		t.Errorf("certificate not renewed for a new address: %v", err)
	}

	// and one near expiry is replaced
	if certFits(moved.Leaf, nil, moved.Leaf.NotAfter.Add(-webCertRenew/2)) {
		t.Error("certificate expiring within the renewal window still fits")
	}
	if !certFits(moved.Leaf, nil, time.Now()) {
		t.Error("fresh certificate doesn't fit")
	}
	if life := moved.Leaf.NotAfter.Sub(moved.Leaf.NotBefore); life > 398*24*time.Hour {
		t.Errorf("certificate valid for %v, over Apple's 398-day limit", life)
	}
}

func TestPagesURL(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8737":    "http://127.0.0.1:8737",
		"[::1]:8737":        "http://[::1]:8737",
		"0.0.0.0:8737":      "https://0.0.0.0:8737",
		"192.168.1.5:8737":  "https://192.168.1.5:8737",
		"[fd00::1]:8737":    "https://[fd00::1]:8737",
		"localhost:8737":    "http://localhost:8737",
		"100.64.0.10:18737": "https://100.64.0.10:18737",
	} {
		if got := pagesURL(addr); got != want {
			t.Errorf("pagesURL(%q) = %q, want %q", addr, got, want)
		}
	}
}
