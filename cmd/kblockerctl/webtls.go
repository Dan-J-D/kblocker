package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPS for the key holder pages once other devices can reach them.
// OpenPGP.js needs WebCrypto, which browsers only expose on https:// pages
// and on localhost, so over http://<LAN address> a key holder's phone can
// neither create a key nor decrypt one. Bound beyond loopback, the pages
// speak TLS and plain http on the same port: localhost stays on http, and
// plain requests for any other host are redirected to https. The
// certificate is self-signed, so each device asks once to accept it.

const (
	webCertFile = "/var/lib/kblocker/web-cert.pem"
	webKeyFile  = "/var/lib/kblocker/web-key.pem"
	// Apple platforms refuse server certificates valid for over 398 days
	webCertLifetime = 397 * 24 * time.Hour
	webCertRenew    = 30 * 24 * time.Hour
	// how long a new connection may stay silent before it's dropped
	sniffTimeout = 30 * time.Second
)

// servePages serves the key holder pages on ln until serving fails,
// adding TLS on the same port when ln listens beyond loopback.
func servePages(ln net.Listener, root string) error {
	h := http.Handler(newWebMux(root))
	if a, ok := ln.Addr().(*net.TCPAddr); ok && !a.IP.IsLoopback() {
		cert := loadWebCert(webCertFile, webKeyFile)
		var bindIP net.IP
		if !a.IP.IsUnspecified() {
			bindIP = a.IP
		}
		loaded := cert.cert
		// ensure logs new certificates; say which one is reused
		if c, err := cert.ensure(bindIP); err != nil {
			log.Printf("web pages: no certificate yet: %v", err)
		} else if c == loaded {
			log.Printf("web pages: certificate SHA-256 %s", certFingerprint(c.Leaf))
		}
		ln = newSniffListener(ln, &tls.Config{GetCertificate: cert.get, MinVersion: tls.VersionTLS12})
		h = redirectToHTTPS(h)
	}
	return http.Serve(ln, withSameOrigin(h))
}

// pagesURL is the address the pages are reached on: https unless they
// only listen on loopback.
func pagesURL(addr string) string {
	if isLoopbackHost(addr) {
		return "http://" + addr
	}
	return "https://" + addr
}

func isLoopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// redirectToHTTPS sends plain http requests for anything but localhost to
// https on the same port, where browsers let the pages use WebCrypto.
func redirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || isLoopbackHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		// the port the request arrived on, which a Host for port 80 leaves out
		port := "443"
		if a, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
			port = strconv.Itoa(a.Port)
		}
		target := net.JoinHostPort(strings.Trim(host, "[]"), port)
		target = strings.TrimSuffix(target, ":443")
		http.Redirect(w, r, "https://"+target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
}

// webCert is the pages' certificate, kept on disk so devices that accepted
// it keep it across restarts. It's replaced when it nears expiry or a
// device connects to an address it doesn't name, as when DHCP hands this
// computer a new one.
type webCert struct {
	certPath, keyPath string

	mu   sync.Mutex
	cert *tls.Certificate // Leaf is set
}

func loadWebCert(certPath, keyPath string) *webCert {
	c := &webCert{certPath: certPath, keyPath: keyPath}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return c
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err == nil {
		c.cert = &cert
	}
	return c
}

// get is the tls.Config GetCertificate hook.
func (c *webCert) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var ip net.IP
	if a, ok := hello.Conn.LocalAddr().(*net.TCPAddr); ok {
		ip = a.IP
	}
	return c.ensure(ip)
}

// ensure returns a current certificate that names ip (if set), replacing
// and saving the one it has when it doesn't.
func (c *webCert) ensure(ip net.IP) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && certFits(c.cert.Leaf, ip, time.Now()) {
		return c.cert, nil
	}
	ips := hostIPs()
	if ip != nil {
		ips = append(ips, ip)
	}
	cert, err := newWebCertificate(ips)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.cert = cert
	if err := c.save(); err != nil {
		log.Printf("web pages: certificate not saved, so devices will be asked to accept a new one after a restart: %v", err)
	}
	log.Printf("web pages: new certificate SHA-256 %s", certFingerprint(cert.Leaf))
	return cert, nil
}

func (c *webCert) save() error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.cert.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.keyPath), 0755); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(c.keyPath, keyPEM, 0600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Certificate[0]})
	return writeFileAtomic(c.certPath, certPEM, 0644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// certFits reports whether leaf is valid well past now and names ip.
func certFits(leaf *x509.Certificate, ip net.IP, now time.Time) bool {
	if now.Before(leaf.NotBefore) || now.Add(webCertRenew).After(leaf.NotAfter) {
		return false
	}
	return ip == nil || ip.IsUnspecified() || leaf.VerifyHostname(ip.String()) == nil
}

// hostIPs lists this computer's addresses, leaving out link-local ones,
// which page URLs can't use.
func hostIPs() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

func newWebCertificate(ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	var names []net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		dup := false
		for _, n := range names {
			dup = dup || n.Equal(ip)
		}
		if !dup {
			names = append(names, ip)
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kblocker key holder pages"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(webCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// certFingerprint is the SHA-256 fingerprint browsers show in a
// certificate's details, for checking the page reached is this computer.
func certFingerprint(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// sniffListener hands http.Serve both TLS and plain connections from one
// port, telling them apart by their first byte: a TLS handshake record
// starts with 0x16, an HTTP request with a letter. Each connection is
// sniffed on its own goroutine so a silent client can't hold up Accept.
type sniffListener struct {
	net.Listener
	config *tls.Config
	conns  chan net.Conn
	errs   chan error
	done   chan struct{}
	once   sync.Once
}

func newSniffListener(ln net.Listener, config *tls.Config) *sniffListener {
	s := &sniffListener{
		Listener: ln,
		config:   config,
		conns:    make(chan net.Conn),
		errs:     make(chan error),
		done:     make(chan struct{}),
	}
	go s.acceptLoop()
	return s
}

func (s *sniffListener) acceptLoop() {
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			// http.Serve decides whether to retry, as with a plain listener
			select {
			case s.errs <- err:
			case <-s.done:
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.sniff(c)
	}
}

func (s *sniffListener) sniff(c net.Conn) {
	var first [1]byte
	c.SetReadDeadline(time.Now().Add(sniffTimeout))
	if _, err := io.ReadFull(c, first[:]); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})

	var conn net.Conn = &peekedConn{Conn: c, r: io.MultiReader(bytes.NewReader(first[:]), c)}
	if first[0] == 0x16 {
		conn = tls.Server(conn, s.config)
	}
	select {
	case s.conns <- conn:
	case <-s.done:
		c.Close()
	}
}

func (s *sniffListener) Accept() (net.Conn, error) {
	select {
	case c := <-s.conns:
		return c, nil
	case err := <-s.errs:
		return nil, err
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *sniffListener) Close() error {
	s.once.Do(func() { close(s.done) })
	return s.Listener.Close()
}

// peekedConn replays the byte sniffListener read before the rest.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite lets http.Server half-close plain connections as it does TCP ones.
func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
