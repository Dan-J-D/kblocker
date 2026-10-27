package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The key-creation and unblock pages, served by add-pgp-web, unblock-web
// and the scheduler daemon. OpenPGP.js is embedded so the pages work
// offline and never load code that handles private keys from a CDN.

//go:embed assets/openpgp.min.js
var openpgpJS []byte

const defaultWebAddr = "127.0.0.1:8737"

// newWebMux serves both pages; root picks which one "/" shows.
func newWebMux(root string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		switch root {
		case "keys":
			serveIndex(w, r)
		case "unblock":
			serveUnblockIndex(w, r)
		default:
			serveWebHome(w, r)
		}
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/"
		serveIndex(w, r)
	})
	mux.HandleFunc("/unblock", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/"
		serveUnblockIndex(w, r)
	})
	mux.HandleFunc("/openpgp.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(openpgpJS)
	})
	mux.HandleFunc("/api/status", handleAPISStatus)
	mux.HandleFunc("/api/keys", handleAddKeyOnly)
	mux.HandleFunc("/api/ciphertext-by-key", handleAPICiphertextByKey)
	mux.HandleFunc("/api/unblock", handleAPIUnblock)
	return mux
}

// withSameOrigin refuses requests a web page on another origin could make
// through the visitor's browser (adding a key holder, then reading back
// their ciphertext, is enough to end a block), and Host names that point
// a rebinding domain at this server.
func withSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "localhost" && net.ParseIP(strings.Trim(host, "[]")) == nil {
			http.Error(w, "Use the server's IP address or localhost", http.StatusMisdirectedRequest)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
				http.Error(w, "Cross-origin requests are not allowed", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// startDaemonWeb hosts the pages from the scheduler daemon. KBLOCKER_WEB
// sets the listen address ("off" disables it).
func startDaemonWeb() {
	addr := getEnvDefault("KBLOCKER_WEB", defaultWebAddr)
	if addr == "off" {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("web pages disabled: %v", err)
		return
	}
	log.Printf("key and unblock pages on http://%s/keys and http://%s/unblock", addr, addr)
	go func() {
		if err := http.Serve(ln, withSameOrigin(newWebMux(""))); err != nil {
			log.Printf("web server stopped: %v", err)
		}
	}()
}

const webHomeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>kblocker</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 560px; margin: 40px auto; }
h1 { color: #58a6ff; margin-bottom: 8px; }
p { color: #8b949e; margin-bottom: 24px; }
a { display: block; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin-bottom: 12px; color: #c9d1d9; text-decoration: none; }
a:hover { border-color: #58a6ff; }
a strong { display: block; color: #58a6ff; }
a span { font-size: 14px; color: #8b949e; }
</style>
</head>
<body>
<div class="container">
  <h1>kblocker</h1>
  <p>Pages for key holders. Private keys stay in your browser.</p>
  <a href="/keys"><strong>Create a key</strong><span>Make a PGP key pair and register its public half as a key holder.</span></a>
  <a href="/unblock"><strong>Unblock</strong><span>Decrypt the unload key with your private key and end the current block.</span></a>
</div>
</body>
</html>`

func serveWebHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(webHomeHTML))
}

// Where the scheduler service hosts the pages is set by a drop-in, so the
// setting survives package upgrades replacing the unit file.
const (
	schedulerUnit = "kblocker-scheduler.service"
	webDropIn     = "/etc/systemd/system/kblocker-scheduler.service.d/web.conf"
)

// currentWebAddr reports the KBLOCKER_WEB the scheduler service runs with.
func currentWebAddr() string {
	out, err := exec.Command("systemctl", "show", "--property=Environment", "--value", schedulerUnit).Output()
	if err == nil {
		for _, kv := range strings.Fields(string(out)) {
			if v, ok := strings.CutPrefix(kv, "KBLOCKER_WEB="); ok {
				return v
			}
		}
	}
	return defaultWebAddr
}

// splitWebAddr splits a KBLOCKER_WEB value into host and port, falling back
// to the default address when the pages are off or the value is malformed.
func splitWebAddr(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port, _ = net.SplitHostPort(defaultWebAddr)
	}
	return host, port
}

// listenPages opens the listener for add-pgp-web and unblock-web. Without
// --bind or --port they use the address saved with web-pages, and if the
// scheduler service is already serving the pages there, point at it instead.
func listenPages(args []string, path string) (net.Listener, string) {
	saved := currentWebAddr()
	bind, port := splitWebAddr(saved)
	explicit := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			port, explicit = args[i+1], true
			i++
		} else if args[i] == "--bind" && i+1 < len(args) {
			bind, explicit = args[i+1], true
			i++
		}
	}

	addr := net.JoinHostPort(bind, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if !explicit && saved != "off" && errors.Is(err, syscall.EADDRINUSE) {
			fmt.Printf("The scheduler service already hosts this page on http://%s%s\n", addr, path)
			os.Exit(0)
		}
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	return ln, bind
}

// doWebPages shows or changes where the scheduler service hosts the key
// holder pages: off, local (this computer only), lan (other devices too) or
// custom (a chosen address). The port is kept unless --port changes it.
func doWebPages(args []string) {
	if len(args) == 0 {
		fmt.Println(currentWebAddr())
		return
	}

	_, port := splitWebAddr(currentWebAddr())
	bind := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			port = args[i+1]
			i++
		} else if args[i] == "--bind" && i+1 < len(args) {
			bind = args[i+1]
			i++
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		fmt.Fprintf(os.Stderr, "%sError: invalid port %q%s\n", colorRed, port, colorNC)
		os.Exit(1)
	}

	var addr string
	switch args[0] {
	case "off":
		addr = "off"
	case "local":
		addr = net.JoinHostPort("127.0.0.1", port)
	case "lan":
		addr = net.JoinHostPort("0.0.0.0", port)
	case "custom":
		if net.ParseIP(bind) == nil {
			fmt.Fprintf(os.Stderr, "%sError: custom needs --bind <ip address>, got %q%s\n", colorRed, bind, colorNC)
			os.Exit(1)
		}
		addr = net.JoinHostPort(bind, port)
	default:
		fmt.Fprintf(os.Stderr, "%sError: expected off, local, lan or custom%s\n", colorRed, colorNC)
		os.Exit(1)
	}

	requiresRoot()
	if err := os.MkdirAll(filepath.Dir(webDropIn), 0755); err != nil {
		log.Fatalf("Failed to create %s: %v", filepath.Dir(webDropIn), err)
	}
	conf := "# Written by kblockerctl web-pages\n[Service]\nEnvironment=KBLOCKER_WEB=" + addr + "\n"
	if err := os.WriteFile(webDropIn, []byte(conf), 0644); err != nil {
		log.Fatalf("Failed to write %s: %v", webDropIn, err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Fatalf("systemctl daemon-reload failed: %v\n%s", err, out)
	}
	// try-restart leaves a stopped service stopped; the setting applies when it starts
	if out, err := exec.Command("systemctl", "try-restart", schedulerUnit).CombinedOutput(); err != nil {
		log.Fatalf("Failed to restart %s: %v\n%s", schedulerUnit, err, out)
	}

	switch args[0] {
	case "off":
		fmt.Println("Key holder pages turned off.")
	case "local":
		fmt.Printf("Key holder pages on http://%s (this computer only).\n", addr)
	case "lan":
		fmt.Printf("Key holder pages on port %s for every device on your network.\n", port)
	default:
		fmt.Printf("Key holder pages on http://%s.\n", addr)
	}
}
