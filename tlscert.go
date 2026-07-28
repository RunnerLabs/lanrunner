package main

// A self-signed certificate for the guest gateway.
//
// This exists for one reason: phones. iOS gives no way to open a downloaded
// HTML file as a real page — the Files app previews it in Quick Look, which
// sandboxes scripts and blocks the network — so a phone guest has to load the
// page from this machine over the network instead. Safari only exposes
// crypto.subtle in a secure context, and a plain http:// LAN address is not
// one, so the gateway has to speak TLS for the encrypted session to be
// possible at all.
//
// The certificate is unavoidably unvouched: there is no certificate authority
// on an offline LAN, and the whole point of Lan Runner is that it works without
// the internet. Browsers therefore warn once before the guest proceeds. The
// connection is genuinely encrypted; the warning only says nobody has vouched
// for the name. The operator can read the fingerprint aloud to a guest who
// wants to confirm it, which is the same out-of-band check the app already uses
// for peer safety numbers.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const guestCertLifetime = 2 * 365 * 24 * time.Hour

// guestCert is a loaded certificate plus the fingerprint we show the operator.
type guestCert struct {
	tls         tls.Certificate
	fingerprint string
	hosts       []string
	notAfter    time.Time
}

// loadOrCreateGuestCert reuses the stored certificate when it still covers
// every address we might be reached on, and regenerates it otherwise. Keeping
// it stable matters: a guest who accepted the certificate once should not be
// re-prompted on every restart.
func loadOrCreateGuestCert(dir string) (*guestCert, error) {
	certPath := filepath.Join(dir, "guest-cert.pem")
	keyPath := filepath.Join(dir, "guest-key.pem")
	wanted := certHosts()

	if c, err := readGuestCert(certPath, keyPath); err == nil {
		if c.covers(wanted) && time.Until(c.notAfter) > 30*24*time.Hour {
			return c, nil
		}
	}

	certPEM, keyPEM, err := generateGuestCert(wanted)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return readGuestCert(certPath, keyPath)
}

func readGuestCert(certPath, keyPath string) (*guestCert, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf

	sum := sha256.Sum256(leaf.Raw)
	var parts []string
	hexSum := hex.EncodeToString(sum[:])
	for i := 0; i+2 <= len(hexSum) && i < 16; i += 2 {
		parts = append(parts, strings.ToUpper(hexSum[i:i+2]))
	}

	hosts := make([]string, 0, len(leaf.IPAddresses)+len(leaf.DNSNames))
	for _, ip := range leaf.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	hosts = append(hosts, leaf.DNSNames...)

	return &guestCert{
		tls:         pair,
		fingerprint: strings.Join(parts, ":"),
		hosts:       hosts,
		notAfter:    leaf.NotAfter,
	}, nil
}

func (c *guestCert) covers(wanted []string) bool {
	have := map[string]bool{}
	for _, h := range c.hosts {
		have[h] = true
	}
	for _, w := range wanted {
		if !have[w] {
			return false
		}
	}
	return true
}

// certHosts is every name and address a guest might use to reach us.
func certHosts() []string {
	out := []string{"localhost", "127.0.0.1"}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true}
	for _, ip := range localIPs() {
		if ip == "none" || ip == "unknown" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// ---------------------------------------------------------------- scheme guard

// Reaching an HTTPS port over plain http produces Go's bare "client sent an
// HTTP request to an HTTPS server" text, which tells a guest nothing useful.
// It is an easy mistake to make: typing an address into a phone browser gets
// http:// by default, and the guest port is exactly the sort of thing people
// type by hand.
//
// splitByScheme peeks at the first byte of every connection. A TLS handshake
// always begins 0x16, so anything else is plaintext and gets redirected to the
// same URL over https instead of an error.
type schemeConn struct {
	net.Conn
	prefix []byte
}

func (c *schemeConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// handoffListener hands connections to whichever server should own them.
type handoffListener struct {
	conns chan net.Conn
	addr  net.Addr
	done  chan struct{}
}

func newHandoffListener(addr net.Addr) *handoffListener {
	return &handoffListener{conns: make(chan net.Conn, 8), addr: addr, done: make(chan struct{})}
}

func (l *handoffListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handoffListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *handoffListener) Addr() net.Addr { return l.addr }

func (l *handoffListener) offer(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// splitByScheme returns one listener for real TLS traffic and one for plaintext
// mistakes, both fed from the same socket.
func splitByScheme(ln net.Listener) (tlsSide, plainSide *handoffListener) {
	tlsSide = newHandoffListener(ln.Addr())
	plainSide = newHandoffListener(ln.Addr())

	go func() {
		defer ln.Close()
		for {
			raw, err := ln.Accept()
			if err != nil {
				tlsSide.Close()
				plainSide.Close()
				return
			}
			go func(raw net.Conn) {
				_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
				first := make([]byte, 1)
				n, err := raw.Read(first)
				if err != nil || n == 0 {
					_ = raw.Close()
					return
				}
				_ = raw.SetReadDeadline(time.Time{})

				wrapped := &schemeConn{Conn: raw, prefix: first[:n]}
				if first[0] == 0x16 { // TLS handshake record
					tlsSide.offer(wrapped)
				} else {
					plainSide.offer(wrapped)
				}
			}(raw)
		}
	}()

	return tlsSide, plainSide
}

// redirectToHTTPS sends a plaintext caller to the same address over https.
func redirectToHTTPS(port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := fmt.Sprintf("https://%s:%d%s", host, port, r.URL.RequestURI())
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
}

func generateGuestCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Lan Runner guest gateway",
			Organization: []string{"Lan Runner"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(guestCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if certPEM == nil || keyPEM == nil {
		return nil, nil, fmt.Errorf("could not encode the generated certificate")
	}
	return certPEM, keyPEM, nil
}
