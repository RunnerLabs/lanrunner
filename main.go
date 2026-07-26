// Lanrunner — an offline, serverless messenger for a single local network.
//
// No internet, no accounts, no central server. Devices find each other by UDP
// broadcast and multicast, then hold long-lived TCP sessions encrypted with
// AES-256-GCM over an X25519 key exchange and authenticated by Ed25519
// identity keys. The UI is plain HTML and bare-bones CSS, served on loopback.
//
// Build:  go build -o lanrunner .
// Run:    ./lanrunner -nick alice
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	protoVersion  = 2
	appName       = "Lanrunner"
	announceEvery = 3 * time.Second
	peerTimeout   = 15 * time.Second
	logRingSize   = 500
	maxBodyRunes  = 2048
	clockSkew     = 120 * time.Second // announce freshness window
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v != "" {
		*s = append(*s, v)
	}
	return nil
}

var (
	flagNick      = flag.String("nick", "", "display name (default: hostname)")
	flagUI        = flag.Int("ui", 8080, "loopback UI port")
	flagDisco     = flag.Int("disco", 47100, "UDP discovery port — must match on every device")
	flagData      = flag.String("data", "", "data directory for keys, trust store and history")
	flagNoMc      = flag.Bool("no-multicast", false, "disable the multicast discovery channel")
	flagSeeds     stringList
	flagVerbose   = flag.Bool("v", false, "log every heartbeat frame too")
	flagNoBrowser = flag.Bool("no-browser", false, "do not open the local web UI automatically")
	flagIdle      = flag.Duration("idle", 30*time.Minute, "shut down after this much inactivity (0 disables)")
)

type runtimeState struct {
	Port int `json:"port"`
}

func startupFatal(dataDir, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	logPath := ""
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0700); err == nil {
			logPath = filepath.Join(dataDir, "startup.log")
			if logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
				_, _ = fmt.Fprintf(logFile, "%s  %s\n", time.Now().Format(time.RFC3339), message)
				_ = logFile.Close()
			}
		}
	}

	detail := message
	if logPath != "" {
		detail += "\n\nStartup log:\n" + logPath
	}
	fmt.Fprintln(os.Stderr, "fatal:", message)
	showStartupError(detail)
}

func lanrunnerAt(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	client := &http.Client{Timeout: 500 * time.Millisecond}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return err == nil &&
		strings.Contains(strings.ToLower(string(body)), "<title>lanrunner")
}

func existingLanrunner(dataDir string, preferredPort int) (string, bool) {
	ports := []int{}
	statePath := filepath.Join(dataDir, "runtime.json")
	if content, err := os.ReadFile(statePath); err == nil {
		var state runtimeState
		if json.Unmarshal(content, &state) == nil {
			ports = append(ports, state.Port)
		}
	}
	ports = append(ports, preferredPort)

	seen := map[int]bool{}
	for _, port := range ports {
		if seen[port] {
			continue
		}
		seen[port] = true
		if lanrunnerAt(port) {
			return fmt.Sprintf("http://127.0.0.1:%d", port), true
		}
	}
	return "", false
}

// ---------------------------------------------------------------- peer table

type Peer struct {
	FP     string
	Nick   string
	IP     string
	Port   int
	EdPub  ed25519.PublicKey
	XPub   *ecdh.PublicKey
	First  time.Time
	Last   time.Time
	LastTS int64 // newest announce timestamp accepted, monotonic replay guard
	RTT    int64
	RxMsgs int
	TxMsgs int
	Bytes  int
	Flags  []string
	Direct bool // learned from its own signed announce, not from gossip
}

func (p *Peer) flag(f string) {
	for _, x := range p.Flags {
		if x == f {
			return
		}
	}
	p.Flags = append(p.Flags, f)
}

type peerView struct {
	FP       string   `json:"fp"`
	Short    string   `json:"short"`
	Safety   string   `json:"safety"`
	Nick     string   `json:"nick"`
	Addr     string   `json:"addr"`
	Age      string   `json:"age"`
	Idle     int64    `json:"idle"`
	RTT      int64    `json:"rtt"`
	Rx       int      `json:"rx"`
	Tx       int      `json:"tx"`
	Bytes    int      `json:"bytes"`
	Online   bool     `json:"online"`
	Verified bool     `json:"verified"`
	Trust    string   `json:"trust"`
	Flags    []string `json:"flags"`
}

// ---------------------------------------------------------------- UI payloads

type LogLine struct {
	TS    string `json:"ts"`
	Level string `json:"level"` // SYS NET PKT SEC CRY
	Src   string `json:"src"`
	Text  string `json:"text"`
}

type ChatMsg struct {
	TS   string `json:"ts"`
	Conv string `json:"conv"` // "room" or a peer fingerprint
	MID  string `json:"mid"`
	FP   string `json:"fp"`
	Nick string `json:"nick"`
	Self bool   `json:"self"`
	Body string `json:"body"`
	Enc  string `json:"enc"` // human-readable cipher note
}

type IdentityView struct {
	Nick   string `json:"nick"`
	FP     string `json:"fp"`
	Short  string `json:"short"`
	Safety string `json:"safety"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Disco  int    `json:"disco"`
	Boot   string `json:"boot"`
	Data   string `json:"data"`
}

// ---------------------------------------------------------------- application

type App struct {
	id      *Identity
	trust   *TrustStore
	hist    *History
	diag    *Diag
	dataDir string

	tcpPort   int
	discoPort int
	multicast bool
	seeds     []string
	boot      time.Time
	verbose   bool

	mu     sync.Mutex
	nick   string
	peers  map[string]*Peer
	conns  map[string]*Conn
	msgSeq uint64

	submu sync.Mutex
	subs  map[chan []byte]bool

	logmu sync.Mutex
	ring  []LogLine

	udp *net.UDPConn // send-side socket for announcements

	lastActivity atomic.Int64
	shutdownOnce sync.Once
	shutdown     chan string
}

func (a *App) touchActivity() {
	a.lastActivity.Store(time.Now().UnixNano())
}

func (a *App) requestShutdown(reason string) {
	a.shutdownOnce.Do(func() {
		a.emit("shutdown", map[string]any{"reason": reason})
		time.AfterFunc(250*time.Millisecond, func() {
			a.shutdown <- reason
		})
	})
}

func (a *App) idleLoop() {
	timeout := *flagIdle
	if timeout <= 0 {
		return
	}
	interval := time.Minute
	if timeout < interval {
		interval = timeout / 4
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		last := time.Unix(0, a.lastActivity.Load())
		if time.Since(last) >= timeout {
			a.logf("SYS", "local", "idle for %s — shutting down and releasing the UI port", timeout)
			a.requestShutdown(fmt.Sprintf("%s of inactivity", timeout))
			return
		}
	}
}

func main() {
	flag.Var(&flagSeeds, "peer", "seed a peer by address when broadcast is blocked (repeatable): -peer 192.168.1.42")
	flag.Parse()

	dataDir := *flagData
	if dataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil || base == "" {
			home, _ := os.UserHomeDir()
			base = home
		}
		dataDir = filepath.Join(base, "lanrunner")
	}

	if url, running := existingLanrunner(dataDir, *flagUI); running {
		fmt.Printf("%s is already running at %s\n", appName, url)
		if !*flagNoBrowser {
			_ = openBrowser(url)
		}
		return
	}

	uiListener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *flagUI))
	if err != nil {
		uiListener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			startupFatal(dataDir, "cannot open local web interface: %v", err)
			return
		}
		*flagUI = uiListener.Addr().(*net.TCPAddr).Port
	}
	defer uiListener.Close()

	id, fresh, err := LoadOrCreateIdentity(filepath.Join(dataDir, "identity.json"))
	if err != nil {
		startupFatal(dataDir, "cannot load or create the local identity: %v", err)
		return
	}

	host, _ := os.Hostname()
	nick := *flagNick
	if nick == "" {
		nick = host
	}
	if nick == "" {
		nick = "anon"
	}

	app := &App{
		id:        id,
		trust:     LoadTrustStore(filepath.Join(dataDir, "known_peers.json")),
		hist:      OpenHistory(filepath.Join(dataDir, "history")),
		dataDir:   dataDir,
		nick:      sanitizeNick(nick),
		discoPort: *flagDisco,
		multicast: !*flagNoMc,
		seeds:     flagSeeds,
		boot:      time.Now(),
		verbose:   *flagVerbose,
		peers:     map[string]*Peer{},
		conns:     map[string]*Conn{},
		subs:      map[chan []byte]bool{},
		shutdown:  make(chan string, 1),
	}
	app.touchActivity()
	app.diag = NewDiag(app)
	runtimePath := filepath.Join(dataDir, "runtime.json")
	if content, err := json.Marshal(runtimeState{Port: *flagUI}); err == nil {
		if err := os.WriteFile(runtimePath, content, 0600); err == nil {
			defer os.Remove(runtimePath)
		}
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		startupFatal(dataDir, "cannot open TCP transport: %v", err)
		return
	}
	app.tcpPort = ln.Addr().(*net.TCPAddr).Port

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		startupFatal(dataDir, "cannot open UDP send socket: %v", err)
		return
	}
	app.udp = udp

	app.logf("SYS", "local", "%s boot — protocol v%d, pid %d", appName, protoVersion, os.Getpid())
	if fresh {
		app.logf("CRY", "local", "generated a new Ed25519 identity and X25519 static key in %s", dataDir)
	} else {
		app.logf("CRY", "local", "loaded existing identity from %s", dataDir)
	}
	app.logf("CRY", "local", "fingerprint %s", SafetyNumber(id.FP))
	app.logf("SYS", "local", "display name %q — trust store holds %d known peers", app.nick, app.trust.Count())
	app.logf("NET", "local", "TCP transport listening on 0.0.0.0:%d", app.tcpPort)
	app.logf("SYS", "local", "local addresses: %s", strings.Join(localIPs(), ", "))
	if len(app.seeds) > 0 {
		app.logf("NET", "local", "manual seeds: %s", strings.Join(app.seeds, ", "))
	}

	go app.acceptLoop(ln)
	go app.listenBroadcast()
	if app.multicast {
		go app.listenMulticast()
	}
	go app.announceLoop()
	go app.maintenanceLoop()
	go app.diag.Run()
	go app.idleLoop()

	mux := http.NewServeMux()
	app.routes(mux)
	srv := &http.Server{Handler: mux}
	go func() {
		app.logf("SYS", "local", "UI bound to http://127.0.0.1:%d (loopback only)", *flagUI)
		if err := srv.Serve(uiListener); err != nil && err != http.ErrServerClosed {
			app.logf("SYS", "local", "UI server stopped: %v", err)
		}
	}()

	fmt.Printf("\n  %s ready — open http://127.0.0.1:%d\n  your fingerprint: %s\n\n",
		appName, *flagUI, SafetyNumber(id.FP))
	if !*flagNoBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := openBrowser(fmt.Sprintf("http://127.0.0.1:%d", *flagUI)); err != nil {
				app.logf("SYS", "local", "could not open the web UI automatically: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	shutdownReason := "system interrupt"
	select {
	case <-stop:
	case shutdownReason = <-app.shutdown:
	}
	signal.Stop(stop)

	app.logf("SYS", "local", "shutdown (%s) — announcing departure and closing sessions", shutdownReason)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
	app.sendBye()
	app.closeAllConns()
	app.hist.Close()
	time.Sleep(150 * time.Millisecond)
}

// ---------------------------------------------------------------- fan-out

func (a *App) emit(kind string, data any) {
	b, err := jsonEnvelope(kind, data)
	if err != nil {
		return
	}
	a.submu.Lock()
	for ch := range a.subs {
		select {
		case ch <- b:
		default: // never let a stalled browser tab back-pressure the network
		}
	}
	a.submu.Unlock()
}

func (a *App) logf(level, src, format string, args ...any) {
	l := LogLine{TS: stamp(), Level: level, Src: src, Text: fmt.Sprintf(format, args...)}
	fmt.Printf("%s  %-3s  %-24s %s\n", l.TS, l.Level, src, l.Text)

	a.logmu.Lock()
	a.ring = append(a.ring, l)
	if len(a.ring) > logRingSize {
		a.ring = a.ring[len(a.ring)-logRingSize:]
	}
	a.logmu.Unlock()

	a.emit("log", l)
}

func (a *App) vlogf(level, src, format string, args ...any) {
	if a.verbose {
		a.logf(level, src, format, args...)
	}
}

func (a *App) pushPeers() {
	a.mu.Lock()
	views := make([]peerView, 0, len(a.peers))
	for _, p := range a.peers {
		_, online := a.conns[p.FP]
		trust := "OK"
		if len(p.Flags) > 0 {
			trust = "SUSPECT"
		}
		views = append(views, peerView{
			FP:       p.FP,
			Short:    shortFP(p.FP),
			Safety:   SafetyNumber(p.FP),
			Nick:     p.Nick,
			Addr:     net.JoinHostPort(p.IP, strconv.Itoa(p.Port)),
			Age:      dur(time.Since(p.First)),
			Idle:     int64(time.Since(p.Last).Seconds()),
			RTT:      p.RTT,
			Rx:       p.RxMsgs,
			Tx:       p.TxMsgs,
			Bytes:    p.Bytes,
			Online:   online,
			Verified: a.trust.IsVerified(p.FP),
			Trust:    trust,
			Flags:    append([]string(nil), p.Flags...),
		})
	}
	a.mu.Unlock()
	sort.Slice(views, func(i, j int) bool {
		if views[i].Online != views[j].Online {
			return views[i].Online
		}
		return strings.ToLower(views[i].Nick) < strings.ToLower(views[j].Nick)
	})
	a.emit("peers", views)
}

func (a *App) currentNick() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nick
}

// maintenanceLoop drops stale peers, dials anyone we know but aren't connected
// to, and refreshes the UI.
func (a *App) maintenanceLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		var stale []Peer
		var dial []Peer

		a.mu.Lock()
		for fp, p := range a.peers {
			_, online := a.conns[fp]
			if time.Since(p.Last) > peerTimeout && !online {
				delete(a.peers, fp)
				stale = append(stale, *p)
				continue
			}
			if !online && time.Since(p.Last) < peerTimeout && p.Port > 0 {
				dial = append(dial, *p)
			}
		}
		a.mu.Unlock()

		for _, p := range stale {
			a.logf("NET", net.JoinHostPort(p.IP, strconv.Itoa(p.Port)),
				"PEER DOWN %s (%s) — no announce for %ds", p.Nick, shortFP(p.FP), int(peerTimeout.Seconds()))
		}
		for _, p := range dial {
			go a.dialPeer(p)
		}
		a.pushPeers()
	}
}

// ---------------------------------------------------------------- helpers

func stamp() string { return time.Now().Format("15:04:05.000") }

func nowMS() int64 { return time.Now().UnixMilli() }

func shortFP(fp string) string {
	if len(fp) <= 8 {
		return fp
	}
	return fp[:8]
}

func dur(d time.Duration) string {
	s := int(d.Seconds())
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm%02ds", s/60, s%60)
	default:
		return fmt.Sprintf("%dh%02dm", s/3600, (s%3600)/60)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func hexPreview(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", b[i])
	}
	if len(b) > n {
		sb.WriteString(" ..")
	}
	return sb.String()
}

func sanitizeNick(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '<' || r == '>' || r == '|' {
			return -1
		}
		return r
	}, s)
	if len([]rune(s)) > 24 {
		s = string([]rune(s)[:24])
	}
	return s
}

// sanitizeBody strips control characters — terminal-escape injection is a real
// concern for anything rendering into a console — and reports whether any were
// present.
func sanitizeBody(s string) (string, bool) {
	found := false
	out := strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			found = true
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(out), found
}

func localIPs() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"unknown"}
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "none")
	}
	return out
}

func primaryIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() {
			continue
		}
		if ip4 := ipn.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return "127.0.0.1"
}

func isLocalIP(ip string) bool {
	for _, l := range localIPs() {
		if l == ip {
			return true
		}
	}
	return ip == "127.0.0.1"
}
