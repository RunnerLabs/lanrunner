package main

// Guest kits — invite someone who does not run Lanrunner.
//
// The operator generates a folder. The folder holds one self-contained HTML
// file with the connection details already baked in. Whoever receives that
// folder opens the file in a browser on the same local network and talks
// directly to the machine that generated it. Nothing is installed, nothing is
// downloaded at run time, and no traffic leaves the LAN.
//
// The guest browser cannot open raw TCP sockets, so it cannot speak the peer
// protocol in transport.go. Instead this file exposes a second, LAN-facing HTTP
// gateway that is deliberately much smaller than the peer transport:
//
//   - it exists only while at least one live invite exists;
//   - every request must carry an invite id and its 256-bit token;
//   - a guest reaches exactly one conversation — the invite's own — and can
//     never see the peer list, the console, diagnostics, or another invite;
//   - payloads are sealed with AES-256-GCM under a key agreed per session by
//     P-256 ECDH, with the invite token mixed into HKDF so that only a holder
//     of the folder can derive the key.
//
// The token is the authentication. Anyone who has the folder is the guest, so
// treat a generated folder like a password and revoke it when the conversation
// is over.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

//go:embed guestkit.html
var guestKitFS embed.FS

const (
	guestProtoVersion = 2
	guestSessionIdle  = 3 * time.Minute
	guestMaxSessions  = 4  // concurrent browser tabs per invite
	guestRateMax      = 30 // messages per window, per session
	guestRateWindow   = 10 * time.Second
	guestQueueDepth   = 256
	guestBacklog      = 80
	guestMaxFrame     = 64 << 10
	guestMaxInvites   = 64

	// Failed handshakes per source address before that address is made to wait.
	guestAuthFails  = 5
	guestAuthWindow = 2 * time.Minute
	guestAuthBanMax = 15 * time.Minute
)

// ---------------------------------------------------------------- anti-replay

// replayWindow is the standard IPsec-style sliding window: it accepts any
// sequence number newer than the last one seen, plus anything inside a 64-frame
// tail that has not already been used.
//
// AES-GCM proves a frame was authentic. It does not prove the frame is new — a
// captured POST can be sent again verbatim and would decrypt perfectly. The
// counter closes that gap. A plain "must increase" rule would be wrong here,
// because the guest page fires typing and message frames concurrently and the
// browser does not guarantee they arrive in order, so a window is needed rather
// than a high-water mark.
type replayWindow struct {
	max  uint64
	bits uint64
}

func (w *replayWindow) accept(seq uint64) bool {
	if seq == 0 {
		return false // counters start at 1; 0 means a client that never set one
	}
	if seq > w.max {
		if shift := seq - w.max; shift >= 64 {
			w.bits = 0
		} else {
			w.bits <<= shift
		}
		w.bits |= 1
		w.max = seq
		return true
	}
	behind := w.max - seq
	if behind >= 64 {
		return false // so old it has fallen out of the window
	}
	if w.bits&(1<<behind) != 0 {
		return false // already used — this is a replay
	}
	w.bits |= 1 << behind
	return true
}

// ---------------------------------------------------------------- auth throttle

// authThrottle slows down anyone spraying invite ids at the gateway. The token
// is 256 bits so guessing is hopeless, but without this an attacker could still
// burn CPU and flood the operator's security log indefinitely.
type authThrottle struct {
	mu   sync.Mutex
	fail map[string]*authFail
}

type authFail struct {
	n     int
	seen  time.Time
	until time.Time
}

func newAuthThrottle() *authThrottle {
	return &authThrottle{fail: map[string]*authFail{}}
}

// blocked reports whether this address is serving a timeout, and for how long.
func (t *authThrottle) blocked(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.fail[ip]
	if !ok {
		return false, 0
	}
	if wait := time.Until(rec.until); wait > 0 {
		return true, wait
	}
	return false, 0
}

// bad records a failure and returns the timeout now imposed, if any.
func (t *authThrottle) bad(ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.fail[ip]
	if !ok || time.Since(rec.seen) > guestAuthWindow {
		rec = &authFail{}
		t.fail[ip] = rec
	}
	rec.n++
	rec.seen = time.Now()
	if rec.n < guestAuthFails {
		return 0
	}
	backoff := 30 * time.Second << uint(rec.n-guestAuthFails)
	if backoff > guestAuthBanMax || backoff <= 0 {
		backoff = guestAuthBanMax
	}
	rec.until = time.Now().Add(backoff)
	return backoff
}

func (t *authThrottle) good(ip string) {
	t.mu.Lock()
	delete(t.fail, ip)
	t.mu.Unlock()
}

func (t *authThrottle) sweep() {
	t.mu.Lock()
	for ip, rec := range t.fail {
		if time.Since(rec.seen) > guestAuthWindow && time.Now().After(rec.until) {
			delete(t.fail, ip)
		}
	}
	t.mu.Unlock()
}

// ---------------------------------------------------------------- source policy

// allowedGuestSource keeps the gateway pointed at the local network. Lan Runner
// is a LAN tool; a guest connection arriving from a routable public address
// means either a misconfiguration or a port forward nobody intended, and in
// both cases refusing is the right answer.
func allowedGuestSource(host string) bool {
	if *flagGuestAny {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT, is what Tailscale and similar hand out.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	return false
}

// ---------------------------------------------------------------- invites

// Invite is one generated guest kit. Its ID doubles as the conversation id, so
// guest chat lands in the ordinary history and tab machinery alongside peers.
type Invite struct {
	ID         string `json:"id"`    // 16 hex chars — also the conversation id
	Token      string `json:"token"` // 64 hex chars — the shared secret
	Label      string `json:"label"`
	Folder     string `json:"folder"`
	Created    int64  `json:"created"`
	Expires    int64  `json:"expires,omitempty"` // 0 = never
	Revoked    bool   `json:"revoked"`
	AllowPlain bool   `json:"allow_plain"`
	LastNick   string `json:"last_nick,omitempty"`
	LastSeen   int64  `json:"last_seen,omitempty"`
}

// expired reports whether this invite has aged out. A leaked folder therefore
// stops being useful on its own, without the operator having to remember to
// revoke it.
func (in *Invite) expired() bool {
	return in.Expires > 0 && nowMS() > in.Expires
}

func (in *Invite) usable() bool { return !in.Revoked && !in.expired() }

// InviteView is what the operator's UI sees. The token never leaves the host.
type InviteView struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Folder   string `json:"folder"`
	Created  string `json:"created"`
	Expires  string `json:"expires"`
	Expired  bool   `json:"expired"`
	Revoked  bool   `json:"revoked"`
	Plain    bool   `json:"plain"`
	Online   int    `json:"online"`
	LastNick string `json:"last_nick"`
	LastSeen string `json:"last_seen"`
}

// ---------------------------------------------------------------- sessions

type guestSession struct {
	sid    string
	invite string
	remote string
	nick   string
	enc    bool
	h2g    cipher.AEAD
	g2h    cipher.AEAD

	ch      chan []byte
	created time.Time

	last        atomic.Int64
	streamGen   atomic.Int64
	sentBacklog atomic.Bool

	mu     sync.Mutex
	rateN  int
	rateAt time.Time
	replay replayWindow
	closed bool
}

func (s *guestSession) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *guestSession) idle() time.Duration {
	return time.Since(time.Unix(0, s.last.Load()))
}

// allow is a token-free leaky bucket: a runaway or hostile guest page cannot
// flood the operator's history.
func (s *guestSession) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.rateAt) > guestRateWindow {
		s.rateAt = now
		s.rateN = 0
	}
	s.rateN++
	return s.rateN <= guestRateMax
}

// fresh checks one frame's counter against the anti-replay window.
func (s *guestSession) fresh(seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replay.accept(seq)
}

// seal wraps one UI envelope for the wire. Encrypted sessions get a random
// 12-byte nonce prepended to the AES-256-GCM ciphertext; a plaintext session
// (only possible when the operator explicitly allowed it) sends the envelope
// as-is so the failure mode is visible rather than silent.
func (s *guestSession) seal(kind string, data any) ([]byte, error) {
	pt, err := jsonEnvelope(kind, data)
	if err != nil {
		return nil, err
	}
	if !s.enc {
		return json.Marshal(map[string]json.RawMessage{"p": json.RawMessage(pt)})
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.h2g.Seal(nonce, nonce, pt, nil)
	return json.Marshal(map[string]string{"f": base64.StdEncoding.EncodeToString(ct)})
}

func (s *guestSession) open(frame string, plain json.RawMessage) ([]byte, error) {
	if !s.enc {
		if len(plain) == 0 {
			return nil, errors.New("empty plaintext body")
		}
		return plain, nil
	}
	if frame == "" {
		return nil, errors.New("session is encrypted but the frame was sent in the clear")
	}
	raw, err := base64.StdEncoding.DecodeString(frame)
	if err != nil {
		return nil, errors.New("frame is not valid base64")
	}
	if len(raw) < 13 || len(raw) > guestMaxFrame {
		return nil, fmt.Errorf("frame length %dB is out of range", len(raw))
	}
	pt, err := s.g2h.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return nil, errors.New("AEAD authentication failed (tampered or wrong token)")
	}
	return pt, nil
}

func (s *guestSession) push(b []byte) {
	select {
	case s.ch <- b:
	default: // a stalled browser tab must never back-pressure the host
	}
}

// ---------------------------------------------------------------- hub

type GuestHub struct {
	app      *App
	path     string
	port     int
	throttle *authThrottle

	mu        sync.Mutex
	invites   map[string]*Invite
	order     []string
	announced map[string]bool                     // expiry already logged
	sessions  map[string]*guestSession            // sid -> session
	byInvite  map[string]map[string]*guestSession // invite id -> sid -> session

	srvMu   sync.Mutex
	srv     *http.Server
	ln      net.Listener
	running bool
}

func NewGuestHub(a *App, path string, port int) *GuestHub {
	h := &GuestHub{
		app:      a,
		path:     path,
		port:     port,
		throttle:  newAuthThrottle(),
		invites:   map[string]*Invite{},
		announced: map[string]bool{},
		sessions:  map[string]*guestSession{},
		byInvite:  map[string]map[string]*guestSession{},
	}
	h.load()
	return h
}

func (h *GuestHub) load() {
	b, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	var list []*Invite
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, in := range list {
		if in == nil || in.ID == "" || in.Token == "" {
			continue
		}
		h.invites[in.ID] = in
		h.order = append(h.order, in.ID)
	}
}

// saveLocked writes the invite file. The caller already holds h.mu.
func (h *GuestHub) saveLocked() {
	list := make([]*Invite, 0, len(h.invites))
	for _, id := range h.order {
		if in, ok := h.invites[id]; ok {
			list = append(list, in)
		}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(h.path), 0o700)
	_ = os.WriteFile(h.path, b, 0o600)
}

func (h *GuestHub) IsInvite(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.invites[id]
	return ok
}

// Label is the friendly name for a guest conversation, used by the operator UI
// and by log lines.
func (h *GuestHub) Label(id string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	in, ok := h.invites[id]
	if !ok {
		return shortFP(id)
	}
	if in.LastNick != "" {
		return in.LastNick
	}
	if in.Label != "" {
		return in.Label
	}
	return "guest " + shortFP(id)
}

func (h *GuestHub) liveCountLocked() int {
	n := 0
	for _, in := range h.invites {
		if in.usable() {
			n++
		}
	}
	return n
}

func (h *GuestHub) Views() []InviteView {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]InviteView, 0, len(h.invites))
	for _, id := range h.order {
		in, ok := h.invites[id]
		if !ok {
			continue
		}
		v := InviteView{
			ID:       in.ID,
			Label:    in.Label,
			Folder:   in.Folder,
			Created:  time.UnixMilli(in.Created).Format("2006-01-02 15:04"),
			Expired:  in.expired(),
			Revoked:  in.Revoked,
			Plain:    in.AllowPlain,
			Online:   len(h.byInvite[in.ID]),
			LastNick: in.LastNick,
		}
		if in.Expires > 0 {
			v.Expires = time.UnixMilli(in.Expires).Format("2006-01-02 15:04")
		}
		if in.LastSeen > 0 {
			v.LastSeen = time.UnixMilli(in.LastSeen).Format("2006-01-02 15:04")
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		iDead, jDead := out[i].Revoked || out[i].Expired, out[j].Revoked || out[j].Expired
		if iDead != jDead {
			return !iDead
		}
		return out[i].Online > out[j].Online
	})
	return out
}

// ---------------------------------------------------------------- key schedule

// guestKeys turns the ECDH secret into two directional AES-256-GCM keys.
//
// The invite token is the HKDF salt. That is what makes this an authenticated
// exchange rather than an anonymous one: an attacker who can sit in the middle
// of the LAN still cannot derive either key without the folder, and a guest who
// has the folder is exactly who the operator meant to invite.
func guestKeys(shared []byte, token, inviteID, sid string) (h2g, g2h cipher.AEAD, err error) {
	base := "lanrunner-guest-v1|" + inviteID + "|" + sid
	salt := []byte(token)

	mk := func(info string) (cipher.AEAD, error) {
		block, err := aes.NewCipher(hkdfSHA256(shared, salt, []byte(base+info), 32))
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	if h2g, err = mk("|h2g"); err != nil {
		return nil, nil, err
	}
	if g2h, err = mk("|g2h"); err != nil {
		return nil, nil, err
	}
	return h2g, g2h, nil
}

// ---------------------------------------------------------------- lifecycle

func (h *GuestHub) ensureServer() error {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if h.running {
		return nil
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", h.port))
	if err != nil && h.port != 0 {
		ln, err = net.Listen("tcp4", "0.0.0.0:0")
	}
	if err != nil {
		return fmt.Errorf("cannot open the guest gateway: %w", err)
	}
	h.port = ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/g/ping", h.handlePing)
	mux.HandleFunc("/g/hello", h.handleHello)
	mux.HandleFunc("/g/events", h.handleEvents)
	mux.HandleFunc("/g/send", h.handleSend)
	mux.HandleFunc("/g/typing", h.handleTyping)
	mux.HandleFunc("/g/bye", h.handleBye)

	h.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	h.ln = ln
	h.running = true

	go func(srv *http.Server, ln net.Listener) {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			h.app.logf("NET", "guest", "guest gateway stopped: %v", err)
		}
	}(h.srv, ln)

	h.app.logf("NET", "guest", "guest gateway listening on 0.0.0.0:%d — reachable from the LAN, invite token required", h.port)
	go h.reapLoop()
	return nil
}

func (h *GuestHub) stopServer() {
	h.srvMu.Lock()
	srv, running := h.srv, h.running
	h.srv, h.ln, h.running = nil, nil, false
	h.srvMu.Unlock()
	if !running || srv == nil {
		return
	}
	_ = srv.Close()
	h.app.logf("NET", "guest", "no live invites remain — guest gateway closed and its port released")
}

func (h *GuestHub) Port() int {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if !h.running {
		return 0
	}
	return h.port
}

// Resume restarts the gateway at boot when invites survived the last run.
func (h *GuestHub) Resume() {
	h.mu.Lock()
	live := h.liveCountLocked()
	h.mu.Unlock()
	if live == 0 {
		return
	}
	if err := h.ensureServer(); err != nil {
		h.app.logf("SEC", "guest", "%v — existing guest kits cannot connect until this is fixed", err)
		return
	}
	h.app.logf("SYS", "guest", "%d guest kit(s) restored from %s", live, h.path)
}

func (h *GuestHub) Close() {
	h.mu.Lock()
	all := make([]*guestSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		h.dropSession(s.sid, "host shutting down")
	}
	h.stopServer()
}

func (h *GuestHub) reapLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		h.srvMu.Lock()
		running := h.running
		h.srvMu.Unlock()
		if !running {
			return
		}

		h.mu.Lock()
		var dead []string
		for sid, s := range h.sessions {
			if s.idle() > guestSessionIdle {
				dead = append(dead, sid)
			}
		}
		h.mu.Unlock()
		for _, sid := range dead {
			h.dropSession(sid, "idle")
		}

		h.sweepExpired()
		h.throttle.sweep()
	}
}

// ---------------------------------------------------------------- generation

func slugify(s string) string {
	var sb strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
			dash = false
		case unicode.IsSpace(r), r == '-', r == '_':
			if !dash && sb.Len() > 0 {
				sb.WriteByte('-')
				dash = true
			}
		}
		if sb.Len() >= 40 {
			break
		}
	}
	return strings.Trim(sb.String(), "-")
}

// kitsBaseDir is where generated folders land unless the operator names a
// different one for a particular kit.
func kitsBaseDir() string {
	if s := strings.TrimSpace(*flagKits); s != "" {
		return s
	}
	return defaultKitsDir()
}

func defaultKitsDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "Lanrunner Guest Kits")
	}
	if st, err := os.Stat(filepath.Join(home, "Desktop")); err == nil && st.IsDir() {
		return filepath.Join(home, "Desktop", "Lanrunner Guest Kits")
	}
	return filepath.Join(home, "Lanrunner Guest Kits")
}

// kitConfig is baked straight into the generated HTML. It has to be inlined
// rather than loaded from a sibling JSON file, because a page opened from
// file:// is not allowed to fetch its own directory.
type kitConfig struct {
	V         int      `json:"v"`
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Hosts     []string `json:"hosts"`
	Port      int      `json:"port"`
	HostNick  string   `json:"host_nick"`
	Safety    string   `json:"safety"`
	Label      string `json:"label"`
	AllowPlain bool   `json:"allow_plain"`
	Created    string `json:"created"`
	Expires    string `json:"expires"`
}

// Create mints an invite and writes the guest folder.
func (h *GuestHub) Create(label, folder string, allowPlain bool) (*Invite, error) {
	label = sanitizeNick(label)
	if label == "" {
		label = "guest"
	}

	h.mu.Lock()
	count := len(h.invites)
	h.mu.Unlock()
	if count >= guestMaxInvites {
		return nil, fmt.Errorf("this build keeps at most %d guest kits — revoke and forget an old one first", guestMaxInvites)
	}

	if err := h.ensureServer(); err != nil {
		return nil, err
	}

	in := &Invite{
		ID:         randHex(8),  // 16 hex chars
		Token:      randHex(32), // 64 hex chars
		Label:      label,
		Created:    nowMS(),
		AllowPlain: allowPlain,
	}
	if *flagGuestTTL > 0 {
		in.Expires = in.Created + flagGuestTTL.Milliseconds()
	}

	base := strings.TrimSpace(folder)
	if base == "" {
		base = kitsBaseDir()
	}
	name := slugify(label)
	if name == "" {
		name = "guest"
	}
	dir := filepath.Join(base, name+"-"+in.ID[:6])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	in.Folder = dir

	if err := h.writeKit(in, dir); err != nil {
		return nil, err
	}

	h.mu.Lock()
	h.invites[in.ID] = in
	h.order = append(h.order, in.ID)
	h.saveLocked()
	h.mu.Unlock()

	h.app.logf("SYS", "guest", "guest kit %q created — invite %s, folder %s", label, shortFP(in.ID), dir)
	h.app.logf("SEC", "guest", "the folder for %q contains a 256-bit token; anyone holding it can message this machine until the invite is revoked", label)
	h.app.pushGuests()
	return in, nil
}

func (h *GuestHub) writeKit(in *Invite, dir string) error {
	tpl, err := guestKitFS.ReadFile("guestkit.html")
	if err != nil {
		return fmt.Errorf("guest client template missing: %w", err)
	}

	cfg := kitConfig{
		V:          guestProtoVersion,
		ID:         in.ID,
		Token:      in.Token,
		Hosts:      kitHostCandidates(),
		Port:       h.Port(),
		HostNick:   h.app.currentNick(),
		Safety:     SafetyNumber(h.app.id.FP),
		Label:      in.Label,
		AllowPlain: in.AllowPlain,
		Created:    time.UnixMilli(in.Created).Format("2006-01-02 15:04"),
		Expires:    "never",
	}
	if in.Expires > 0 {
		cfg.Expires = time.UnixMilli(in.Expires).Format("2006-01-02 15:04")
	}
	// json.Marshal escapes <, > and & as \u00xx, so a hostile display name
	// cannot break out of the <script> block it lands in.
	blob, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	page := strings.Replace(string(tpl), `"__LANRUNNER_CONNECT__"`, string(blob), 1)

	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(page), 0o644); err != nil {
		return err
	}

	readme := strings.Join([]string{
		"LANRUNNER GUEST KIT",
		"",
		"For: " + in.Label,
		"From: " + cfg.HostNick + "  (" + cfg.Safety + ")",
		"Created: " + cfg.Created,
		"Expires: " + cfg.Expires,
		"",
		"HOW TO USE",
		"",
		"  1. Put this folder anywhere on your computer.",
		"  2. Make sure you are on the same local network (same Wi-Fi or the",
		"     same switch) as the person who sent it to you.",
		"  3. Double-click index.html. It opens in your browser.",
		"  4. Type a name when asked, then start typing messages.",
		"",
		"There is nothing to install. The page talks straight to the other",
		"computer over the local network. No traffic goes to the internet and",
		"there is no server in the middle.",
		"",
		"IF IT WILL NOT CONNECT",
		"",
		"  - The other computer must have Lanrunner running.",
		"  - You must both be on the same network. Guest Wi-Fi that isolates",
		"    clients from each other will block this and nothing in the page",
		"    can work around it.",
		"  - Their firewall must allow inbound TCP on port " + fmt.Sprint(cfg.Port) + ".",
		"  - If their address changed, use the 'host' box at the top of the",
		"    page to type the new one, then press Reconnect.",
		"",
		"ADDRESSES TRIED, IN ORDER",
		"",
		"  " + strings.Join(cfg.Hosts, "\n  "),
		"  port " + fmt.Sprint(cfg.Port),
		"",
		"PRIVACY",
		"",
		"  This folder contains a secret invite token. Anyone who gets a copy",
		"  can message that computer as you. Do not repost it. When you are",
		"  done, ask them to revoke the invite.",
		"",
		"  This invite stops working on its own after " + cfg.Expires + ".",
		"",
		"  Messages are encrypted with AES-256-GCM using a key your browser",
		"  and their computer agree on per session (P-256 ECDH, with the invite",
		"  token mixed in). The page shows the live cipher state in its header;",
		"  if it ever says UNENCRYPTED, stop and tell them.",
		"",
	}, "\r\n")
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte(readme), 0o644); err != nil {
		return err
	}

	details := strings.Join([]string{
		"Lanrunner guest kit — connection details",
		"",
		"label      " + in.Label,
		"invite id  " + in.ID,
		"host       " + strings.Join(cfg.Hosts, ", "),
		"port       " + fmt.Sprint(cfg.Port),
		"created    " + cfg.Created,
		"",
		"The invite token is inside index.html. Keep both together.",
		"",
	}, "\r\n")
	return os.WriteFile(filepath.Join(dir, "connection.txt"), []byte(details), 0o644)
}

// kitHostCandidates lists every address a guest might reach us on, best guess
// first. The generated page probes them in order, which covers the common case
// of a machine with both Wi-Fi and Ethernet up.
func kitHostCandidates() []string {
	primary := primaryIP()
	out := []string{}
	seen := map[string]bool{}
	add := func(ip string) {
		if ip == "" || ip == "unknown" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	add(primary)
	for _, ip := range localIPs() {
		if ip == "127.0.0.1" || ip == "none" {
			continue
		}
		add(ip)
	}
	add("127.0.0.1")
	return out
}

// Regenerate rewrites an existing kit's folder — used when the host address or
// display name changed since the folder was handed out.
func (h *GuestHub) Regenerate(id string) (string, error) {
	h.mu.Lock()
	in, ok := h.invites[id]
	h.mu.Unlock()
	if !ok {
		return "", errors.New("unknown invite")
	}
	if in.Revoked {
		return "", errors.New("invite is revoked")
	}
	if err := h.ensureServer(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(in.Folder, 0o755); err != nil {
		return "", err
	}
	if err := h.writeKit(in, in.Folder); err != nil {
		return "", err
	}
	h.app.logf("SYS", "guest", "guest kit %q refreshed with current address details — %s", in.Label, in.Folder)
	return in.Folder, nil
}

func (h *GuestHub) Revoke(id string) bool {
	h.mu.Lock()
	in, ok := h.invites[id]
	if !ok {
		h.mu.Unlock()
		return false
	}
	in.Revoked = true
	sids := make([]string, 0, len(h.byInvite[id]))
	for sid := range h.byInvite[id] {
		sids = append(sids, sid)
	}
	h.saveLocked()
	live := h.liveCountLocked()
	h.mu.Unlock()

	for _, sid := range sids {
		h.dropSession(sid, "invite revoked")
	}
	h.app.logf("SEC", "guest", "invite %q revoked — its folder can no longer reach this machine", in.Label)
	if live == 0 {
		h.stopServer()
	}
	h.app.pushGuests()
	return true
}

func (h *GuestHub) Remove(id string) bool {
	h.Revoke(id)
	h.mu.Lock()
	if _, ok := h.invites[id]; !ok {
		h.mu.Unlock()
		return false
	}
	delete(h.invites, id)
	for i, x := range h.order {
		if x == id {
			h.order = append(h.order[:i], h.order[i+1:]...)
			break
		}
	}
	h.saveLocked()
	h.mu.Unlock()
	h.app.pushGuests()
	return true
}

// ---------------------------------------------------------------- delivery

// Deliver fans one envelope out to every live session of an invite and reports
// how many got it.
func (h *GuestHub) Deliver(inviteID, kind string, data any) int {
	h.mu.Lock()
	list := make([]*guestSession, 0, len(h.byInvite[inviteID]))
	for _, s := range h.byInvite[inviteID] {
		list = append(list, s)
	}
	h.mu.Unlock()

	n := 0
	for _, s := range list {
		b, err := s.seal(kind, data)
		if err != nil {
			continue
		}
		s.push(b)
		n++
	}
	return n
}

func (h *GuestHub) sessionsFor(inviteID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.byInvite[inviteID])
}

func (h *GuestHub) dropSession(sid, why string) {
	h.mu.Lock()
	s, ok := h.sessions[sid]
	if !ok {
		h.mu.Unlock()
		return
	}
	delete(h.sessions, sid)
	if m, ok := h.byInvite[s.invite]; ok {
		delete(m, sid)
		if len(m) == 0 {
			delete(h.byInvite, s.invite)
		}
	}
	h.mu.Unlock()

	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.mu.Unlock()
	if already {
		return
	}

	if b, err := s.seal("bye", map[string]string{"reason": why}); err == nil {
		s.push(b)
	}
	s.streamGen.Add(1)
	time.AfterFunc(time.Second, func() { close(s.ch) })

	h.app.logf("NET", "guest/"+s.remote, "guest %q disconnected — %s", s.nick, why)
	h.app.emit("presence", map[string]any{"fp": s.invite, "nick": s.nick, "online": false})
	h.app.pushGuests()
}

// ---------------------------------------------------------------- http plumbing

func guestCORS(w http.ResponseWriter) {
	// A kit opened from file:// has the opaque origin "null", so the wildcard is
	// the only value that works. It is safe here because every request must
	// carry the invite token — the browser's origin is not the credential.
	hdr := w.Header()
	hdr.Set("Access-Control-Allow-Origin", "*")
	hdr.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	hdr.Set("Access-Control-Allow-Headers", "Content-Type")
	hdr.Set("Access-Control-Max-Age", "600")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}

// guestGate applies the checks every guest request must pass before anything
// else looks at it: the source has to be on the local network, and the address
// must not be serving an authentication timeout. It returns false when the
// request has already been answered.
func (h *GuestHub) guestGate(w http.ResponseWriter, r *http.Request) bool {
	if guestPreflight(w, r) {
		return false
	}
	remote := guestRemote(r)
	if !allowedGuestSource(remote) {
		h.app.logf("SEC", "guest/"+remote,
			"REFUSED a guest request from %s — not a private LAN address (override with -guest-any-source)", remote)
		guestFail(w, http.StatusForbidden, "this gateway only serves the local network")
		return false
	}
	if blocked, wait := h.throttle.blocked(remote); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		guestFail(w, http.StatusTooManyRequests,
			fmt.Sprintf("too many failed attempts — try again in %s", dur(wait)))
		return false
	}
	return true
}

func guestPreflight(w http.ResponseWriter, r *http.Request) bool {
	guestCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func guestJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func guestFail(w http.ResponseWriter, code int, msg string) {
	guestJSON(w, code, map[string]string{"error": msg})
}

// handleRoot deliberately answers with JSON rather than HTML: the single
// instance check in main.go identifies Lanrunner by its UI title, and the guest
// gateway must never be mistaken for the operator's private UI.
func (h *GuestHub) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	guestJSON(w, http.StatusOK, map[string]any{
		"app":  "lanrunner-guest-gateway",
		"v":    guestProtoVersion,
		"note": "open the index.html from your guest kit folder",
	})
}

func (h *GuestHub) handlePing(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	guestJSON(w, http.StatusOK, map[string]any{"ok": true, "v": guestProtoVersion})
}

// inviteFor resolves an invite id and checks its token.
//
// An unknown id still runs a comparison against a decoy of the same length, so
// the time taken does not reveal which invite ids exist. The single caller logs
// one message for every failure mode, so a prober also learns nothing from the
// response.
func (h *GuestHub) inviteFor(id, token string) (*Invite, bool) {
	h.mu.Lock()
	in, ok := h.invites[id]
	h.mu.Unlock()

	want := strings.Repeat("0", 64)
	if ok {
		want = in.Token
	}
	match := subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1

	if !ok || !match || !in.usable() {
		return nil, false
	}
	return in, true
}

// sweepExpired retires invites that have aged out, closing their sessions and
// releasing the gateway port if nothing live is left. Each expiry is announced
// once, tracked by h.announced so the ticker does not repeat itself.
func (h *GuestHub) sweepExpired() {
	h.mu.Lock()
	var dropped []string
	var sids []string
	for id, in := range h.invites {
		if in.Revoked || !in.expired() || h.announced[id] {
			continue
		}
		h.announced[id] = true
		dropped = append(dropped, in.Label)
		for sid := range h.byInvite[id] {
			sids = append(sids, sid)
		}
	}
	live := h.liveCountLocked()
	h.mu.Unlock()

	if len(dropped) == 0 {
		return
	}
	for _, sid := range sids {
		h.dropSession(sid, "invite expired")
	}
	for _, label := range dropped {
		h.app.logf("SEC", "guest", "invite %q reached its expiry and no longer works", label)
	}
	if live == 0 {
		h.stopServer()
	}
	h.app.pushGuests()
}

type guestHelloIn struct {
	V     int    `json:"v"`
	ID    string `json:"id"`
	Token string `json:"token"`
	Nick  string `json:"nick"`
	XK    string `json:"xk"` // base64 raw P-256 public key; empty asks for plaintext
}

func (h *GuestHub) handleHello(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		guestFail(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in guestHelloIn
	if err := decodeBody(r, &in); err != nil {
		guestFail(w, http.StatusBadRequest, "malformed request")
		return
	}

	remote := guestRemote(r)
	inv, ok := h.inviteFor(in.ID, in.Token)
	if !ok {
		penalty := h.throttle.bad(remote)
		h.app.logf("SEC", "guest/"+remote,
			"GUEST REJECTED — invite %s is unknown, revoked, expired, or the token did not match", shortFP(in.ID))
		if penalty > 0 {
			h.app.logf("SEC", "guest/"+remote,
				"%s has failed %d handshakes — further attempts refused for %s", remote, guestAuthFails, dur(penalty))
		}
		guestFail(w, http.StatusForbidden, "this invite is not valid any more")
		return
	}
	h.throttle.good(remote)
	if in.V != guestProtoVersion {
		guestFail(w, http.StatusBadRequest, fmt.Sprintf("guest kit speaks v%d, this host speaks v%d — ask for a fresh kit", in.V, guestProtoVersion))
		return
	}

	nick := sanitizeNick(in.Nick)
	if nick == "" {
		nick = inv.Label
	}

	sid := randHex(8)
	s := &guestSession{
		sid:     sid,
		invite:  inv.ID,
		remote:  remote,
		nick:    nick,
		ch:      make(chan []byte, guestQueueDepth),
		created: time.Now(),
		rateAt:  time.Now(),
	}
	s.touch()

	hostPubB64 := ""
	if in.XK != "" {
		raw, err := base64.StdEncoding.DecodeString(in.XK)
		if err != nil {
			guestFail(w, http.StatusBadRequest, "unusable public key")
			return
		}
		theirs, err := ecdh.P256().NewPublicKey(raw)
		if err != nil {
			guestFail(w, http.StatusBadRequest, "unusable public key")
			return
		}
		mine, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			guestFail(w, http.StatusInternalServerError, "key generation failed")
			return
		}
		shared, err := mine.ECDH(theirs)
		if err != nil {
			guestFail(w, http.StatusBadRequest, "key agreement failed")
			return
		}
		if s.h2g, s.g2h, err = guestKeys(shared, inv.Token, inv.ID, sid); err != nil {
			guestFail(w, http.StatusInternalServerError, "key derivation failed")
			return
		}
		s.enc = true
		hostPubB64 = base64.StdEncoding.EncodeToString(mine.PublicKey().Bytes())
	} else if !inv.AllowPlain {
		h.app.logf("SEC", "guest/"+remote,
			"guest %q asked for an UNENCRYPTED session and was refused — its browser has no Web Crypto (regenerate the kit with plaintext allowed if you accept that)", nick)
		guestFail(w, http.StatusForbidden, "this invite requires encryption, and your browser did not offer a key")
		return
	} else {
		h.app.logf("SEC", "guest/"+remote, "guest %q connected WITHOUT ENCRYPTION — the operator allowed plaintext for this invite", nick)
	}

	// Keep the number of tabs bounded; evict the oldest if a guest piles up.
	h.mu.Lock()
	m, ok := h.byInvite[inv.ID]
	if !ok {
		m = map[string]*guestSession{}
		h.byInvite[inv.ID] = m
	}
	var evict string
	if len(m) >= guestMaxSessions {
		oldest := time.Now()
		for id, other := range m {
			if other.created.Before(oldest) {
				oldest, evict = other.created, id
			}
		}
	}
	h.sessions[sid] = s
	m[sid] = s
	inv.LastNick = nick
	inv.LastSeen = nowMS()
	h.saveLocked()
	h.mu.Unlock()

	if evict != "" {
		h.dropSession(evict, "replaced by a newer tab")
	}

	cipherNote := "AES-256-GCM"
	if !s.enc {
		cipherNote = "UNENCRYPTED"
	}
	h.app.logf("CRY", "guest/"+remote, "guest %q joined invite %q — %s, P-256 ECDH keyed by the invite token",
		nick, inv.Label, cipherNote)
	h.app.emit("presence", map[string]any{"fp": inv.ID, "nick": nick, "online": true})
	h.app.pushGuests()
	h.app.touchActivity()

	guestJSON(w, http.StatusOK, map[string]any{
		"v":      guestProtoVersion,
		"sid":    sid,
		"xk":     hostPubB64,
		"enc":    s.enc,
		"cipher": cipherNote,
		"host":   h.app.currentNick(),
		"safety": SafetyNumber(h.app.id.FP),
		"label":  inv.Label,
	})
}

func (h *GuestHub) session(r *http.Request, id, sid string) (*guestSession, bool) {
	h.mu.Lock()
	s, ok := h.sessions[sid]
	h.mu.Unlock()
	if !ok || s.invite != id {
		return nil, false
	}
	s.touch()
	return s, true
}

func (h *GuestHub) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	s, ok := h.session(r, r.URL.Query().Get("id"), r.URL.Query().Get("sid"))
	if !ok {
		guestFail(w, http.StatusForbidden, "session expired — reload the page")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	gen := s.streamGen.Add(1)

	write := func(b []byte) bool {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		fl.Flush()
		s.touch()
		return true
	}

	if b, err := s.seal("ready", map[string]any{
		"host":   h.app.currentNick(),
		"safety": SafetyNumber(h.app.id.FP),
		"sid":    s.sid,
		"enc":    s.enc,
	}); err == nil && !write(b) {
		return
	}

	// Backlog once per session, so a reconnecting EventSource does not duplicate
	// the whole conversation in the guest's log.
	if s.sentBacklog.CompareAndSwap(false, true) {
		for _, e := range h.app.hist.Load(s.invite, guestBacklog) {
			from := "host"
			if !e.Self {
				from = "guest"
			}
			b, err := s.seal("msg", map[string]any{
				"ts":   time.UnixMilli(e.TS).Format("15:04:05"),
				"mid":  e.MID,
				"from": from,
				"nick": e.Nick,
				"body": e.Body,
				"old":  true,
			})
			if err != nil || !write(b) {
				return
			}
		}
	}

	keep := time.NewTicker(20 * time.Second)
	defer keep.Stop()
	for {
		select {
		case b, open := <-s.ch:
			if !open {
				return
			}
			if !write(b) {
				return
			}
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
			s.touch()
		case <-r.Context().Done():
			return
		}
		if s.streamGen.Load() != gen {
			return // a newer tab took this session over
		}
	}
}

type guestFrameIn struct {
	ID    string          `json:"id"`
	SID   string          `json:"sid"`
	Frame string          `json:"f"`
	Plain json.RawMessage `json:"p"`
}

// guestPayload is the decrypted guest->host body. Seq feeds the anti-replay
// window, so it is inside the sealed envelope where it cannot be edited.
type guestPayload struct {
	T    string `json:"t"`
	Body string `json:"body"`
	Seq  uint64 `json:"seq"`
}

func (h *GuestHub) readFrame(w http.ResponseWriter, r *http.Request) (*guestSession, *guestPayload, bool) {
	if r.Method != http.MethodPost {
		guestFail(w, http.StatusMethodNotAllowed, "POST only")
		return nil, nil, false
	}
	var in guestFrameIn
	if err := decodeBody(r, &in); err != nil {
		guestFail(w, http.StatusBadRequest, "malformed request")
		return nil, nil, false
	}
	s, ok := h.session(r, in.ID, in.SID)
	if !ok {
		guestFail(w, http.StatusForbidden, "session expired — reload the page")
		return nil, nil, false
	}
	pt, err := s.open(in.Frame, in.Plain)
	if err != nil {
		h.app.logf("SEC", "guest/"+s.remote, "frame from guest %q rejected — %v", s.nick, err)
		guestFail(w, http.StatusBadRequest, "frame rejected")
		return nil, nil, false
	}
	var p guestPayload
	if json.Unmarshal(pt, &p) != nil {
		guestFail(w, http.StatusBadRequest, "payload is not valid JSON")
		return nil, nil, false
	}
	if !s.fresh(p.Seq) {
		h.app.logf("SEC", "guest/"+s.remote,
			"REPLAYED FRAME from guest %q — counter %d already used or too old, dropped", s.nick, p.Seq)
		guestFail(w, http.StatusBadRequest, "frame rejected")
		return nil, nil, false
	}
	return s, &p, true
}

func (h *GuestHub) handleSend(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	s, p, ok := h.readFrame(w, r)
	if !ok {
		return
	}
	if !s.allow() {
		h.app.logf("SEC", "guest/"+s.remote, "guest %q exceeded %d messages per %s — message dropped",
			s.nick, guestRateMax, guestRateWindow)
		guestFail(w, http.StatusTooManyRequests, "slow down")
		return
	}

	body, hadControl := sanitizeBody(p.Body)
	if hadControl {
		h.app.logf("SEC", "guest/"+s.remote, "control characters stripped from a message by guest %q", s.nick)
	}
	if body == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len([]rune(body)) > maxBodyRunes {
		body = string([]rune(body)[:maxBodyRunes])
	}

	h.app.touchActivity()
	mid := randHex(6)
	enc := "AES-256-GCM"
	if !s.enc {
		enc = "PLAINTEXT"
	}

	h.app.hist.Append(HistEntry{
		TS: nowMS(), Conv: s.invite, FP: s.invite, Nick: s.nick,
		Self: false, Body: body, MID: mid,
	})
	h.app.logf("PKT", "guest/"+s.remote, "RX guest msg conv=%s mid=%s plaintext=%dB — %s",
		shortFP(s.invite), mid, len(body), enc)
	h.app.emit("msg", ChatMsg{
		TS: stamp(), Conv: s.invite, MID: mid, FP: s.invite, Nick: s.nick,
		Body: body, Enc: enc,
	})

	// Echo the guest's own line back to its other tabs, and acknowledge.
	h.mu.Lock()
	others := make([]*guestSession, 0)
	for _, o := range h.byInvite[s.invite] {
		if o.sid != s.sid {
			others = append(others, o)
		}
	}
	h.mu.Unlock()
	for _, o := range others {
		if b, err := o.seal("msg", map[string]any{
			"ts": stamp()[:8], "mid": mid, "from": "guest", "nick": s.nick, "body": body,
		}); err == nil {
			o.push(b)
		}
	}
	if b, err := s.seal("ack", map[string]string{"mid": mid}); err == nil {
		s.push(b)
	}

	h.mu.Lock()
	if inv, ok := h.invites[s.invite]; ok {
		inv.LastSeen = nowMS()
		inv.LastNick = s.nick
	}
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (h *GuestHub) handleTyping(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	s, _, ok := h.readFrame(w, r)
	if !ok {
		return
	}
	h.app.emit("typing", map[string]any{"fp": s.invite, "nick": s.nick, "conv": s.invite})
	w.WriteHeader(http.StatusNoContent)
}

func (h *GuestHub) handleBye(w http.ResponseWriter, r *http.Request) {
	if !h.guestGate(w, r) {
		return
	}
	var in guestFrameIn
	if err := decodeBody(r, &in); err != nil {
		guestFail(w, http.StatusBadRequest, "malformed request")
		return
	}
	if s, ok := h.session(r, in.ID, in.SID); ok {
		h.dropSession(s.sid, "guest closed the page")
	}
	w.WriteHeader(http.StatusNoContent)
}

func guestRemote(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
