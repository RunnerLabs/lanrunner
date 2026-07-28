package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTimeout = 6 * time.Second
	heartbeatEvery   = 8 * time.Second
	sessionIdle      = 40 * time.Second
	helloMaxLine     = 8 << 10
)

// Hello is the cleartext, signed handshake. It carries public keys only.
type Hello struct {
	V     int    `json:"v"`
	T     string `json:"t"`
	FP    string `json:"fp"`
	Nick  string `json:"nick"`
	Ed    string `json:"ed"`
	XK    string `json:"xk"`
	Nonce string `json:"n"`
	TS    int64  `json:"ts"`
	Sig   string `json:"sig"`
}

func helloPayload(h *Hello) string {
	return strings.Join([]string{
		"lanrunner-hello-v2", h.FP, h.Nick, h.Ed, h.XK, h.Nonce,
		strconv.FormatInt(h.TS, 10),
	}, "|")
}

func (a *App) buildHello(nonce string) *Hello {
	h := &Hello{
		V:     protoVersion,
		T:     "hello",
		FP:    a.id.FP,
		Nick:  a.currentNick(),
		Ed:    base64.StdEncoding.EncodeToString(a.id.EdPub),
		XK:    base64.StdEncoding.EncodeToString(a.id.XPub.Bytes()),
		Nonce: nonce,
		TS:    nowMS(),
	}
	h.Sig = a.id.Sign(helloPayload(h))
	return h
}

// verifyHello checks the peer's handshake and returns its keys.
func verifyHello(h *Hello) (ed25519.PublicKey, *ecdh.PublicKey, error) {
	if h.V != protoVersion {
		return nil, nil, fmt.Errorf("protocol v%d, expected v%d", h.V, protoVersion)
	}
	if h.T != "hello" {
		return nil, nil, fmt.Errorf("unexpected handshake opcode %q", h.T)
	}
	edRaw, err := base64.StdEncoding.DecodeString(h.Ed)
	if err != nil || len(edRaw) != ed25519.PublicKeySize {
		return nil, nil, errors.New("unusable Ed25519 key")
	}
	edPub := ed25519.PublicKey(edRaw)
	if got := Fingerprint(edPub); got != h.FP {
		return nil, nil, fmt.Errorf("fingerprint forgery: claimed %s, key hashes to %s", shortFP(h.FP), shortFP(got))
	}
	if !VerifySig(edPub, helloPayload(h), h.Sig) {
		return nil, nil, errors.New("signature does not verify")
	}
	if len(h.Nonce) < 16 {
		return nil, nil, errors.New("handshake nonce too short")
	}
	xkRaw, err := base64.StdEncoding.DecodeString(h.XK)
	if err != nil {
		return nil, nil, errors.New("unusable X25519 key")
	}
	xPub, err := ecdh.X25519().NewPublicKey(xkRaw)
	if err != nil {
		return nil, nil, errors.New("unusable X25519 key")
	}
	return edPub, xPub, nil
}

// ---------------------------------------------------------------- connections

type Conn struct {
	app      *App
	fp       string
	nick     string
	addr     string
	sc       *secureConn
	outbound bool
	opened   time.Time

	mu      sync.Mutex
	rtt     int64
	pings   map[uint64]time.Time
	pingSeq uint64
	closed  bool
}

// Msg is the payload carried inside the encrypted channel.
type Msg struct {
	T    string `json:"t"` // msg | ack | ping | pong | typing
	Conv string `json:"conv,omitempty"`
	MID  string `json:"mid,omitempty"`
	TS   int64  `json:"ts,omitempty"`
	Body string `json:"body,omitempty"`
	PN   uint64 `json:"pn,omitempty"`
}

// dialerOf reports which fingerprint initiated a connection, used to settle
// simultaneous connects identically on both sides.
func (c *Conn) dialerOf(selfFP string) string {
	if c.outbound {
		return selfFP
	}
	return c.fp
}

func (a *App) dialPeer(p Peer) {
	a.mu.Lock()
	_, exists := a.conns[p.FP]
	a.mu.Unlock()
	if exists {
		return
	}

	addr := net.JoinHostPort(p.IP, strconv.Itoa(p.Port))
	t0 := time.Now()
	raw, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		a.diag.CountDialFail()
		a.logf("NET", addr, "dial failed for %s — %v", p.Nick, err)
		return
	}
	connectMS := time.Since(t0).Milliseconds()

	c, err := a.handshake(raw, true, p.FP)
	if err != nil {
		_ = raw.Close()
		a.logf("SEC", addr, "HANDSHAKE REJECTED with %s — %v", p.Nick, err)
		return
	}
	c.mu.Lock()
	c.rtt = connectMS
	c.mu.Unlock()
	a.logf("CRY", addr, "session established with %s — X25519 ECDH, AES-256-GCM, connect %dms",
		c.nick, connectMS)
	a.runConn(c)
}

func (a *App) acceptLoop(ln net.Listener) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			a.logf("NET", "local", "accept error: %v", err)
			return
		}
		go func(raw net.Conn) {
			a.diag.CountInbound()
			c, err := a.handshake(raw, false, "")
			if err != nil {
				_ = raw.Close()
				a.logf("SEC", raw.RemoteAddr().String(), "HANDSHAKE REJECTED — %v", err)
				return
			}
			a.logf("CRY", raw.RemoteAddr().String(),
				"inbound session from %s accepted — X25519 ECDH, AES-256-GCM", c.nick)
			a.runConn(c)
		}(raw)
	}
}

// handshake performs the signed key exchange and returns a live encrypted Conn.
func (a *App) handshake(raw net.Conn, outbound bool, expectFP string) (*Conn, error) {
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(raw, 16<<10)

	myNonce := randHex(16)
	mine := a.buildHello(myNonce)
	mineJSON, err := json.Marshal(mine)
	if err != nil {
		return nil, err
	}

	readHello := func() (*Hello, error) {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("no handshake received: %w", err)
		}
		if len(line) > helloMaxLine {
			return nil, fmt.Errorf("handshake line %dB exceeds ceiling", len(line))
		}
		var h Hello
		if err := json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &h); err != nil {
			return nil, fmt.Errorf("handshake is not valid JSON: %w", err)
		}
		return &h, nil
	}
	writeHello := func() error {
		if _, err := raw.Write(append(mineJSON, '\n')); err != nil {
			return fmt.Errorf("could not send handshake: %w", err)
		}
		return nil
	}

	var theirs *Hello
	if outbound {
		if err := writeHello(); err != nil {
			return nil, err
		}
		if theirs, err = readHello(); err != nil {
			return nil, err
		}
	} else {
		if theirs, err = readHello(); err != nil {
			return nil, err
		}
		if err := writeHello(); err != nil {
			return nil, err
		}
	}

	edPub, xPub, err := verifyHello(theirs)
	if err != nil {
		return nil, err
	}
	if theirs.FP == a.id.FP {
		return nil, errors.New("peer presented our own fingerprint")
	}
	if expectFP != "" && theirs.FP != expectFP {
		return nil, fmt.Errorf("expected fingerprint %s but got %s", shortFP(expectFP), shortFP(theirs.FP))
	}

	skew := time.Since(time.UnixMilli(theirs.TS))
	if skew > clockSkew || skew < -clockSkew {
		return nil, fmt.Errorf("handshake timestamp is %s outside the freshness window", dur(skew.Abs()))
	}

	shared, err := a.id.XPriv.ECDH(xPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	dialerFP, responderFP := a.id.FP, theirs.FP
	salt := myNonce + theirs.Nonce
	if !outbound {
		dialerFP, responderFP = theirs.FP, a.id.FP
		salt = theirs.Nonce + myNonce
	}
	sc := deriveSession(shared, []byte(salt), dialerFP, responderFP, outbound)
	if sc == nil {
		return nil, errors.New("could not derive session keys")
	}
	sc.attach(raw, br)

	nick := sanitizeNick(theirs.Nick)
	if nick == "" {
		nick = shortFP(theirs.FP)
	}

	obs := a.trust.Observe(theirs.FP, nick)
	if obs.Status == "impersonation" {
		a.logf("SEC", raw.RemoteAddr().String(),
			"NAME CONFLICT during handshake: %q is pinned to a different key (%s)", nick, shortFP(obs.OtherFP))
	}

	// Record or refresh the peer even if discovery never saw it — this is how a
	// manually seeded or gossiped peer becomes real.
	ip, portStr, _ := net.SplitHostPort(raw.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)
	a.mu.Lock()
	p, known := a.peers[theirs.FP]
	if !known {
		p = &Peer{FP: theirs.FP, First: time.Now()}
		a.peers[theirs.FP] = p
	}
	p.Nick, p.EdPub, p.XPub, p.Last = nick, edPub, xPub, time.Now()
	if p.IP == "" {
		p.IP = ip
	}
	if p.Port == 0 {
		p.Port = port
	}
	a.mu.Unlock()

	_ = raw.SetDeadline(time.Time{})
	return &Conn{
		app: a, fp: theirs.FP, nick: nick,
		addr: raw.RemoteAddr().String(), sc: sc,
		outbound: outbound, opened: time.Now(),
		pings: map[uint64]time.Time{},
	}, nil
}

// register resolves simultaneous connects. Both ends apply the same rule — keep
// the connection whose dialer has the lexicographically smaller fingerprint —
// so they converge on the same survivor without negotiation.
func (a *App) register(c *Conn) bool {
	a.mu.Lock()
	existing, ok := a.conns[c.fp]
	if !ok {
		a.conns[c.fp] = c
		a.mu.Unlock()
		return true
	}
	keepNew := c.dialerOf(a.id.FP) < existing.dialerOf(a.id.FP)
	if keepNew {
		a.conns[c.fp] = c
	}
	a.mu.Unlock()

	if keepNew {
		a.logf("NET", c.addr, "duplicate session with %s resolved — keeping the newer one", c.nick)
		existing.close("superseded by a simultaneous connect")
		return true
	}
	return false
}

func (a *App) runConn(c *Conn) {
	if !a.register(c) {
		a.logf("NET", c.addr, "duplicate session with %s dropped — an equivalent one is already live", c.nick)
		_ = c.sc.Close()
		return
	}
	a.pushPeers()
	a.emit("presence", map[string]any{"fp": c.fp, "nick": c.nick, "online": true})

	go c.heartbeat()

	for {
		_ = c.sc.c.SetReadDeadline(time.Now().Add(sessionIdle))
		pt, err := c.sc.ReadFrame()
		if err != nil {
			if strings.Contains(err.Error(), "AEAD") {
				a.logf("SEC", c.addr, "FRAME AUTHENTICATION FAILED from %s — %v — session torn down", c.nick, err)
				a.flagPeer(c.fp, "AEAD-FAIL")
			} else {
				a.logf("NET", c.addr, "session with %s ended — %v", c.nick, err)
			}
			break
		}
		c.handleFrame(pt)
	}

	c.close("read loop ended")
	a.mu.Lock()
	if a.conns[c.fp] == c {
		delete(a.conns, c.fp)
	}
	a.mu.Unlock()
	a.emit("presence", map[string]any{"fp": c.fp, "nick": c.nick, "online": false})
	a.pushPeers()
}

func (a *App) flagPeer(fp, flag string) {
	a.mu.Lock()
	if p, ok := a.peers[fp]; ok {
		p.flag(flag)
	}
	a.mu.Unlock()
	a.pushPeers()
}

func (c *Conn) close(why string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.sc.Close()
	c.app.logf("NET", c.addr, "session %s closed — %s", shortFP(c.fp), why)
}

func (c *Conn) sendMsg(m *Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.sc.WriteFrame(b)
}

func (c *Conn) heartbeat() {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.pingSeq++
		pn := c.pingSeq
		c.pings[pn] = time.Now()
		// Keep the ping table from growing if a peer stops answering.
		if len(c.pings) > 8 {
			for k := range c.pings {
				if k <= pn-8 {
					delete(c.pings, k)
				}
			}
		}
		c.mu.Unlock()

		if err := c.sendMsg(&Msg{T: "ping", PN: pn, TS: nowMS()}); err != nil {
			c.close("heartbeat write failed")
			return
		}
		c.app.vlogf("PKT", c.addr, "TX ping pn=%d (encrypted, 12-byte counter nonce)", pn)
	}
}

func (c *Conn) handleFrame(pt []byte) {
	a := c.app
	var m Msg
	if err := json.Unmarshal(pt, &m); err != nil {
		a.logf("SEC", c.addr, "authenticated frame from %s was not valid JSON — dropped", c.nick)
		return
	}

	switch m.T {
	case "ping":
		_ = c.sendMsg(&Msg{T: "pong", PN: m.PN, TS: nowMS()})
		a.vlogf("PKT", c.addr, "RX ping pn=%d — pong sent", m.PN)

	case "pong":
		c.mu.Lock()
		t0, ok := c.pings[m.PN]
		delete(c.pings, m.PN)
		if ok {
			c.rtt = time.Since(t0).Milliseconds()
		}
		rtt := c.rtt
		c.mu.Unlock()
		if ok {
			a.mu.Lock()
			if p, exists := a.peers[c.fp]; exists {
				p.RTT = rtt
				p.Last = time.Now()
			}
			a.mu.Unlock()
			a.vlogf("PKT", c.addr, "RX pong pn=%d rtt=%dms", m.PN, rtt)
		}

	case "ack":
		// The peer echoes the scope it received; map it back to our local
		// conversation id, which for a DM is that peer's fingerprint.
		conv := "room"
		if m.Conv == "dm" {
			conv = c.fp
		}
		a.emit("ack", map[string]any{"mid": m.MID, "conv": conv, "fp": c.fp, "nick": c.nick})
		a.hist.MarkDelivered(conv, m.MID)
		a.vlogf("PKT", c.addr, "RX ack mid=%s conv=%s", m.MID, conv)

	case "typing":
		a.emit("typing", map[string]any{"fp": c.fp, "nick": c.nick, "conv": m.Conv})

	case "msg":
		body, hadControl := sanitizeBody(m.Body)
		if hadControl {
			a.flagPeer(c.fp, "CONTROL-CHARS")
			a.logf("SEC", c.addr, "control characters stripped from a message by %s — escape-injection attempt", c.nick)
		}
		if body == "" {
			return
		}
		if len([]rune(body)) > maxBodyRunes {
			body = string([]rune(body)[:maxBodyRunes])
			a.logf("SEC", c.addr, "message from %s truncated at %d runes by local policy", c.nick, maxBodyRunes)
		}
		a.touchActivity()

		conv := "room"
		if m.Conv == "dm" {
			conv = c.fp
		}

		a.mu.Lock()
		if p, ok := a.peers[c.fp]; ok {
			p.RxMsgs++
			p.Bytes += len(pt)
			p.Last = time.Now()
		}
		a.mu.Unlock()

		a.logf("PKT", c.addr, "RX msg conv=%s mid=%s plaintext=%dB — AEAD verified, counter %d",
			conv, m.MID, len(pt), c.sc.rxCtr-1)

		entry := HistEntry{
			TS: nowMS(), Conv: conv, FP: c.fp, Nick: c.nick, Self: false,
			Body: body, MID: m.MID,
		}
		a.hist.Append(entry)
		a.emit("msg", ChatMsg{
			TS: stamp(), Conv: conv, MID: m.MID, FP: c.fp, Nick: c.nick,
			Body: body, Enc: "AES-256-GCM",
		})
		_ = c.sendMsg(&Msg{T: "ack", MID: m.MID, Conv: m.Conv})
		a.pushPeers()

	default:
		a.logf("SEC", c.addr, "unknown message opcode %q from %s — dropped", m.T, c.nick)
	}
}

// ---------------------------------------------------------------- send path

// Send delivers a message to the room (conv == "room"), to a single peer, or to
// a guest kit conversation.
func (a *App) Send(conv, body string) {
	body, _ = sanitizeBody(body)
	if body == "" {
		return
	}
	if len([]rune(body)) > maxBodyRunes {
		body = string([]rune(body)[:maxBodyRunes])
	}

	// A guest conversation has no peer session behind it — it is served over the
	// guest gateway instead, so it takes its own path.
	if a.guests != nil && a.guests.IsInvite(conv) {
		a.sendToGuest(conv, body)
		return
	}

	a.mu.Lock()
	a.msgSeq++
	nick := a.nick
	var targets []*Conn
	if conv == "room" {
		for _, c := range a.conns {
			targets = append(targets, c)
		}
	} else if c, ok := a.conns[conv]; ok {
		targets = append(targets, c)
	}
	a.mu.Unlock()

	mid := randHex(6)
	scope := "room"
	if conv != "room" {
		scope = "dm"
	}

	entry := HistEntry{TS: nowMS(), Conv: conv, FP: a.id.FP, Nick: nick, Self: true, Body: body, MID: mid}
	a.hist.Append(entry)
	a.emit("msg", ChatMsg{
		TS: stamp(), Conv: conv, MID: mid, FP: a.id.FP, Nick: nick,
		Self: true, Body: body, Enc: "AES-256-GCM",
	})

	if len(targets) == 0 {
		if conv == "room" {
			a.logf("SEC", "local", "NO LIVE SESSIONS — message %s composed but not transmitted", mid)
		} else {
			a.logf("SEC", "local", "%s is offline — message %s not transmitted", shortFP(conv), mid)
		}
		return
	}

	m := &Msg{T: "msg", Conv: scope, MID: mid, TS: nowMS(), Body: body}
	a.logf("PKT", "local", "TX msg conv=%s mid=%s plaintext=%dB fanout=%d — sealed per session",
		conv, mid, len(body), len(targets))

	for _, c := range targets {
		go func(c *Conn) {
			if err := c.sendMsg(m); err != nil {
				a.logf("NET", c.addr, "TX FAILED to %s — %v", c.nick, err)
				c.close("write failed")
				return
			}
			a.mu.Lock()
			if p, ok := a.peers[c.fp]; ok {
				p.TxMsgs++
			}
			a.mu.Unlock()
		}(c)
	}
}

// sendToGuest mirrors the peer send path — same history, same UI event, same
// receipt — but hands the body to the guest gateway instead of a TCP session.
func (a *App) sendToGuest(conv, body string) {
	nick := a.currentNick()
	mid := randHex(6)

	a.hist.Append(HistEntry{
		TS: nowMS(), Conv: conv, FP: a.id.FP, Nick: nick, Self: true, Body: body, MID: mid,
	})
	a.emit("msg", ChatMsg{
		TS: stamp(), Conv: conv, MID: mid, FP: a.id.FP, Nick: nick,
		Self: true, Body: body, Enc: "AES-256-GCM",
	})

	n := a.guests.Deliver(conv, "msg", map[string]any{
		"ts": stamp()[:8], "mid": mid, "from": "host", "nick": nick, "body": body,
	})
	if n == 0 {
		a.logf("SEC", "guest", "%s is not connected — message %s composed but not transmitted",
			a.guests.Label(conv), mid)
		return
	}
	a.logf("PKT", "guest", "TX guest msg conv=%s mid=%s plaintext=%dB fanout=%d — sealed per session",
		shortFP(conv), mid, len(body), n)
	a.emit("ack", map[string]any{
		"mid": mid, "conv": conv, "fp": conv, "nick": a.guests.Label(conv),
	})
	a.hist.MarkDelivered(conv, mid)
}

func (a *App) SendTyping(conv string) {
	if a.guests != nil && a.guests.IsInvite(conv) {
		a.guests.Deliver(conv, "typing", map[string]any{"nick": a.currentNick()})
		return
	}
	a.mu.Lock()
	var targets []*Conn
	if conv == "room" {
		for _, c := range a.conns {
			targets = append(targets, c)
		}
	} else if c, ok := a.conns[conv]; ok {
		targets = append(targets, c)
	}
	a.mu.Unlock()
	for _, c := range targets {
		_ = c.sendMsg(&Msg{T: "typing", Conv: conv})
	}
}

func (a *App) closeAllConns() {
	a.mu.Lock()
	list := make([]*Conn, 0, len(a.conns))
	for _, c := range a.conns {
		list = append(list, c)
	}
	a.conns = map[string]*Conn{}
	a.mu.Unlock()
	for _, c := range list {
		c.close("local shutdown")
	}
}
