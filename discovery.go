package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// multicastGroup is a second discovery channel. Some networks pass multicast
// but filter broadcast, and some do the reverse, so Lan Runner speaks both.
const multicastGroup = "239.255.42.99"

// Announce is the discovery datagram. It is signed but not encrypted: it has to
// be readable to bootstrap, and it carries only public keys and a display name.
type Announce struct {
	V      int      `json:"v"`
	T      string   `json:"t"` // announce | bye
	FP     string   `json:"fp"`
	Nick   string   `json:"nick"`
	Ed     string   `json:"ed"`
	XK     string   `json:"xk"`
	Port   int      `json:"port"`
	TS     int64    `json:"ts"`
	Gossip []string `json:"g,omitempty"`
	Sig    string   `json:"sig"`
}

func announcePayload(a *Announce) string {
	return strings.Join([]string{
		"lanrunner-announce-v2",
		a.T, a.FP, a.Nick, a.Ed, a.XK,
		strconv.Itoa(a.Port),
		strconv.FormatInt(a.TS, 10),
		strings.Join(a.Gossip, ","),
	}, "|")
}

func (a *App) buildAnnounce(kind string) *Announce {
	an := &Announce{
		V:    protoVersion,
		T:    kind,
		FP:   a.id.FP,
		Nick: a.currentNick(),
		Ed:   base64.StdEncoding.EncodeToString(a.id.EdPub),
		XK:   base64.StdEncoding.EncodeToString(a.id.XPub.Bytes()),
		Port: a.tcpPort,
		TS:   nowMS(),
	}
	if kind == "announce" {
		an.Gossip = a.gossipAddrs()
	}
	an.Sig = a.id.Sign(announcePayload(an))
	return an
}

// gossipAddrs shares the addresses of peers we can see, capped, so that two
// devices which can each reach us but not each other get introduced.
//
// These are hints only. A peer is never created from gossip — we merely probe
// the address, and identity is still established by that device's own signed
// announce.
func (a *App) gossipAddrs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, 16)
	for _, p := range a.peers {
		if !p.Direct {
			continue
		}
		out = append(out, net.JoinHostPort(p.IP, strconv.Itoa(p.Port)))
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// ---------------------------------------------------------------- listeners

func (a *App) listenBroadcast() {
	lc := net.ListenConfig{Control: reuseControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", a.discoPort))
	if err != nil {
		a.logf("SEC", "local", "BROADCAST BIND FAILED on :%d (%v) — another process holds the port, or the OS refused it", a.discoPort, err)
		return
	}
	a.logf("NET", "local", "broadcast discovery listening on 0.0.0.0:%d", a.discoPort)
	a.diag.MarkBind("broadcast")
	a.readDatagrams(pc, "bcast")
}

func (a *App) listenMulticast() {
	gaddr := &net.UDPAddr{IP: net.ParseIP(multicastGroup), Port: a.discoPort}
	pc, err := net.ListenMulticastUDP("udp4", nil, gaddr)
	if err != nil {
		a.logf("NET", "local", "multicast channel unavailable (%v) — continuing with broadcast only", err)
		return
	}
	a.logf("NET", "local", "multicast discovery joined %s:%d", multicastGroup, a.discoPort)
	a.diag.MarkBind("multicast")
	a.readDatagrams(pc, "mcast")
}

func (a *App) readDatagrams(pc net.PacketConn, via string) {
	defer pc.Close()
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			a.logf("NET", "local", "%s discovery read error: %v", via, err)
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		a.diag.CountDatagram()
		a.onAnnounce(ua.IP.String(), via, append([]byte(nil), buf[:n]...))
	}
}

// ---------------------------------------------------------------- inbound

func (a *App) onAnnounce(ip, via string, raw []byte) {
	var an Announce
	if err := json.Unmarshal(raw, &an); err != nil {
		a.logf("SEC", ip, "malformed %s datagram len=%dB — dropped", via, len(raw))
		return
	}
	if an.FP == a.id.FP {
		a.diag.MarkLoopback() // our own datagram came back: inbound UDP works
		return
	}
	if an.V != protoVersion {
		a.logf("SEC", ip, "protocol v%d from %s, this build speaks v%d — ignored", an.V, ip, protoVersion)
		return
	}

	edRaw, err := base64.StdEncoding.DecodeString(an.Ed)
	if err != nil || len(edRaw) != ed25519.PublicKeySize {
		a.logf("SEC", ip, "announce carried an unusable Ed25519 key — dropped")
		return
	}
	edPub := ed25519.PublicKey(edRaw)

	// The fingerprint must be derived from the key in the same datagram.
	if got := Fingerprint(edPub); got != an.FP {
		a.logf("SEC", ip, "FINGERPRINT FORGERY claimed=%s but key hashes to %s — dropped",
			shortFP(an.FP), shortFP(got))
		return
	}
	if !VerifySig(edPub, announcePayload(&an), an.Sig) {
		a.logf("SEC", ip, "SIGNATURE INVALID on %s announce from %s — dropped", via, shortFP(an.FP))
		return
	}

	// Freshness and monotonicity: a captured announce cannot be replayed later.
	skew := time.Since(time.UnixMilli(an.TS))
	if skew > clockSkew || skew < -clockSkew {
		a.logf("SEC", ip, "STALE ANNOUNCE from %s is %s outside the freshness window — dropped",
			shortFP(an.FP), dur(skew.Abs()))
		return
	}

	if an.T == "bye" {
		a.handleBye(ip, an.FP)
		return
	}
	if an.T != "announce" {
		a.logf("SEC", ip, "unknown discovery opcode %q — dropped", an.T)
		return
	}
	if an.Port <= 0 || an.Port > 65535 {
		a.logf("SEC", ip, "announce carried invalid transport port %d — dropped", an.Port)
		return
	}

	xkRaw, err := base64.StdEncoding.DecodeString(an.XK)
	if err != nil {
		a.logf("SEC", ip, "announce carried an unusable X25519 key — dropped")
		return
	}
	xPub, err := ecdh.X25519().NewPublicKey(xkRaw)
	if err != nil {
		a.logf("SEC", ip, "announce carried an unusable X25519 key — dropped")
		return
	}

	nick := sanitizeNick(an.Nick)
	if nick == "" {
		nick = shortFP(an.FP)
	}

	a.mu.Lock()
	p, known := a.peers[an.FP]
	if known && an.TS <= p.LastTS {
		a.mu.Unlock()
		return // duplicate or replayed announce; silently ignore
	}
	isNew := !known
	if isNew {
		p = &Peer{FP: an.FP, First: time.Now()}
		a.peers[an.FP] = p
	}
	prevIP := p.IP
	p.Nick, p.IP, p.Port = nick, ip, an.Port
	p.EdPub, p.XPub = edPub, xPub
	p.Last, p.LastTS, p.Direct = time.Now(), an.TS, true
	snapshot := *p // copy for use outside the lock
	a.mu.Unlock()

	obs := a.trust.Observe(an.FP, nick)

	if isNew {
		a.logf("NET", net.JoinHostPort(ip, strconv.Itoa(an.Port)),
			"PEER UP %s via %s — fingerprint %s", nick, via, shortFP(an.FP))
		switch obs.Status {
		case "new":
			a.logf("CRY", ip, "first sighting of %s — key pinned on trust-on-first-use", shortFP(an.FP))
		case "known":
			a.logf("CRY", ip, "fingerprint %s matches the pinned key for %s", shortFP(an.FP), nick)
		case "renamed":
			a.logf("NET", ip, "%s previously appeared as %q — same key, so this is a rename, not a spoof",
				nick, obs.PrevNick)
		case "impersonation":
			a.mu.Lock()
			p.flag("NAME-CONFLICT")
			a.mu.Unlock()
			a.logf("SEC", ip,
				"NAME CONFLICT %q is already pinned to a different key (%s) — one of them is impersonating",
				nick, shortFP(obs.OtherFP))
		}
		if obs.Verified {
			a.logf("CRY", ip, "%s is manually verified — safety number confirmed out of band", nick)
		}
		go a.dialPeer(snapshot)
	} else if prevIP != "" && prevIP != ip {
		// Same key, new address. With signatures this is benign — only the
		// keyholder could have produced it — so it is roaming, not a hijack.
		a.logf("NET", ip, "%s moved %s -> %s (signature still valid, key unchanged)", nick, prevIP, ip)
	}

	a.probeGossip(an.Gossip)
	a.pushPeers()
}

func (a *App) handleBye(ip, fp string) {
	a.mu.Lock()
	p, ok := a.peers[fp]
	if ok {
		delete(a.peers, fp)
	}
	c := a.conns[fp]
	a.mu.Unlock()
	if c != nil {
		c.close("peer announced departure")
	}
	if ok {
		a.logf("NET", ip, "%s signed off — session %s closed", p.Nick, shortFP(fp))
		a.pushPeers()
	}
}

// probeGossip unicasts our announce to addresses we heard about but have no
// peer for, so the two of us can introduce ourselves properly.
func (a *App) probeGossip(hints []string) {
	if len(hints) == 0 {
		return
	}
	a.mu.Lock()
	known := make(map[string]bool, len(a.peers))
	for _, p := range a.peers {
		known[p.IP] = true
	}
	a.mu.Unlock()

	for _, h := range hints {
		host, _, err := net.SplitHostPort(h)
		if err != nil {
			continue
		}
		if known[host] || isLocalIP(host) {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			continue
		}
		a.logf("NET", host, "gossip hint — probing with a direct announce")
		a.sendTo(a.buildAnnounce("announce"), &net.UDPAddr{IP: ip.To4(), Port: a.discoPort})
	}
}

// ---------------------------------------------------------------- outbound

func (a *App) announceLoop() {
	t := time.NewTicker(announceEvery)
	defer t.Stop()
	a.sendAnnounce()
	for range t.C {
		a.sendAnnounce()
	}
}

func (a *App) sendAnnounce() {
	an := a.buildAnnounce("announce")
	for _, dst := range a.discoveryTargets() {
		a.sendTo(an, dst)
	}
	a.diag.CountAnnounce()
}

func (a *App) sendBye() {
	an := a.buildAnnounce("bye")
	for _, dst := range a.discoveryTargets() {
		a.sendTo(an, dst)
	}
}

func (a *App) sendTo(an *Announce, dst *net.UDPAddr) {
	b, err := json.Marshal(an)
	if err != nil {
		return
	}
	_, _ = a.udp.WriteToUDP(b, dst)
}

// discoveryTargets is the global broadcast address, loopback (so two instances
// on one machine find each other), every interface's subnet broadcast, the
// multicast group, and any manually seeded peers.
func (a *App) discoveryTargets() []*net.UDPAddr {
	out := []*net.UDPAddr{
		{IP: net.IPv4bcast, Port: a.discoPort},
		{IP: net.IPv4(127, 0, 0, 1), Port: a.discoPort},
	}
	if a.multicast {
		if ip := net.ParseIP(multicastGroup); ip != nil {
			out = append(out, &net.UDPAddr{IP: ip, Port: a.discoPort})
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, ad := range addrs {
				ipn, ok := ad.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipn.IP.To4()
				if ip4 == nil {
					continue
				}
				mask := ipn.Mask
				if len(mask) == 16 {
					mask = mask[12:]
				}
				if len(mask) != 4 {
					continue
				}
				bc := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					bc[i] = ip4[i] | ^mask[i]
				}
				out = append(out, &net.UDPAddr{IP: bc, Port: a.discoPort})
			}
		}
	}
	for _, s := range a.seeds {
		host, portStr, err := net.SplitHostPort(s)
		port := a.discoPort
		if err != nil {
			host = s
		} else if pn, err := strconv.Atoi(portStr); err == nil {
			port = pn
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, &net.UDPAddr{IP: ip4, Port: port})
				break
			}
		}
	}
	return out
}
