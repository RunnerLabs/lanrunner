package main

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Diag watches the network plumbing and turns "nobody shows up" into a
// specific, actionable answer instead of a shrug.
//
// The key trick: every announce is also sent to 127.0.0.1, so we should always
// receive our own datagram back. If we never do, inbound UDP is being dropped
// locally — almost always a host firewall — and no amount of waiting will help.
type Diag struct {
	app *App

	bindB, bindM                                      atomic.Bool
	announces, datagrams, loopback, inbound, dialFail atomic.Int64

	mu      sync.Mutex
	sev     string // ok | warn | crit | pending
	verdict string
	detail  string
	fixes   []string
}

func NewDiag(a *App) *Diag {
	d := &Diag{app: a, sev: "pending", verdict: "Running startup checks…"}
	return d
}

func (d *Diag) MarkBind(which string) {
	if which == "broadcast" {
		d.bindB.Store(true)
	} else {
		d.bindM.Store(true)
	}
}

func (d *Diag) MarkLoopback()  { d.loopback.Add(1) }
func (d *Diag) CountDatagram() { d.datagrams.Add(1) }
func (d *Diag) CountAnnounce() { d.announces.Add(1) }
func (d *Diag) CountInbound()  { d.inbound.Add(1) }
func (d *Diag) CountDialFail() { d.dialFail.Add(1) }

type DiagView struct {
	Sev       string   `json:"sev"`
	Verdict   string   `json:"verdict"`
	Detail    string   `json:"detail"`
	Fixes     []string `json:"fixes"`
	Announces int64    `json:"announces"`
	Datagrams int64    `json:"datagrams"`
	Loopback  int64    `json:"loopback"`
	Inbound   int64    `json:"inbound"`
	DialFail  int64    `json:"dial_fail"`
	Peers     int      `json:"peers"`
	Sessions  int      `json:"sessions"`
	Broadcast bool     `json:"broadcast"`
	Multicast bool     `json:"multicast"`
}

func (d *Diag) Snapshot() DiagView {
	d.app.mu.Lock()
	peers := len(d.app.peers)
	sessions := len(d.app.conns)
	d.app.mu.Unlock()

	d.mu.Lock()
	defer d.mu.Unlock()
	return DiagView{
		Sev: d.sev, Verdict: d.verdict, Detail: d.detail,
		Fixes:     append([]string(nil), d.fixes...),
		Announces: d.announces.Load(), Datagrams: d.datagrams.Load(),
		Loopback: d.loopback.Load(), Inbound: d.inbound.Load(),
		DialFail: d.dialFail.Load(),
		Peers:    peers, Sessions: sessions,
		Broadcast: d.bindB.Load(), Multicast: d.bindM.Load(),
	}
}

func (d *Diag) set(sev, verdict, detail string, fixes ...string) {
	d.mu.Lock()
	changed := d.sev != sev || d.verdict != verdict
	d.sev, d.verdict, d.detail, d.fixes = sev, verdict, detail, fixes
	d.mu.Unlock()

	if changed {
		level := "SYS"
		if sev == "crit" {
			level = "SEC"
		} else if sev == "warn" {
			level = "NET"
		}
		d.app.logf(level, "diagnostics", "%s — %s", verdict, detail)
		for _, f := range fixes {
			d.app.logf(level, "diagnostics", "  fix: %s", f)
		}
	}
}

// Run gives discovery a grace period, then keeps re-evaluating.
func (d *Diag) Run() {
	time.Sleep(10 * time.Second)
	d.evaluate()

	push := time.NewTicker(3 * time.Second)
	eval := time.NewTicker(15 * time.Second)
	defer push.Stop()
	defer eval.Stop()
	for {
		select {
		case <-push.C:
			d.app.emit("diag", d.Snapshot())
		case <-eval.C:
			d.evaluate()
		}
	}
}

func (d *Diag) evaluate() {
	a := d.app
	a.mu.Lock()
	peers := len(a.peers)
	sessions := len(a.conns)
	a.mu.Unlock()

	fwHint := "allow lanrunner through the firewall on your private network"
	switch runtime.GOOS {
	case "windows":
		fwHint = fmt.Sprintf("Windows Defender Firewall: allow lanrunner.exe on Private networks (UDP %d and TCP %d inbound)",
			a.discoPort, a.tcpPort)
	case "darwin":
		fwHint = "System Settings → Network → Firewall → Options: allow incoming connections for lanrunner"
	case "linux":
		fwHint = fmt.Sprintf("ufw: sudo ufw allow %d/udp && sudo ufw allow %d/tcp", a.discoPort, a.tcpPort)
	}

	switch {
	case !d.bindB.Load():
		d.set("crit",
			"Discovery socket never bound",
			fmt.Sprintf("Nothing is listening on UDP %d, so no peer can ever be seen.", a.discoPort),
			fmt.Sprintf("another process may hold port %d — try -disco 47102 on every device", a.discoPort),
			"on some systems binding a low port needs elevated rights; this one should not")

	case d.loopback.Load() == 0 && d.announces.Load() > 2:
		d.set("crit",
			"Inbound UDP is being dropped on this machine",
			fmt.Sprintf("We sent %d announces including to 127.0.0.1 and received none back. That is a local block, not a network problem.",
				d.announces.Load()),
			fwHint,
			"some VPN clients and endpoint-security agents silently drop broadcast traffic — try disabling temporarily to confirm")

	case peers == 0:
		d.set("warn",
			"No peers found yet",
			fmt.Sprintf("Our own datagrams loop back fine (%d seen), so this machine is transmitting and receiving. Nobody else has answered.",
				d.loopback.Load()),
			"confirm another device is actually running Lanrunner",
			fmt.Sprintf("confirm every device uses the same -disco port (this one: %d)", a.discoPort),
			"if you are on guest or hotel Wi-Fi, client isolation is blocking peer traffic — nothing in the app can bypass it",
			"across subnets or with isolation on, seed directly: -peer 192.168.1.42")

	case sessions == 0 && d.dialFail.Load() > 0:
		d.set("warn",
			"Peers are visible but sessions will not open",
			fmt.Sprintf("%d peer(s) announced, %d dial attempts failed. Discovery (UDP) is passing while the TCP transport is blocked.",
				peers, d.dialFail.Load()),
			fwHint,
			"the other device may be blocking inbound TCP — check its diagnostics panel too")

	case d.inbound.Load() == 0 && sessions > 0:
		d.set("warn",
			"Outbound works, inbound never arrives",
			"We opened sessions ourselves but no peer has ever connected to us. Our inbound TCP is probably blocked. Messaging still works over the sessions we opened.",
			fwHint)

	default:
		d.set("ok",
			"Network healthy",
			fmt.Sprintf("%d peer(s), %d encrypted session(s), %d datagrams received.",
				peers, sessions, d.datagrams.Load()))
	}

	d.app.emit("diag", d.Snapshot())
}
