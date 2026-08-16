# Lanrunner

An early 2000's messenger for a single local network. No internet, no server, no
accounts. Devices find each other by UDP broadcast and multicast, then hold
long-lived TCP sessions encrypted end to end. The UI is plain HTML and
bare-bones CSS served on loopback.

> **Early beta:** This is pre-release software. The one-screen download page
> lives in [`site/index.html`](site/index.html); it is intentionally separate
> from the in-app interface embedded by the Go program.

Public beta page: <https://runnerlabs.github.io/lanrunner/>

Official source and releases:
<https://github.com/RunnerLabs/lanrunner>

The public page provides a per-user Windows installer with Start Menu and
optional desktop shortcuts. The application source is public in this
repository.

Zero third-party dependencies — everything is Go's standard library, so it
builds on a machine that has never been online.

## Build

Needs Go 1.21+ (crypto/ecdh landed in 1.20).

```
go build -trimpath -o lanrunner .          # macOS / Linux
go build -trimpath -o lanrunner.exe .      # Windows
```

One self-contained binary; the HTML is compiled in. Cross-compile for the rest
of the fleet from one machine:

```
GOOS=windows GOARCH=amd64 go build -trimpath -o lanrunner.exe .
GOOS=darwin  GOARCH=arm64 go build -trimpath -o lanrunner-mac .
GOOS=linux   GOARCH=amd64 go build -trimpath -o lanrunner-linux .
```

## Run

```
./lanrunner -nick alice
```

Lanrunner opens <http://127.0.0.1:8080> in your default browser automatically.
Start it on another device and the two find each other in about three seconds.
Launching Lanrunner again opens the existing interface instead of starting a
second background copy. Use **CLEAR ROOM** or **CLEAR MESSAGES** to erase the
active transcript from the current local session. Use **EXIT APP** to stop the
background process, erase every in-memory transcript, and release its ports.
Lanrunner also shuts itself down after 30 minutes without chat activity.

### Native Linux

Native Linux packages are available for x86_64 (`linux-amd64`) and ARM64
(`linux-arm64`):

```sh
chmod +x launch-lanrunner-linux.sh lanrunner
./launch-lanrunner-linux.sh
```

The launcher starts Lanrunner in the background, waits for the local interface,
and opens `http://127.0.0.1:8080` through `xdg-open` or `gio`. Its launch log is
saved under `$XDG_STATE_HOME/lanrunner/native-launch.log` (or
`~/.local/state/lanrunner/native-launch.log`).

### Firewall

Lanrunner uses fixed LAN ports so firewall rules survive restarts:

- UDP `47100` for peer discovery
- TCP `47101` for encrypted messaging

On Linux with UFW:

```sh
sudo ufw allow 47100/udp
sudo ufw allow 47101/tcp
```

On Windows, allow `Lanrunner.exe` on Private networks when Defender prompts.
Administrators can also create explicit inbound rules in PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Lanrunner Discovery" -Direction Inbound -Protocol UDP -LocalPort 47100 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "Lanrunner Messaging" -Direction Inbound -Protocol TCP -LocalPort 47101 -Action Allow -Profile Private
```

| flag | default | meaning |
|---|---|---|
| `-nick` | hostname | display name |
| `-ui` | `8080` | loopback UI port |
| `-tcp` | `47101` | TCP messaging port; `0` chooses an automatic port |
| `-disco` | `47100` | UDP discovery port — must match on every device |
| `-peer` | — | seed a peer by address, repeatable: `-peer 192.168.1.42` |
| `-data` | OS config dir | where identity and trust settings live; chat history stays in memory |
| `-no-browser` | off | do not open the local web UI automatically |
| `-idle` | `30m` | shut down after this much inactivity; `0` disables it |
| `-no-multicast` | off | broadcast only |
| `-v` | off | log heartbeat frames too |

Two instances on one machine:
`./lanrunner -nick bob -ui 8081 -tcp 47102 -data ./bob`. Give the second one
its own `-data` directory and TCP port or it will reuse the same identity key
and contend for the default messaging port.

## Guest kits — talking to someone who doesn't run Lanrunner

Everything above assumes both ends run Lanrunner. A guest kit is for the person
who doesn't and isn't going to install anything.

In the diagnostics panel, under **Guest Kits**, name the person and press
**Generate guest folder**. You get a folder holding one self-contained HTML
file. Send them the folder; they open `index.html` on the same network and you
have a conversation. Nothing is installed, nothing is downloaded at run time,
and no traffic leaves the LAN.

Guest conversations appear as ordinary tabs alongside peers.

### Phones use the QR code instead

The folder works on a computer. It cannot work on a phone, and that is a
platform rule rather than something the app can route around: iOS has no way to
open a downloaded HTML file as a real page, because the Files app previews it in
Quick Look, which sandboxes scripts and blocks the network.

So phones fetch the page from you instead. Expand **QR code for phones** on any
kit and point a camera at it. It is collapsed by default and costs no space
until you open it.

The phone will warn that the certificate is not trusted. That is expected on a
local network — there is no certificate authority on an offline LAN, and getting
one would mean the internet access this app exists to avoid. Tap through it. The
session is genuinely encrypted; the warning only says nobody has vouched for the
name. The certificate fingerprint is shown next to the QR if a guest wants to
confirm it out of band, exactly like a peer safety number.

TLS is not decoration here. Browsers only expose the Web Crypto API in a secure
context, so a plain `http://` LAN address could never produce an encrypted phone
session. The gateway generates a self-signed certificate on first use and keeps
it, so a guest who accepts it once is not asked again after a restart.

### What a guest can and cannot reach

A guest reaches exactly one conversation — the invite's own. Never the peer
list, the console, diagnostics, the room, or another invite.

The gateway only exists while a usable invite exists, and closes and releases
its ports the moment the last one is revoked or expires. If you have never made
a kit, Lanrunner opens no LAN-facing port at all.

### Treat a kit like a password

The folder contains a 256-bit invite token. Anyone who gets a copy can message
you as that guest, so send it the way you would send a password, and press
**Revoke** when the conversation is over — their copy stops working immediately.
Invites also expire on their own after seven days, so a folder you forget about
stops being useful without you having to remember it.

The QR carries a short-lived handoff code rather than the token itself, because
whatever sits in a URL is the weakest part of the exchange. Codes last 30
minutes and reissuing one never invalidates another.

### Guest options

```
-guest 47102            LAN port for guest kits (opened only while an invite exists)
-guest-tls 47103        HTTPS port; phones can only connect over this
-no-guest               disable guest kits entirely
-no-guest-tls           no HTTPS gateway (phones will not work)
-kits <path>            where generated folders are written
-guest-ttl 168h         how long invites last (0 disables expiry)
-guest-any-source       accept guests from outside private LAN ranges
```

## Security model

**Identity.** On first run each device generates an Ed25519 keypair and an
X25519 static key, stored in `identity.json` (mode 0600). Your session ID *is*
the fingerprint of your Ed25519 public key, so a session ID cannot be claimed
by anyone who doesn't hold the private key. Every announce and every handshake
is signed. A forged fingerprint is rejected before anything else happens,
because the fingerprint is recomputed from the key in the same datagram.

**Sessions.** The handshake is a signed X25519 ECDH. Both identities are mixed
into the key derivation (HKDF-SHA256), which blocks unknown-key-share attacks.
Each direction gets its own AES-256-GCM key and a counter nonce.

Counter nonces are why the old sequence-number heuristics are gone: a replayed,
reordered, or injected frame decrypts against the wrong counter and fails
authentication outright. There is no heuristic left to defeat.

**Trust on first use.** Fingerprints are pinned in `known_peers.json` the first
time you see them. If a display name ever shows up attached to a different key,
that's a `NAME CONFLICT` in the console and a red badge in the buddy list.

**Manual verification.** Click a buddy to see their safety number. Read it
aloud to them; if it matches, hit *Mark verified*. That's the only step that
upgrades trust-on-first-use into actual authentication, and it's the same model
Signal uses.

**Guests are authenticated differently, and it's worth being clear about how.**
A peer proves who it is with a key you can pin and verify. A guest proves only
that it holds the folder you sent. Possession of the invite token *is* the
identity, which is why revocation and expiry matter more there.

Guest sessions use P-256 ECDH with the invite token as the HKDF salt, so the key
exchange is authenticated by that shared secret: someone sitting in the middle of
the LAN cannot derive the key without the folder, and someone who has the folder
is the person you invited. Each direction gets its own AES-256-GCM key.

Guest frames carry a counter inside the sealed payload, checked against a
sliding window. AES-GCM proves a frame is authentic but not that it is *new*, and
a captured request replayed verbatim would otherwise decrypt perfectly. The
window rather than a high-water mark, because a browser fires typing and message
requests concurrently and does not guarantee their order.

A guest picks its own display name, so the operator's panel shows the invite
label you chose as the identity and the guest's chosen name only as a secondary
detail. Otherwise a guest could name itself after one of your peers.

The gateway also refuses connections from outside private LAN ranges, backs off
an address after repeated failed handshakes, rate-limits each session, and
compares tokens in constant time — including a decoy comparison for unknown
invite ids, so response timing does not reveal which invites exist.

## Efficiency

Sessions are long-lived and pooled — one TCP connection per peer, reused for
every message, with an 8-second encrypted heartbeat that doubles as the RTT
measurement. Simultaneous connects are resolved deterministically (keep the one
whose dialer has the smaller fingerprint), so both ends converge on the same
survivor without negotiation.

## When nobody shows up

The diagnostics panel answers this instead of making you guess. Every announce
is also sent to `127.0.0.1`, so we should always receive our own datagram back.
If we never do, inbound UDP is being dropped locally — a host firewall, a VPN
client, or an endpoint agent — and no amount of waiting will help. The panel
distinguishes that from "discovery works but TCP is blocked" and from "nothing
is wrong, nobody else is running it," and prints the fix for your OS.

Discovery covers more ground than before:

- **broadcast** to the global and per-interface subnet broadcast addresses
- **multicast** on `239.255.42.99` — some networks filter one but not the other
- **manual seeds** via `-peer`, for crossing subnets or routing around isolation
- **gossip** — peers share the addresses they can see, so two devices that can
  each reach you but not each other get introduced

Gossip carries addresses only. A peer is never created from a gossip hint; we
just probe the address, and identity is still established by that device's own
signed announce.

The one thing that still can't be fixed in software is **AP isolation** — many
guest, hotel, and office networks block client-to-client traffic entirely. Use
`-peer` if unicast still works between the devices, otherwise you need a
network you control.

## The console

Filterable and searchable, streamed live.

- **SYS** — process, identity, bind events
- **NET** — peer up/down, session lifecycle, dial results, roaming
- **CRY** — key generation, fingerprint pinning, session establishment, verification
- **PKT** — frame inspection: conversation, message id, plaintext size, AEAD counter
- **SEC** — anything that failed validation

### What triggers a SEC line

| check | signature |
|---|---|
| fingerprint forgery | claimed session ID doesn't match the hash of the key in the same datagram |
| signature invalid | announce or handshake signature doesn't verify |
| stale announce | timestamp outside the ±120s freshness window (captured-and-replayed announce) |
| name conflict | a display name already pinned to a different key |
| handshake rejected | wrong fingerprint, bad key, protocol mismatch, clock skew |
| AEAD authentication failure | frame tampered with, replayed, or injected |
| control characters | terminal-escape bytes stripped from a payload |
| oversized frame | declared length above the 64 KiB ceiling |
| unknown opcode | message type this build doesn't speak |

Everything also goes to stdout: `./lanrunner -nick alice | tee run.log`.

## Storage

Only long-lived identity and trust settings live in the data directory
(`-data`, default your OS config dir):

```
identity.json      Ed25519 seed + X25519 private key, mode 0600
known_peers.json   pinned fingerprints, nicknames, verification state
guests.json        guest invites and their tokens, mode 0600
guest-cert.pem     self-signed certificate for the HTTPS guest gateway
guest-key.pem      its private key, mode 0600
```

The guest files appear only once you generate a kit. `guests.json` holds live
invite tokens, so it is as sensitive as `identity.json`. Revoking an invite in
the UI is the way to retire one.

Chat transcripts are **memory-only**. They are not written to disk, are erased
when Lan Runner exits, and can be erased during a run with **CLEAR ROOM** or
**CLEAR MESSAGES**. Closing and reopening the browser UI during the same running
app session does not restore data from disk; it only shows messages still held
in that process. On startup, this release also deletes plaintext
`history/*.jsonl` transcript files left by earlier beta builds. Identity keys
and verified-peer fingerprints remain available so trusted devices do not look
new after every launch.

## Remaining limits, honestly

- **Early beta.** The project now passes `go test ./...` and builds on Windows,
  Linux x86_64, Linux ARM64, and Windows x86/x64, but it has not yet had broad
  real-world testing across different distributions, routers, firewalls, VPNs,
  and operating systems. Expect rough edges while the discovery and connection
  paths are exercised on more networks.
- **Room messages are encrypted per session, not group-encrypted.** Each peer
  gets its own sealed copy over its own session. That's fine for a LAN-sized
  room, but it's N sends per message and there's no forward secrecy across
  restarts: session keys are ephemeral per connection, but the static X25519
  key is long-lived, so a stolen identity file plus a full packet capture would
  expose past sessions. Rotating with an ephemeral-ephemeral handshake would
  fix it.
- **Announces are unencrypted.** They have to be readable to bootstrap, so
  anyone on the LAN can see who is running Lanrunner, their display name, and
  their public keys. They cannot read messages or impersonate anyone. Wrapping
  discovery in a shared room passphrase would hide even that.
- **Metadata is visible.** Message sizes and timing are observable on the wire
  even though contents aren't.
- **Trust on first use is only as good as the first use.** If an attacker is
  already in place the very first time you see a peer, you'll pin their key.
  Verifying safety numbers out of band is what closes that hole.
- **A guest kit is a bearer token.** Anyone holding the folder is the guest;
  there is no second factor and no key to pin. That is the cost of requiring
  nothing to be installed. Revoke when you're done, and note that the seven-day
  expiry limits the damage rather than preventing it.
- **The guest certificate is self-signed, so guests see a warning.** There is no
  certificate authority on an offline LAN, and getting one would need the
  internet access this app exists to avoid. Guests are trained to click through
  a warning, which is not a habit worth encouraging — but the alternative is no
  encryption on phones at all. The fingerprint is displayed so it can be checked
  out of band.
