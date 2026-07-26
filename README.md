# Lanrunner

An AIM-style messenger for a single local network. No internet, no server, no
accounts. Devices find each other by UDP broadcast and multicast, then hold
long-lived TCP sessions encrypted end to end. The UI is plain HTML and
bare-bones CSS served on loopback.

> **Early beta:** This is pre-release software. The one-screen download page
> lives in [`site/index.html`](site/index.html); it is intentionally separate
> from the in-app interface embedded by the Go program.

Public beta page: <https://lanrunner-beta.quantum-bydesign.chatgpt.site>

The public page provides a per-user Windows installer with Start Menu and
optional desktop shortcuts. The application source is public in this
repository.

Zero third-party dependencies — everything is Go's standard library, so it
builds on a machine that has never been online.

## Build

Needs Go 1.21+ (crypto/ecdh landed in 1.20).

```
go build -o lanrunner .          # macOS / Linux
go build -o lanrunner.exe .      # Windows
```

One self-contained binary; the HTML is compiled in. Cross-compile for the rest
of the fleet from one machine:

```
GOOS=windows GOARCH=amd64 go build -o lanrunner.exe .
GOOS=darwin  GOARCH=arm64 go build -o lanrunner-mac .
GOOS=linux   GOARCH=amd64 go build -o lanrunner-linux .
```

## Run

```
./lanrunner -nick alice
```

Lanrunner opens <http://127.0.0.1:8080> in your default browser automatically.
Start it on another device and the two find each other in about three seconds.
Launching Lanrunner again opens the existing interface instead of starting a
second background copy. Use **Exit Lanrunner** in the interface to stop the
background process and release its ports. Lanrunner also shuts itself down
after 30 minutes without chat activity.

### Native Linux

Native Linux packages are available for x86_64 (`linux-amd64`) and ARM64
(`linux-arm64`). They do not require Wine:

```sh
chmod +x launch-lanrunner-linux.sh lanrunner
./launch-lanrunner-linux.sh
```

The launcher starts Lanrunner in the background, waits for the local interface,
and opens `http://127.0.0.1:8080` through `xdg-open` or `gio`. Its launch log is
saved under `$XDG_STATE_HOME/lanrunner/native-launch.log` (or
`~/.local/state/lanrunner/native-launch.log`).

### Wine

Version 0.1.3-beta detects Wine and uses Wine's browser bridge instead of the
older `rundll32` URL handoff. The installer carries both x86 and x64 builds so
it can run in either kind of Wine prefix.

For the most reliable Wine launch, download the portable Wine package, extract
it, make the launcher executable, and run it:

```sh
chmod +x Launch-Lanrunner-with-Wine.sh
./Launch-Lanrunner-with-Wine.sh
```

The launcher starts the Windows binary without its internal browser handoff,
waits for the loopback UI, and opens `http://127.0.0.1:8080` through
`xdg-open`. Its launch log is saved under
`$XDG_STATE_HOME/lanrunner/wine-launch.log` (or
`~/.local/state/lanrunner/wine-launch.log`).

| flag | default | meaning |
|---|---|---|
| `-nick` | hostname | display name |
| `-ui` | `8080` | loopback UI port |
| `-disco` | `47100` | UDP discovery port — must match on every device |
| `-peer` | — | seed a peer by address, repeatable: `-peer 192.168.1.42` |
| `-data` | OS config dir | where keys, trust store and history live |
| `-no-browser` | off | do not open the local web UI automatically |
| `-idle` | `30m` | shut down after this much inactivity; `0` disables it |
| `-no-multicast` | off | broadcast only |
| `-v` | off | log heartbeat frames too |

Two instances on one machine: `./lanrunner -nick bob -ui 8081 -data ./bob`.
Give the second one its own `-data` directory or it will reuse the same
identity key.

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

Everything lives in the data directory (`-data`, default your OS config dir):

```
identity.json      Ed25519 seed + X25519 private key, mode 0600
known_peers.json   pinned fingerprints, nicknames, verification state
history/room.jsonl        append-only conversation log
history/<fingerprint>.jsonl
```

History is append-only, including delivery receipts, so a crash can't corrupt
it. Note it is stored in **plaintext** — the encryption protects the wire, not
the disk. If that matters, put the data directory on an encrypted volume.

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
