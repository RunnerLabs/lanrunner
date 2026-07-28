# Lanrunner — Quickstart (Windows)

## First, the thing that's confusing

Do **not** open `index.html` by double-clicking it. That page is only the
dashboard. The actual program is the Go code, and it *serves* that page to your
browser. Opened directly as a file, it has nothing to talk to — every field
shows `—` and it says "reconnecting…" forever.

The real sequence is: install Go → build one `.exe` → run the `.exe` → open the
address it prints.

---

## Step 1 — Move the folder somewhere permanent

The folder these files are in is temporary. Copy the whole `lanrunner` folder
to somewhere stable, for example:

```
C:\Users\YourName\lanrunner
```

## Step 2 — Install Go

Download the Windows installer from <https://go.dev/dl/> (the `.msi` file) and
run it. Click through the defaults.

Then **close and reopen** PowerShell — the installer changes your PATH and open
windows won't see it. Check it worked:

```powershell
go version
```

You should see something like `go version go1.23.x windows/amd64`. If you get
"not recognized", reopen PowerShell; if it still fails, restart Windows.

## Step 3 — Build it

Open PowerShell and go to the folder:

```powershell
cd C:\Users\YourName\lanrunner
go build -o lanrunner.exe .
```

The first build takes a few seconds. **Success prints nothing at all** — that's
normal for Go. You'll see `lanrunner.exe` appear in the folder.

If it prints errors instead, copy the whole output and send it back — the code
was written without a Go toolchain available to test against, so a small fix or
two is plausible.

## Step 4 — Run it

```powershell
.\lanrunner.exe -nick pat
```

Two things happen:

1. **Windows Firewall pops up.** Tick **Private networks** and click *Allow
   access*. If you miss this, other devices can't reach you — this is the single
   most common reason nothing shows up.
2. The window prints your address and fingerprint:

```
  Lanrunner ready — open http://127.0.0.1:8080
  your fingerprint: A3F1-9C22-...
```

Leave that window open. Closing it quits the app.

## Step 5 — Open the UI

Go to <http://127.0.0.1:8080> in your browser. Note it's `http://127.0.0.1:8080`,
**not** a `file:///C:/...` path. Now the fields fill in, the console starts
scrolling, and Diagnostics turns green or tells you what's wrong.

At this point you're running and announcing. There's nobody to talk to yet.

---

## Step 6 — Get a second person on

Copy just `lanrunner.exe` to the other device — it's fully self-contained, no
Go needed there. On that machine:

```powershell
.\lanrunner.exe -nick bob
```

Allow its firewall prompt too, then open `http://127.0.0.1:8080` on *that*
machine. Within a few seconds you each appear in the other's Buddy List. Type in
the LAN Room and it arrives.

Lanrunner uses UDP `47100` for discovery and TCP `47101` for encrypted
messaging. Both must be allowed inbound on the Private network.

Both devices must be on the same Wi-Fi or switch. Different Wi-Fi networks,
guest network, or a phone hotspot won't work.

### Testing alone on one machine

Open a second PowerShell window in the same folder:

```powershell
.\lanrunner.exe -nick bob -ui 8081 -tcp 47102 -data .\bob-data
```

Then open `http://127.0.0.1:8081` in a second browser tab. You'll see two
buddies talking to each other. The separate `-data` and `-tcp` values matter —
without them the second copy reuses the same identity key and contends for the
default messaging port.

## Step 7 — Invite someone who hasn't installed anything

Step 6 assumes the other person runs Lanrunner. If they don't want to, use a
guest kit instead.

In the right-hand **Diagnostics** panel, find **Guest Kits**. Type who it's for
and press **Generate guest folder**. A folder appears on your Desktop under
`Lanrunner Guest Kits`.

**For a computer:** send them the whole folder however you like. They
double-click `index.html`, type a name, and you're talking. It's one
self-contained file — nothing to install.

**For a phone:** don't send the file. It will not work, and that's iOS's rule
rather than a bug — a downloaded HTML file opens in Quick Look, which blocks
scripts and the network. Instead expand **QR code for phones** under the kit and
point their camera at it.

Their phone will warn that the certificate isn't trusted. Tap **Show Details →
visit this website**. That warning is expected on a local network: there's no
certificate authority on an offline LAN. The connection is still encrypted — the
warning only means nobody has vouched for the name. The fingerprint is shown
next to the QR if they want to check it with you out loud.

Their messages arrive as a new tab in your window, labelled with the name you
gave the kit.

When you're done, press **Revoke**. Their copy stops working immediately.
Invites also expire on their own after a week.

> The folder holds a secret token — anyone with a copy can message you as that
> guest. Send it the way you'd send a password.

Phones connect over TCP `47103`, so allow that inbound too if you're prompted.

---

## What to click once it's running

- **Type in the box, press Enter** — goes to everyone in the LAN Room.
- **Double-click a buddy** — opens a private 1:1 tab, encrypted just for them.
- **Single-click a buddy** — shows their safety number on the right. Read it
  aloud to them; if it matches what's on their screen, click *Mark verified*.
  That's what upgrades them from "unverified" to actually authenticated.
- **Console at the bottom** — live network log. Untick SYS/NET/PKT to leave only
  SEC if you just want security events. The filter box greps everything.
- **Diagnostics on the right** — if nobody shows up, read this. It distinguishes
  "your firewall is blocking it" from "the network blocks peer traffic" from
  "nobody else is running it," and prints the fix.

## Common snags

| symptom | cause |
|---|---|
| Fields show `—`, "reconnecting…" | You opened the HTML file directly. Use `http://127.0.0.1:8080`. |
| `go: not recognized` | Reopen PowerShell after installing Go. |
| Buddy list stays empty | Firewall prompt was denied, or the other device is on a different network. Check Diagnostics. |
| Peer appears but connection times out | Allow inbound TCP `47101` on the peer device. |
| Works one direction only | One side's inbound TCP `47101` is blocked. |
| Two copies, one identity | Give the second `-data .\bob-data`. |
| Guest kit does nothing on a phone | Expected — iOS previews HTML files instead of running them. Use the QR code. |
| Phone says the link expired | Join codes last 30 minutes and don't survive restarting Lanrunner. Reopen the QR panel for a fresh one. |
| Phone says "not private" | Expected on a LAN. Tap *Show Details → visit this website*. |
| Guest page loads but never connects | Their device must be on the same network, and inbound TCP `47103` must be allowed. |

## Everyday use

```powershell
cd C:\Users\YourName\lanrunner
.\lanrunner.exe -nick pat
```

Then open <http://127.0.0.1:8080>. You only build once; after that it's just
those two lines. Ctrl-C in the PowerShell window quits and tells your peers
you've gone.
