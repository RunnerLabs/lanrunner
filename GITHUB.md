# Putting Lanrunner on GitHub (private)

## Before you start: don't commit your keys

`identity.json` holds your Ed25519 seed and X25519 private key. Anyone who has
that file can impersonate you on the network. `known_peers.json` and `history/`
reveal who you talk to and what you said.

The included `.gitignore` already excludes all of them. Just don't override it,
and don't use `git add -f` on those names.

By default those files live in your Windows config directory, not in this
folder — so unless you ran with `-data .\something`, there's nothing to worry
about. Check anyway:

```powershell
cd C:\Users\patri\lanrunner
git status --short
```

If `identity.json` or `history/` appear in that list, stop and tell me.

---

## Option A — GitHub website, no tools (easiest)

1. Go to <https://github.com/new>.
2. Repository name: `lanrunner`. Select **Private**. Don't tick "Add a README"
   — you already have one.
3. Click **Create repository**.
4. On the next page click **uploading an existing file**.
5. Open `C:\Users\patri\lanrunner` in Explorer, select all the files, and drag
   them into the browser. Upload these 14:

   ```
   main.go          identity.go      crypto.go        transport.go
   discovery.go     diag.go          store.go         httpui.go
   reuse_unix.go    reuse_windows.go reuse_other.go
   go.mod           index.html
   README.md        QUICKSTART.md    GITHUB.md        .gitignore
   ```

   Do **not** upload `lanrunner.exe` — it's a build artifact, and GitHub will
   complain about the size.

   Explorer hides files starting with a dot. To get `.gitignore` in, either turn
   on **View → Show → Hidden items**, or use Option B.

6. Type a commit message and click **Commit changes**.

---

## Option B — git command line

Install Git for Windows from <https://git-scm.com/download/win> if you don't
have it, then:

```powershell
cd C:\Users\patri\lanrunner

git init
git add .
git commit -m "Lanrunner: offline encrypted LAN messenger"
git branch -M main
```

Create the empty **private** repo at <https://github.com/new> (no README, no
.gitignore, no license), then:

```powershell
git remote add origin https://github.com/YOUR-USERNAME/lanrunner.git
git push -u origin main
```

Git will open a browser window to sign in the first time. After that, pushing
future changes is:

```powershell
git add .
git commit -m "what changed"
git push
```

---

## Getting at it from your other account

This is the part that isn't obvious: **a private repo is visible only to the
account that owns it.** Your second account won't see it just by being yours —
GitHub has no concept of "my other account."

From the account that owns the repo:

1. Open the repo → **Settings** → **Collaborators** (left sidebar).
2. Click **Add people**.
3. Enter your other account's username or the email on it.
4. Send the invite.

Then sign in as the other account, check its notifications or email, and accept.
It'll have full access from then on.

Private repos allow unlimited collaborators on the free plan, so this costs
nothing.

### Alternative: transfer to an organisation

If you expect to juggle both accounts regularly, make a free organisation, move
the repo into it, and add both accounts as members. Slightly more setup, but you
stop thinking about which account owns what.

---

## Cloning it on the other machine

```powershell
git clone https://github.com/YOUR-USERNAME/lanrunner.git
cd lanrunner
go build -o lanrunner.exe .
```

That machine generates its **own** identity key on first run, which is correct —
each device should have a distinct identity. Two devices sharing one key would
look like impersonation to everyone else, and Lanrunner would flag it.
