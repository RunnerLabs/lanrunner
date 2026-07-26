LANRUNNER 0.1.5-BETA — NATIVE LINUX QUICK START

This package runs directly on Linux.

1. Extract the archive.
2. Open a terminal in the extracted directory.
3. Run:

     chmod +x launch-lanrunner-linux.sh lanrunner
     ./launch-lanrunner-linux.sh

The launcher starts Lanrunner in the background, waits for its local interface,
and opens http://127.0.0.1:8080 in your normal Linux browser.

Lanrunner uses these fixed LAN ports:

  UDP 47100   Peer discovery
  TCP 47101   Encrypted messaging

When UFW is active, allow them once:

  sudo ufw allow 47100/udp
  sudo ufw allow 47101/tcp

Choose the package matching your computer:

  linux-amd64   Most Intel and AMD desktop/laptop computers
  linux-arm64   ARM64 computers, including many Linux SBCs

The native launch log is written to:

  $XDG_STATE_HOME/lanrunner/native-launch.log

or, when XDG_STATE_HOME is unset:

  ~/.local/state/lanrunner/native-launch.log

Lanrunner data is stored under your Linux user configuration directory,
normally ~/.config/lanrunner. Use Exit Lanrunner in the browser interface to
stop the background process and release its ports.
