LANRUNNER 0.1.3-BETA — WINE QUICK START

1. Extract this entire ZIP into one directory.
2. In a Linux terminal, enter that directory.
3. Run:

     chmod +x Launch-Lanrunner-with-Wine.sh
     ./Launch-Lanrunner-with-Wine.sh

The launcher starts Lanrunner through Wine, waits for the local interface, and
opens http://127.0.0.1:8080 in your Linux browser.

The x64 build is selected by default. If you use a 32-bit Wine prefix, launch
with WINEARCH=win32:

     WINEARCH=win32 ./Launch-Lanrunner-with-Wine.sh

You may choose a binary explicitly:

     LANRUNNER_WINE_EXE="$PWD/Lanrunner-x86.exe" ./Launch-Lanrunner-with-Wine.sh

The Wine launch log is written to:

  $XDG_STATE_HOME/lanrunner/wine-launch.log

or, when XDG_STATE_HOME is unset:

  ~/.local/state/lanrunner/wine-launch.log

Lanrunner's local identity and message history remain inside the selected Wine
prefix. Messages travel directly over the LAN and do not use a central server.
