#!/bin/bash
set -e

EMULATOR_HOST="${EMULATOR_HOST:-android-emulator}"
EMULATOR_PORT="${EMULATOR_PORT:-5555}"
SERIAL="${EMULATOR_HOST}:${EMULATOR_PORT}"
MAX_WAIT="${MAX_WAIT_SECONDS:-300}"
INTERVAL=10

echo "[runner] Waiting for ADB on $SERIAL (timeout ${MAX_WAIT}s)..."
elapsed=0
while true; do
    result=$(adb connect "$SERIAL" 2>&1 || true)
    if echo "$result" | grep -qE "connected|already"; then
        echo "[runner] ADB connected: $result"
        break
    fi
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "[runner] ERROR: Could not connect to emulator after ${MAX_WAIT}s" >&2
        exit 1
    fi
    echo "[runner] Not ready yet (${elapsed}s elapsed) — $result"
    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
done

echo "[runner] Waiting for sys.boot_completed..."
while true; do
    booted=$(adb -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n' || true)
    if [ "$booted" = "1" ]; then
        echo "[runner] Emulator fully booted."
        break
    fi
    echo "[runner] boot_completed=$booted — waiting..."
    sleep 10
done

echo "[runner] Installing APK..."
adb -s "$SERIAL" install -r /apk-input/app-release.apk 2>&1 || {
    echo "[runner] WARN: APK install failed — tests will run without fresh install"
}

echo "[runner] Running security test suite..."
pwsh -File /scripts/test-android-docker.ps1 \
    -AdbHost "$EMULATOR_HOST" \
    -AdbPort "$EMULATOR_PORT"
