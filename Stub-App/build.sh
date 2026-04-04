#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

ANDROID_JAR="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platforms/android-36/android.jar"
D8_BIN="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools/36.1.0/d8"

if [ ! -f "$ANDROID_JAR" ]; then
    echo "ERROR: android.jar not found at $ANDROID_JAR" >&2; exit 1
fi
if [ ! -f "$D8_BIN" ]; then
    echo "ERROR: d8 not found at $D8_BIN" >&2; exit 1
fi

rm -rf build/classes
mkdir -p build/classes

echo "[1/2] javac → .class"
javac --release 17 \
    -cp "$ANDROID_JAR" \
    -d build/classes \
    src/com/shell/stub/utils/RefInvoke.java \
    src/com/shell/stub/ProxyApplication.java

echo "[2/2] d8 → classes.dex"
"$D8_BIN" \
    --min-api 21 \
    --lib "$ANDROID_JAR" \
    --output build/ \
    build/classes/com/shell/stub/ProxyApplication.class \
    build/classes/com/shell/stub/utils/RefInvoke.class

echo "Done: build/classes.dex ($(wc -c < build/classes.dex) bytes)"
