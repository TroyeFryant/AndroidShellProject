#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CPP_DIR="$SCRIPT_DIR/app/src/main/cpp"
OUT_DIR="$SCRIPT_DIR/libs"

NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk}"
# Pick the latest NDK version available
NDK_VER=$(ls "$NDK_ROOT" 2>/dev/null | sort -V | tail -1)
if [ -z "$NDK_VER" ]; then
    echo "ERROR: No NDK found under $NDK_ROOT" >&2
    exit 1
fi
NDK="$NDK_ROOT/$NDK_VER"
echo "[NDK] Using $NDK"

CMAKE_BIN="$NDK/build/cmake/bin/cmake"
if [ ! -x "$CMAKE_BIN" ]; then
    CMAKE_BIN=$(command -v cmake 2>/dev/null || true)
    if [ -z "$CMAKE_BIN" ]; then
        echo "ERROR: cmake not found" >&2
        exit 1
    fi
fi

TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
ABIS="arm64-v8a armeabi-v7a x86_64 x86"
MIN_API=21

rm -rf "$OUT_DIR"

for ABI in $ABIS; do
    echo ""
    echo "════════════════════════════════════════"
    echo "  Building: $ABI"
    echo "════════════════════════════════════════"
    BUILD="$SCRIPT_DIR/build_native/$ABI"
    mkdir -p "$BUILD"

    "$CMAKE_BIN" -S "$CPP_DIR" -B "$BUILD" \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
        -DANDROID_ABI="$ABI" \
        -DANDROID_NATIVE_API_LEVEL="$MIN_API" \
        -DCMAKE_BUILD_TYPE=Release \
        -DANDROID_STL=c++_static

    "$CMAKE_BIN" --build "$BUILD" --config Release -j"$(sysctl -n hw.ncpu)"

    DST="$OUT_DIR/$ABI"
    mkdir -p "$DST"
    cp "$BUILD/libguard.so" "$DST/libguard.so"
    echo "[OK] $DST/libguard.so ($(wc -c < "$DST/libguard.so") bytes)"
done

rm -rf "$SCRIPT_DIR/build_native"

echo ""
echo "════════════════════════════════════════"
echo "  All ABIs built → $OUT_DIR/"
ls -R "$OUT_DIR"
echo "════════════════════════════════════════"
