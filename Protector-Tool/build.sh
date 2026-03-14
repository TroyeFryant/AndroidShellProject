#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
OUT_DIR="$SCRIPT_DIR/build"

echo "=== 编译 Protector-Tool (Java 17) ==="

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

javac --release 17 \
    -d "$OUT_DIR" \
    "$SRC_DIR"/com/shell/protector/*.java

echo "编译完成 -> $OUT_DIR"
echo ""
echo "运行示例:"
echo "  java -cp $OUT_DIR com.shell.protector.Main <input.apk> <output_dir>"
