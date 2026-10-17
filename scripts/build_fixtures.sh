#!/usr/bin/env bash
# Builds harmless Windows test executables for the optional integration tests.
# Needs: x86_64-w64-mingw32-gcc  (Debian/Kali/Ubuntu: apt install mingw-w64)
# Optional: upx                  (apt install upx-ucl) for the packed fixture.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=tests/fixtures/build
mkdir -p "$OUT"
x86_64-w64-mingw32-gcc -O0 -o "$OUT/benign_demo.exe" tests/fixtures/demo.c
if command -v upx >/dev/null 2>&1; then
  upx -q -f -o "$OUT/benign_packed.exe" "$OUT/benign_demo.exe" >/dev/null
else
  echo "upx not found: skipping the packed fixture"
fi
echo "Built fixtures in $OUT (gitignored, never commit them)"
