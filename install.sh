#!/usr/bin/env bash
# ==============================================================================
#  Malvexis One-Step Global Installer
#  Author: https://github.com/anilkashyap01
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "  Installing Malvexis - Static Malware Analysis Engine"
echo "  Author: https://github.com/anilkashyap01"
echo "======================================================================"

# 1. Check Python version
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required but not installed." >&2
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "[-] Error: Python 3.10 or higher is required (found Python $PYTHON_VER)." >&2
    exit 1
fi
echo "[+] Detected Python $PYTHON_VER"

# 2. Create isolated virtual environment
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment in $VENV_DIR..."
    python3 -m venv --system-site-packages "$VENV_DIR"
else
    echo "[+] Using existing virtual environment in $VENV_DIR"
fi

# 3. Install malvexis in editable mode
echo "[+] Installing Malvexis in editable mode..."
"$VENV_DIR/bin/pip" install --quiet --no-build-isolation -e "$SCRIPT_DIR[yara]" 2>/dev/null || "$VENV_DIR/bin/pip" install --quiet -e "$SCRIPT_DIR[yara]"

# 4. Link malvexis to ~/.local/bin
USER_BIN="$HOME/.local/bin"
mkdir -p "$USER_BIN"
echo "[+] Linking executable to $USER_BIN/malvexis..."
ln -sf "$VENV_DIR/bin/malvexis" "$USER_BIN/malvexis"

# 5. Verify installation
echo "[+] Verifying installation..."
"$USER_BIN/malvexis" --version

echo ""
echo "======================================================================"
echo "  [SUCCESS] Malvexis is installed and ready to use globally!"
echo "======================================================================"
echo ""
echo "You can now run 'malvexis' from any terminal, anywhere:"
echo "  malvexis                                # Show banner, author & usage"
echo "  malvexis scan <sample.exe>              # Static scan"
echo "  malvexis scan <sample.exe> --html out.html"
echo ""
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "[!] Notice: $HOME/.local/bin is not yet in your PATH."
    echo "    Add this line to your ~/.bashrc or ~/.zshrc:"
    echo '    export PATH="$HOME/.local/bin:$PATH"'
    echo ""
fi
