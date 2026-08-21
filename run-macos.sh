#!/usr/bin/env bash
# MM Scribe — macOS 啟動腳本
#
# 遊戲在 macOS 上是「iOS App on Mac」,流量直接走實體網卡,
# 抓法與 Windows 端相同,不需要模擬器或額外的轉送設定。
set -euo pipefail

cd "$(dirname "$0")"

VENV_PY="$PWD/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
    cat >&2 <<'EOF'
找不到虛擬環境,請先建立:

    uv venv --python 3.12 .venv
    uv pip install --python .venv/bin/python scapy==2.7.0 customtkinter==5.2.2 Brotli==1.1.0

EOF
    exit 1
fi

# uv 的 standalone Python 在 venv 裡找不到 Tcl/Tk 的 script library,
# 得指回 base 安裝位置,否則 tkinter.Tk() 會拋 "Can't find a usable init.tcl"。
BASE="$("$VENV_PY" -c 'import sys; print(sys.base_prefix)')"
TK_ENV=()
if [[ -d "$BASE/lib/tcl8.6" ]]; then
    TK_ENV=(TCL_LIBRARY="$BASE/lib/tcl8.6" TK_LIBRARY="$BASE/lib/tk8.6")
    export "${TK_ENV[@]}"
fi

SCRIPT="Source/MabinogiMobileScribe_Beta.py"

# 能直接開 BPF 就不必提權(裝過 Wireshark 的 ChmodBPF 就屬於這種情況)
if "$VENV_PY" - <<'PY' 2>/dev/null
import os, sys
for i in range(4):
    p = f"/dev/bpf{i}"
    if os.path.exists(p):
        try:
            os.close(os.open(p, os.O_RDWR))  # 與 scapy 的 get_dev_bpf() 一致
            sys.exit(0)
        except PermissionError:
            sys.exit(1)
        except OSError:
            continue
sys.exit(1)
PY
then
    echo "BPF 可直接存取,免 sudo 啟動"
    exec "$VENV_PY" "$SCRIPT"
fi

echo "需要提權才能抓封包 — 接下來會要求輸入密碼"
echo "(想免 sudo 的話,安裝 Wireshark 內附的 ChmodBPF 即可)"
exec sudo "${TK_ENV[@]}" "$VENV_PY" "$SCRIPT"
