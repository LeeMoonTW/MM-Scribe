#!/usr/bin/env bash
# ============================================================
#  MM Scribe - Build Dev + Release .app (macOS)
#  Usage: ./MabinogiMobileScribe_BuildTool.sh
#
#  對應 Windows 版的 MabinogiMobileScribe_BuildTool.bat,行為刻意保持一致:
#    - 原始碼固定叫 MabinogiMobileScribe_Beta.py,換版本號不用改這支腳本
#    - 產出 Dev(含開發者選項) 與 Release(隱藏) 兩個版本
#  macOS 的差異:
#    - --add-data 分隔符是 ':' 不是 ';'
#    - --windowed 產生 .app bundle,--icon 吃 .icns
#    - 另外把 icon.png 一起打包,給執行期的 iconphoto() 用
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

cleanup() {
    rm -f RELEASE.marker
}
trap cleanup EXIT

# ---- Locate source: 檔名不再帶版號,直接指名 ----
#      找不到才退回舊的「挑最新修改的 MabinogiMobileScribe_*.py」,
#      讓還留著舊版號檔名的工作目錄不會突然建置失敗。
SCRIPT="MabinogiMobileScribe_Beta.py"
if [[ ! -f "$SCRIPT" ]]; then
    SCRIPT="$(ls -t MabinogiMobileScribe_*.py 2>/dev/null | head -1 || true)"
fi
if [[ -z "$SCRIPT" ]]; then
    echo "[ERROR] Cannot find MabinogiMobileScribe_Beta.py in current directory." >&2
    exit 1
fi
echo "Detected source: $SCRIPT"

# ---- Python:優先用專案的 venv,沒有就退回 PATH 上的 python3 ----
PY="../.venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
echo "Using Python   : $PY"

if ! "$PY" -c "import PyInstaller" 2>/dev/null; then
    echo "[ERROR] PyInstaller 未安裝:uv pip install --python $PY pyinstaller==6.21.0" >&2
    exit 1
fi

# uv 的 standalone Python 需要指出 Tcl/Tk 位置,否則 PyInstaller 收不到 tkinter 資源
BASE="$("$PY" -c 'import sys; print(sys.base_prefix)')"
if [[ -d "$BASE/lib/tcl8.6" ]]; then
    export TCL_LIBRARY="$BASE/lib/tcl8.6"
    export TK_LIBRARY="$BASE/lib/tk8.6"
fi

# ---- Auto-detect icon files ----
#     ICON_*     : .app 的圖示 (--icon,macOS 只吃 .icns)
#     ADD_ICON_* : 打包 .png 進去,讓執行期的 iconphoto() 載得到
ICON_DEV=(); ICON_REL=(); ADD_ICON_DEV=(); ADD_ICON_REL=()
[[ -f icon_dev.icns ]] && ICON_DEV=(--icon=icon_dev.icns)
[[ -f icon.icns ]] && ICON_REL=(--icon=icon.icns)
[[ -f icon.icns && ${#ICON_DEV[@]} -eq 0 ]] && ICON_DEV=(--icon=icon.icns)
[[ -f icon_dev.png ]] && ADD_ICON_DEV=(--add-data=icon_dev.png:.)
[[ -f icon.png ]] && ADD_ICON_REL=(--add-data=icon.png:.)
[[ -f icon.png && ${#ADD_ICON_DEV[@]} -eq 0 ]] && ADD_ICON_DEV=(--add-data=icon.png:.)

echo "Icon for Dev     : ${ICON_DEV[*]:-none - using default}"
echo "Icon for Release : ${ICON_REL[*]:-none - using default}"

# ---- 預設設定檔:打包進 bundle 當種子 ----
# macOS 的 .app 內部不可寫,程式會在首次啟動時把這些複製到
# ~/Library/Application Support/MM Scribe/ 供使用者編輯。
CONFIGS=()
for cfg in skills.ini settings.ini; do
    [[ -f "$cfg" ]] && CONFIGS+=("--add-data=$cfg:.")
done

# BPF 權限設定腳本(在專案根目錄):首次啟動偵測到沒權限時,程式會透過系統
# 授權對話框提權執行它,所以必須跟著打包進 bundle。
if [[ -f ../macos-bpf-access.sh ]]; then
    CONFIGS+=("--add-data=../macos-bpf-access.sh:.")
fi

echo "Bundled configs  : ${CONFIGS[*]:-none}"
echo

# ---- Clean previous build artifacts so PyInstaller does not reuse cached spec ----
rm -rf build "MM Scribe.spec" "MM Scribe Dev.spec"

echo "============================================================"
echo " Step 1/3 : Build DEV version (with developer options)"
echo "============================================================"
"$PY" -m PyInstaller --windowed --noconfirm \
    --collect-data customtkinter \
    "${ICON_DEV[@]}" "${ADD_ICON_DEV[@]}" "${CONFIGS[@]}" \
    --name "MM Scribe Dev" \
    "$SCRIPT"

echo
echo "============================================================"
echo " Step 2/3 : Create release marker"
echo "============================================================"
: > RELEASE.marker
echo "Marker created."

echo
echo "============================================================"
echo " Step 3/3 : Build RELEASE version (developer options hidden)"
echo "============================================================"
"$PY" -m PyInstaller --windowed --noconfirm \
    --collect-data customtkinter \
    --add-data "RELEASE.marker:." \
    "${ICON_REL[@]}" "${ADD_ICON_REL[@]}" "${CONFIGS[@]}" \
    --name "MM Scribe" \
    "$SCRIPT"

echo
echo "============================================================"
echo " DONE!"
echo "    Dev     : dist/MM Scribe Dev.app"
echo "    Release : dist/MM Scribe.app"
echo
echo " 只有 ad-hoc 簽章,使用者首次開啟會被 Gatekeeper 攔下,"
echo " 需執行 xattr -dr com.apple.quarantine \"<路徑>/MM Scribe.app\","
echo " 或從系統設定 →「隱私權與安全性」→「仍要打開」放行。"
echo " .app 沒有「以管理員身分執行」,抓封包請搭配 ChmodBPF,"
echo " 或從終端機以 sudo 啟動 .app 內的執行檔。"
echo "============================================================"
