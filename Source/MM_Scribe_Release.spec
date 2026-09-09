# -*- mode: python ; coding: utf-8 -*-
"""發布版建置設定:主程式與圖表閱覽器共用同一份 _internal。

為什麼是 onedir:
  onefile 每次執行都要把整包解到 %TEMP% 下的 _MEIxxxx 再從那裡載入 DLL,那是
  dropper 的典型行為,也是 Defender ML 啟發式的高權重特徵 —— Windows 版
  被判 Trojan:Win32/Wacatac.B!ml 的成因之一(其餘兩項見 make_version_file.py)。

為什麼要手寫這份 spec:
  兩支程式各自 onedir 會各帶一份 Python runtime / tk / PIL,zip 大一倍。
  一個 COLLECT 同時收兩個 EXE 就能共用 _internal,而這是命令列參數表達不了的。
  BuildTool.bat 的清理步驟只刪 PyInstaller 自動產生的 "MM Scribe*.spec",
  檔名刻意取成底線版避開它 —— 這份是版控裡的來源,不是產物。

前置條件(BuildTool.bat 會準備好):
  RELEASE.marker、VERSION.txt、version_info_main.txt、version_info_graph.txt

Dev 版不走這裡 —— 它跟 Release 只差一個 RELEASE.marker,共用資料夾反而會打架。
"""
from PyInstaller.utils.hooks import collect_data_files

ctk = collect_data_files('customtkinter')

# 怪物名對照表少了它目標欄位只能顯示 entityId 的 hex;圖表閱覽器不需要,
# 它的目標名稱是從存檔讀的。
a_main = Analysis(
    ['MabinogiMobileScribe_Beta.py'],
    pathex=[],
    binaries=[],
    datas=[('RELEASE.marker', '.'),
           ('icon.ico', '.'),
           ('notice_monster_names_tw.json', '.')] + ctk,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# 圖表閱覽器沒有 Dev/Release 之分。版號從 VERSION.txt 讀,單一真相仍是
# 主程式的 VERSION_STR。
a_graph = Analysis(
    ['MabinogiMobileScribeGraph_Beta.py'],
    pathex=[],
    binaries=[],
    datas=[('VERSION.txt', '.'),
           ('icon.ico', '.')] + ctk,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz_main = PYZ(a_main.pure)
pyz_graph = PYZ(a_graph.pure)

# exclude_binaries=True:binaries 交給下面的 COLLECT 統一收,兩支才共用得到。
exe_main = EXE(
    pyz_main,
    a_main.scripts,
    [],
    exclude_binaries=True,
    name='MM Scribe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info_main.txt',
    icon=['icon.ico'],
)

exe_graph = EXE(
    pyz_graph,
    a_graph.scripts,
    [],
    exclude_binaries=True,
    name='MM Scribe Graph',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info_graph.txt',
    icon=['icon.ico'],
)

# 兩個 EXE 進同一個 COLLECT:重複的 DLL / tk 資源只會收一份。
coll = COLLECT(
    exe_main,
    a_main.binaries,
    a_main.datas,
    exe_graph,
    a_graph.binaries,
    a_graph.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='MM Scribe',
)
