"""
瑪奇即時傷害監控 - customtkinter 版
需求: pip install customtkinter scapy
抓封包需要提權:Windows 以系統管理員執行;macOS 需 root 或已放寬 /dev/bpf* 權限。

支援 Windows 10/11 與 macOS (Apple Silicon / Intel)。
macOS 上遊戲為 iOS App on Mac,流量直接走實體網卡,抓法與 Windows 端相同。

打包說明 (實務上直接跑 MabinogiMobileScribe_BuildTool.bat / .sh,以下是等價的手動指令):
  怪物名對照表也要打包 —— 少了它目標欄位只能顯示 entityId 的 hex。
  Windows 版是 onedir 且一律加 --noupx —— onefile 的「解壓到 %TEMP% 再載入 DLL」
  與 UPX 加殼都是 Defender ML 啟發式的高權重特徵,會被判成
  Trojan:Win32/Wacatac.B!ml。BuildTool.bat 另外會用 make_version_file.py
  產生 --version-file,補上空白的 exe metadata(同一個誤判的第三個成因)。

  Windows 開發版 (顯示開發者選項):
    python -m PyInstaller --onedir --noconfirm --noconsole --noupx --collect-data customtkinter --add-data "notice_monster_names_tw.json;." MabinogiMobileScribe_Beta.py

  Windows 發布版 (隱藏開發者選項):
    走 MM_Scribe_Release.spec —— 主程式與圖表閱覽器共用一份 _internal,
    這是命令列參數表達不了的,所以那份 spec 是版控裡的來源而非產物:
    python -m PyInstaller --noconfirm MM_Scribe_Release.spec

  macOS (--add-data 分隔符是 ':' 不是 ';'):
    touch RELEASE.marker
    python -m PyInstaller --windowed --collect-data customtkinter --add-data "RELEASE.marker:." --add-data "notice_monster_names_tw.json:." MabinogiMobileScribe_Beta.py

  程式啟動時會偵測執行檔內是否包含 RELEASE.marker 檔案,
  存在則隱藏開發者選項按鈕(釋出給他人使用)。
"""
import collections
import configparser
import csv
import io
import json
import os
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk  # 只用 StringVar / BooleanVar
import tkinter.font as tkfont  # 日誌技能欄的像素寬度量測
import webbrowser
import customtkinter as ctk
from scapy.all import sniff, TCP, IP

# Brotli 是**必要**相依,不是選用的。角色身分偵測 (見 PacketNotes_Identity) 讀的
# 0x4FFF / 0x4E4F 兩則訊息都是 encodingType==1,也就是 Brotli;解不開就綁不到自己的
# 實體 ID,而傷害統計又以「攻擊者 == 自己」為門檻 (同筆記 §9) —— 結果是一筆傷害都
# 不會記,UI 上只看得到紅字「尚未偵測到角色ID」。
# 這裡仍然用 try/except 匯入,是為了讓缺套件時能給出一句講得清楚的錯誤訊息,
# 而不是開機就 ImportError 掛掉。缺套件的後果由 IDENT_MSG_NO_BROTLI 說明。
try:
    import brotli as _BROTLI
except ImportError:
    try:
        import brotlicffi as _BROTLI
    except ImportError:
        _BROTLI = None

# ----------------------------------------------------
# 平台差異
# ----------------------------------------------------
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

# 字體:FONT_UI 是介面主字體,FONT_MONO 只留給開發者診斷 LOG (hex dump 需要等寬)
if IS_MACOS:
    FONT_UI = "PingFang TC"
    FONT_MONO = "Menlo"
else:
    FONT_UI = "Microsoft JhengHei"
    FONT_MONO = "Consolas"
# 攻擊 / 治癒日誌一律走 UI 字體 (Windows = 微軟正黑體),不再混用等寬字 —
# 混用時中文會從等寬字 fallback 到系統 CJK 字體,同一行看起來字重不一致。
# 傷害欄的右對齊改由 Tk 的 right tab stop 負責 (見 _scaled_tab_stops),
# 不再靠空白補齊,所以不需要等寬字也能對齊。
FONT_LOG = FONT_UI


def is_release_build():
    """判定是否為 release 打包版。
    - 打包成 EXE 且內含 RELEASE.marker → True
    - 或環境變數 LDM_RELEASE=1 (方便開發時預覽發布 UI)
    - 其他情況 (含未打包的原始碼直接執行) → False
    """
    if getattr(sys, "frozen", False):
        marker_path = os.path.join(getattr(sys, "_MEIPASS", ""), "RELEASE.marker")
        if os.path.exists(marker_path):
            return True
    return os.environ.get("LDM_RELEASE") == "1"

# ----------------------------------------------------
# 設定
# ----------------------------------------------------
VERSION_STR = "Beta V0.68"
COVERAGE_MIN_HITS = 10  # 覆蓋率計算所需最少樣本數
# 需要統計覆蓋率的標籤 (上方面板、技能排行展開明細共用同一份;順序即顯示順序)
COVERAGE_TAGS = ("爆擊", "強擊", "連擊", "追擊")
# 持續傷害 (見 DMG_SUSTAIN_BITS) 只計入這幾個標籤的覆蓋率:它不是玩家直接命中,
# 不會觸發強擊/連擊/追擊,分子分母都要排除,只有爆擊照算。
COVERAGE_TAGS_SUSTAIN = ("爆擊",)
# 目標篩選:TARGET_ALL 是「全部對象」的彙總桶,其餘 key 為 target_id (int)
TARGET_ALL = "__ALL__"
TARGET_ALL_LABEL = "All"
TARGET_BTN_SELECTED = "#3a6a9a"    # 目標按鈕:選中
TARGET_BTN_IDLE = "#2a2a2a"        # 目標按鈕:未選中
TARGET_SORT_INTERVAL_MS = 3000     # 目標按鈕列依累積傷害重排的週期
# 目標按鈕寬度用「顯示單位」估算 (CJK 算 2 單位),不量實際字型 —
# 量測值是螢幕像素,而 width= 吃的是 CTk 縮放後的單位,HiDPI 下會對不上。
TARGET_BTN_UNIT_W = 9              # 每單位估算寬度 (0x + 8 碼 = 10 單位 ≈ 舊的 96)
TARGET_BTN_MIN_W = 60
TARGET_BTN_MAX_W = 200             # 名字再長也不讓單顆按鈕吃掉整條列
TARGET_NAME_MAX_UNITS = 20         # 超過就截斷加省略號
# 攻擊日誌保留筆數上限 (切換目標時要依此緩衝重畫整份,故需有上界)
LOG_HISTORY_MAX = 5000
# === 傷害事件時間序列 (給日後的傷害曲線圖表用,不顯示在日誌上) ===
# 每筆傷害存一列 (ts, target_id, skill_id, damage, flags):
#   ts       = time.time() 絕對時間戳,與統計桶的 first/last 同一個時鐘
#   skill_id = 抓不到時為 None
#   flags    = DMG_EVENT_TAG_BITS 的位元 + DoT / 間接兩個高位元
# 存成 tuple 而非 dict:一場動輒數萬筆,tuple 省下的記憶體與存檔體積都不小。
DMG_EVENT_TAG_BITS = ("爆擊", "強擊", "破防", "無防備",
                      "連擊", "多重打擊", "迎擊", "追擊",
                      "延長破防", "終結")
# DoT / 間接 / 連攜固定放在高位,中間留空檔 — 標籤再加也不會撞到這幾個位元
DMG_EVENT_DOT_BIT = 1 << 16
DMG_EVENT_SUSTAIN_BIT = 1 << 17
# 連攜 (技能是隊友放的,傷害掛在自己身上):這種事件不進統計桶,只留在時間序列裡,
# 所以位元一定要寫進存檔 —— 否則事後看存檔會發現事件總和對不上統計總傷害。
DMG_EVENT_CHAIN_BIT = 1 << 18
# 時間序列保留筆數上限 (deque,超量自動丟最舊的)
DMG_EVENT_MAX = 100000
SKILL_CFG_NAME = "skills.ini"
EFFECT_CFG_NAME = "effects.ini"   # buffId → 效果名 (見 load_effect_names)
EFFECT_IGNORE_SECTION = "ignore"  # 這個區段列的 buffId 不顯示在面板上 (比對時轉小寫)
SETTINGS_CFG_NAME = "settings.ini"
# 代理模式偵測用的遊戲執行檔名 (小寫比對)。可由 settings.ini 的 [Network] 覆寫
DEFAULT_GAME_PROCESSES = ("mabinogimobile.exe",)
# 存檔 (「紀錄 / 讀取」):檔案放在 EXE (或原始碼) 旁的 Save/ 資料夾
SAVE_DIR_NAME = "Save"
SAVE_FILE_PREFIX = "MMScribe_"
SAVE_FILE_EXT = ".json"
# 存檔格式版號。欄位語意變動時 +1;讀檔遇到不認得的版號直接拒讀,
# 免得舊檔被當成新格式塞進 target_stats,畫面數字錯得無聲無息。
SAVE_FORMAT_VERSION = 1
SAVE_COMBO_EMPTY = "(無存檔)"
BPF_HELPER_NAME = "macos-bpf-access.sh"  # macOS 抓包權限設定腳本
FONT_SCALE_MIN = 1.0
FONT_SCALE_MAX = 2.0
FONT_SCALE_DEFAULT = 1.0
MERGE_GROUP_SECTION = "合併群組"
# 註:舊版的「忽略寵物攻擊」設定已移除 — 統計改用角色 ID 門檻 (只收攻擊者 == 自己的
# 傷害),寵物是獨立實體,本來就不會進統計。skills.ini 的 [寵物] 區段仍照常提供技能名。
# Skill ID 提取 (見 HEAL_SHIELD_SKILL_ID.md §4)
HEAL_SHIELD_SKILL_NEAR_WINDOW = 300  # Near 掃描單向視窗大小 (bytes)
ALT_SKILL_MAX_GAP = 8                # 0x1ADE8 允許緊接 0x4EED 結束後的最大 gap
ALT_SKILL_BACKSCAN = 64              # 往前找 0x4EED 的搜尋深度
# 傷害事件 opcode — 2026-09-09 改版後伺服器重發 packet_type_config,整份目錄改號。
# 標頭結構與欄位佈局完全沒變,只有 packetType 數值變了 (筆記 §2 第 3 點預測的情形)。
# 驗證:1.37MB / 33223 則訊息以 9-byte 標頭鏈式解析覆蓋率 100%;0x5235 的
#      attacker/target/dmg/flags offset 全部命中,技能 ID 解出「普攻」「魔力連結飛彈」。
DMG_EVENT_TYPE = 0x5235           # CHANNEL_ShowDamageFloater_NTF (舊 0x51E9)
DMG_EVENT_MAGIC = struct.pack("<I", DMG_EVENT_TYPE)
SKILL_TLV_TYPE = 0x4FEC           # 技能 TLV,經典型 size 35 (舊 0x4FC5)
SKILL_TLV_MAGIC = struct.pack("<I", SKILL_TLV_TYPE)
# 0x4F40 與傷害事件同為 contentLength 53,但 attacker == target 且 dmg = 0 —— 就是
# 筆記 §3 說的 decoy。opcode 不同所以正常掃描撞不到,parse_payload 仍照 protocol 的
# 合法條件 (userId != targetId 且兩者皆非 0) 加一道守門,擋對錯位撞出來的假標頭。
# 傷害旗標區 (見 MM_Scribe_PacketNotes_Damage.md §4)
# 0x5235 事件的旗標是連續 7 bytes: payload[offset+41 .. offset+47]
#   flags[0] = b41 (已用), flags[1] = b42 (已用), flags[2..6] = b43..b47 (診斷中)
DMG_FLAG_BASE = 41
DMG_FLAG_LEN = 7
# 持續傷害 (DoT) — 2026-08-16 以 5 組樣本修正
#   判定只看 b45 bit4 一個位元。對照組:
#     被動毒DOT   flags 00 88 01 00 14 → DoT
#     3技創傷DOT  flags 00 88 01 10 10 → DoT
#     4技毒DOT    flags 00 88 01 00 14 → DoT
#     2技追加傷害 flags 05 88 01 00 00 → 非 DoT
#     4技地面傷害 flags 01 88 01 00 04 → 非 DoT
#   佐證:真 DoT 的 b41 恆為 00 (不會爆擊) 且每跳數值固定;追加/地面傷害兩者皆否。
DMG_DOT_BITS = ((4, 0x10),)
DMG_DOT_SUFFIX = "(Dot)"
# 「非直接命中的額外傷害」通用標記 — DoT / 追加傷害 / 地面傷害都會亮,
# 因此不足以判定 DoT (舊版誤把這組當成 DoT,導致追加傷害被標成 Dot)。
DMG_EXTRA_BITS = ((1, 0x08), (1, 0x80), (2, 0x01))
# 持續傷害 (遊戲內敘述用語,不是封包意義的 DoT):額外傷害三個位元全亮、DoT 位元沒亮。
#   樣本 5技 高潮(終章) 0x6E202640,flags = 05/00/01 88 01 00 00:
#     b41=00        → 2723 / 3009 / 2960   (基準)
#     b41=01 爆擊    → 5359 / 5839          (約 1.9x)
#     b41=05 爆+無防 → 7594 / 7680 / 7334   (約 2.6x)
#   倍率乾淨且會爆擊 → 走正常傷害計算,與 DoT (b41 恆 00、每跳定值) 明顯不同。
#   ⚠ 地面傷害同樣符合這個條件,旗標層面無法再細分 (見筆記 §4.2 / §4.4)。
DMG_SUSTAIN_BITS = DMG_EXTRA_BITS
DMG_SUSTAIN_SUFFIX = "(間接)"
# 開發者模式用:把上面兩組拆回「是哪幾個 bit 亮的」。格式: (flags index, mask, 標籤)
DMG_DOT_BIT_LABELS = ((4, 0x10, "45.10"),)
DMG_EXTRA_BIT_LABELS = ((1, 0x08, "42.08"), (1, 0x80, "42.80"), (2, 0x01, "43.01"))
# 追擊 (add_hit_flag) — 位置來自 packet-protocol.md, 本地尚未錄到樣本驗證。
# 已納入正式標籤與覆蓋率統計; 若實測發現誤判, 只要改這一組常數即可。
DMG_ADD_HIT_BIT = (3, 0x08)
# ---- 0x5235 <-> 0x4FEC 配對 (2026-09-11 實機錄包實測,見筆記 §5.1) ----
# 舊作法「往後掃 200 bytes 抓第一個 0x4FEC」是錯的。實測 5557 封包 / 289 筆傷害:
#   * 施法者 == 傷害事件的攻擊者 (自己動手打的) → DMG 在前、SKILL 在後   100/100 筆
#   * 連攜觸發 (治癒師 1 技光波之類)          → SKILL 在前、DMG 在後   184/189 筆
# 所以只能雙向掃。配對鍵也不能用 attacker —— 連攜時 SKILL 的 userId 是「放技能
# 的那個隊友」,DMG 的 userId 是「被掛連結的自己」,兩邊本來就不同。
# 實測可零歧義配對的鍵是:目標 ID 相同 + 7 bytes 旗標全等 → 289/289 筆全中。
DMG_EVENT_SIZE = 53            # 0x5235 的 contentLength;非此值視為假標頭
DMG_SKILL_NEAR_WINDOW = 400    # 雙向掃描視窗 (實測 SKILL 最遠落在 171 bytes 外)
SKILL_TLV_FLAG_BASE = 33       # 0x4FEC 內旗標起點 (content+24),對應 DMG 的 +41
DMG_CHAIN_SUFFIX = "(連攜)"    # SKILL.userId != DMG.userId → 別人掛在你身上觸發的
# ---- TCP 位元組接續 (2026-09-11 實測) ----
# 289 筆傷害事件裡有 16 筆 (5.5%) 被切在 TCP segment 邊界上,逐封包掃會整筆漏掉
# (筆記 §2「被切中機率低」的推測與實測不符)。這裡不做完整 TCP stack,只做同一
# 連線的位元組接續:seq 接得上就把上一包的尾巴續上,亂序/丟包就丟掉重來。
DMG_STREAM_CARRY = 1024        # 每條連線保留的尾端位元組數 (需 > 視窗+事件長)
DMG_STREAM_MAX_CONNS = 8       # 同時追蹤的連線數上限
DMG_PAIR_FLUSH_SEC = 0.25      # 事件後方資料還沒到齊時最多等多久,逾時就照現況判
# 以下位元語意來自第三方整理的 packet-protocol.md, 尚未用本地樣本驗證,
# 目前「只在開發者模式顯示」, 不進入正式標籤 / 統計。
# 格式: (flags index, mask, 顯示名稱)
DMG_FLAG_CANDIDATES = (
    # 出血/毒 已於 2026-08-16 由多個技能交叉驗證 (創傷 DOT = 出血;三個毒技能 = 毒),
    # 其餘元素仍未錄到樣本,一律保留 "?" 提醒。
    (3, 0x10, "出血"), (3, 0x20, "暗?"), (3, 0x40, "火?"), (3, 0x80, "聖?"),
    (4, 0x01, "冰?"), (4, 0x02, "雷?"), (4, 0x04, "毒"), (4, 0x08, "心?"),
)
# ---- 角色身分偵測 (規則來自 Note/Ref/for-mm-scribe-identity.md) ----
# 尚未用本地樣本驗證,純觀測:只寫開發者 LOG,不影響任何統計。
#
# 前提:實體 ID (entityId) 換場景就換,角色身分 (帳號碼 + 角色索引) 永遠不變。
# 認出「自己」不是靠某個旗標,是把兩者對上 —— 先知道自己的身分,再反查哪個
# 實體 ID 的身分跟自己一樣。比對鍵**兩個都要相等**:只比帳號碼會綁到同帳號
# 的別隻角色,只比角色索引會撞到別的帳號 (索引 4、5 這種小數字滿地都是)。
#
#   A. 我的角色資料 0x4FFF — 遊戲只發給本人,unframed、enc=1。
#      解壓後前 8 bytes: [u16 characterIndex][u32 accountInfo][u16 reserved(必須=0)]
#   B. 玩家出現   0x4E4F — 每個玩家進視野時送,framed、enc=1。
#      解壓後前 4 bytes 是 entityId,內文某處有
#      u64 characterId = accountInfo << 16 | characterIndex
#
# 兩個方向都要做:A 先到就回頭掃已快取的 B;B 先到就在每次有人出現時順手比對。
# 換場景 → 實體 ID 變、身分不清,拿身分重新綁定;換角色 → A 的身分變了,清掉舊綁定。
#
# **本工具不做 TCP 重組**,而 A 訊息壓縮後可達 170KB+、會跨上百個封包。
# 這裡的做法是「串流解壓器邊收邊餵,只要吐得出前 8 bytes 就收工」——
# 能不能成立取決於 brotli 在只收到開頭幾 KB 時肯不肯吐 output,**待實測**。
IDENT_SELF_TYPE = 0x5028          # 2026-09-09 改版:舊 0x4FFF (解壓後佈局不變)
IDENT_APPEAR_TYPE = 0x4E4F        # 改版後未變動 (實測仍是這個值)
IDENT_SELF_MIN_SIZE = 1024        # A 訊息很大;太小的多半是對錯位撞出來的假標頭
IDENT_SELF_FEED_MAX = 1 << 18     # 餵超過這麼多 bytes 還吐不出 8 bytes 就放棄本則
IDENT_APPEAR_MIN_SIZE = 64        # B 訊息實測 1100~1300 bytes;放寬下限只擋明顯假的
IDENT_APPEAR_HEAD_BYTES = 4096    # B 訊息解壓前幾 bytes,拿來找 characterId
IDENT_APPEAR_CACHE_MAX = 64       # 身分還沒到手前,先留這麼多筆 B 訊息回頭比對
IDENT_MATCH_OFF_MAX = 4           # 一則 B 訊息裡最多記幾個 characterId 命中位移
IDENT_REJECT_LOG_MAX = 5          # 同一場最多記幾行「拒絕改綁」,免得洗版
IDENT_MAX_SIZE = 1 << 20          # contentLength 上限 (超過視為對錯位撞出來的假標頭)
IDENT_STREAM_MAX = 8              # 同時追蹤幾條 TCP 連線的「收到一半的訊息」
# 攻擊事件日誌上的角色 ID 狀態列 (紅字 / 綠字)。沒有角色 ID 時傷害一律不記錄,
# 所以這行要直接出現在使用者天天在看的日誌上,不能只留在開發者面板。
IDENT_MSG_NONE = "尚未偵測到角色ID，請嘗試更換地圖或重新登入來獲取角色ID"
IDENT_MSG_OK = "已獲得角色ID資訊"
# 缺 brotli 時走這句。沿用上面那句的話會叫使用者去換地圖,而換幾次都不會好 —
# 訊息本身把人導向錯的方向,比沒有訊息更糟。
IDENT_MSG_NO_BROTLI = ("缺少 brotli 套件，無法偵測角色ID（傷害統計因此不會記錄）。"
                       "原始碼版請執行 pip install Brotli==1.1.0；"
                       "打包版請改用有內含 brotli 的新版本")
# 「⚡ 強制偵測」旁的 ? 提示 (見 toggle_force_all)
FORCE_ALL_TIP = ("無視角色 ID 偵測,把所有解析到的傷害全部納入統計。\n"
                 "包含隊友、寵物、敵人打的傷害,數據不再只屬於你自己。\n"
                 "只在角色 ID 一直偵測不到時當作應急手段;切換時會清除已累積的統計。")
TOOLTIP_DELAY_MS = 400            # 滑鼠停留多久才跳提示
# ---- 底部診斷 LOG 區塊 ----
# 收合狀態只顯示最新一行,點一下彈出完整視窗 (見 dev_log / _popout_dev)
DEV_LOG_MAX = 800                 # 緩衝保留幾行 (超過丟最舊的)
DEV_STRIP_MAX_CHARS = 160         # 單行顯示上限,超過截斷加省略號
DEV_STRIP_EMPTY = "🛠 診斷 LOG — 尚無訊息  (點擊展開)"
# 診斷 LOG 的上色:整片灰字裡身分偵測出問題那幾行必須一眼認得出來。
# dev_log() 依訊息裡的標記自動判定 (順序 = 優先權),也可以由呼叫端明寫 tag。
DEV_TAG_MARKS = (("✗", "dev_err"), ("⚠", "dev_warn"), ("★", "dev_ok"))
DEV_TAG_COLORS = {"dev_err": "#ff5555", "dev_warn": "#ffcc4d", "dev_ok": "#4dd471"}
DEV_STRIP_IDLE_COLOR = "#888888"      # 底部單行沒有標記時的灰
# 展開視窗上方的分類過濾:訊息開頭的 [XXX] 決定它屬於哪一類。
# (設定鍵, 勾選標題, 訊息前綴) — 前綴要和各 _*_note/_*_log 寫出去的字串對得上。
# 沒有前綴的訊息 (啟動提示、brotli 警告等) 不歸類,永遠顯示。
DEV_CATEGORIES = (
    ("dmg", "傷害", "[Flag]"),
    ("buff", "BUFF", "[BUFF]"),
    ("mob", "敵人ID", "[MOB]"),
    ("id", "角色ID", "[ID]"),
)
DEV_PREFIX_CAT = {prefix: key for key, _, prefix in DEV_CATEGORIES}
IDENT_SELF_MAGIC = struct.pack("<I", IDENT_SELF_TYPE)
IDENT_APPEAR_MAGIC = struct.pack("<I", IDENT_APPEAR_TYPE)
# ---- 怪物登場包探針 (0x4E4C) — 開發者 LOG 觀測用,不進統計 ----
# CHANNEL_AppearingAutomaton_NTF:怪物/召喚物/機關進視野時送,framed、enc=1,
# 版面與玩家出現 (0x4E4F) 同族,只差 opcode。解壓後前 4 bytes 一樣是 entityId,
# 但「怪物碼」沒有固定位移 — 要從尾端往前掃哨兵:
#     03 00 00 00 | [4 bytes 怪物碼] | 00 00 00 00
# 怪物碼是全域型別鍵 (同種怪在哪一場都一樣),拿 8 字元大寫 hex 去對照表查名字。
# 戰鬥封包裡只有 entityId 沒有怪物碼,所以名字一定要在登場時記下來。
#
# 這裡是純觀測:串流狀態獨立一份 (**絕不共用 _ident_streams** — 那是每條連線
# 只追一則訊息,混進來會打斷角色 ID 綁定),只寫診斷 LOG,不碰任何統計。
# opcode 20044 是「今天台版的值」,會隨版本變 (現有的 0x4FFF/0x4E4F 同樣風險)。
MOB_APPEAR_TYPE = 0x4E4C          # CHANNEL_AppearingAutomaton_NTF (台版 opcode 20044)
MOB_APPEAR_MAGIC = struct.pack("<I", MOB_APPEAR_TYPE)
MOB_MIN_SIZE = 32                 # 太小的多半是對錯位撞出來的假標頭
MOB_MAX_SIZE = 1 << 18
MOB_PLAIN_MAX = 1 << 16           # 解壓後保留上限 (只是拿來掃哨兵,不必無限吃)
MOB_STREAM_MAX = 8                # 同時追蹤幾條連線的「收到一半的登場包」
MOB_SEEN_MAX = 256                # 記住幾隻已印過的怪 (避免同一隻反覆洗版)
MOB_LOG_MAX = 300                 # 詳細行總量上限,超過只留累計數字
MOB_TALLY_EVERY = 20              # 每收幾則登場包印一次累計
MOB_NAME_FILE = "notice_monster_names_tw.json"
ENTITY_NAME_MAX = 2048            # 記住幾隻怪的 eid → 名字 (給目標欄位用,與 MOB_SEEN_MAX 無關)
MOB_HEAD_SENTINEL = b"\x03\x00\x00\x00"   # 前哨
MOB_TAIL_SENTINEL = b"\x00\x00\x00\x00"   # 後哨
# 掃到這三個一律當沒掃到,繼續往前找 (對照表裡確認過沒有這三個鍵)
MOB_CODE_IGNORE = {"00000000", "01000000", "FFFFFFFF"}
# ---- Buff 探針 (0x1D4FD / 0x1D4FF / 0x1D4FE) — 開發者 LOG 觀測用,不進統計 ----
# 見 Note/MM_Scribe_PacketNotes_Buff.md。四份離線樣本 (Note/Ref/Buff pcapng) 推導,
# ADD/REM 的語意已由「宣告 8.0 秒 → 實際存活 8.01 秒」驗證。
#
#   ADD/UPD content (36B): [8B 擁有者 eid][8B buffKey][u32 buffId][f32 秒數]
#                          [u32 層數][8B 來源 eid]
#   REM   content (16B): [8B 擁有者 eid][8B buffKey]
#
# 這三個 opcode 的 content 都是 enc=0 (未壓縮),不需要 brotli、也不必接續跨封包的
# body —— 整則訊息只有 25/45 bytes,直接逐 payload 掃 magic 就好,不必像 _mob_walk
# 那樣維護串流狀態。假標頭靠「opcode + 長度完全相符 + enc==0」三重守門擋掉。
# opcode 是「今天台版的值」,會隨改版變動 (與 0x5235 / 0x4E4C 同樣風險)。
BUFF_ADD_TYPE = 0x1D4FD           # REPLICATION_ActorBuff_Add_REPL
BUFF_UPD_TYPE = 0x1D4FF           # 更新 (同 key/buffId/秒數,只有 c 欄變)
BUFF_REM_TYPE = 0x1D4FE           # 移除 / 到期
# {packetType: (magic, content 長度, 顯示名)} — 長度必須完全相符才採信
BUFF_OPS = {
    BUFF_ADD_TYPE: (struct.pack("<I", BUFF_ADD_TYPE), 36, "ADD"),
    BUFF_UPD_TYPE: (struct.pack("<I", BUFF_UPD_TYPE), 36, "UPD"),
    BUFF_REM_TYPE: (struct.pack("<I", BUFF_REM_TYPE), 16, "REM"),
}
# 無限持續的判定:**不能比對特定值**。實測拿到 0xD1B03913 與 0xD1B03914 兩個,
# 解成 float32 是 -94608973824.0 / -94608982016.0 —— 都是「約 -3000 年」,
# 差一個 ULP = 8192 秒 ≈ 2.3 小時。這欄放的是絕對時間值,底層時鐘一直在走,
# 只是 float32 在這個量級每 8192 秒才跳一格,短時間內錄的樣本才會全都一樣
# (初版就是這樣誤判成固定哨兵,隔幾天撞到 0x...14 就顯示成未知值)。
# 改成:解得出合理秒數就是有限,否則 (負值 / 0 / NaN / 超大值) 一律當無限。
BUFF_DUR_MAX = 1e7                # 合理秒數上限 (約 115 天)。真實 buff 遠短於此,
                                  # 「無限」那個值是 9.46e10,兩者差 4 個數量級
BUFF_LOG_MAX = 5000               # 詳細行總量上限,超過只留累計數字
# ---- 即時 Buff 監測面板 ----
BUFF_TICK_MS = 200                # 倒數重繪間隔。100ms 以下只是白燒 CPU,肉眼看不出差別
# 進度條填充色:綠 #30A050 以 60% alpha 疊在 canvas 深灰底 (#3A3A3A) 上,
# 算法與技能列的橘色同一套 (見 _create_skill_row):
#   R = 0.6*0x30 + 0.4*0x3A = 0x34   G = 0.6*0xA0 + 0.4*0x3A = 0x77
#   B = 0.6*0x50 + 0.4*0x3A = 0x47
BUFF_FILL_COLOR = "#347747"
BUFF_INFINITE_TEXT = "∞"          # 無限持續的 buff 沒有秒數可倒數,進度條固定滿格
PANE_CONTENT_MIN_H = 90           # 攻擊日誌 / 技能排行 / Buff 三個 pane 內容區的
                                  # 最小高度。均分靠 grid uniform,而 uniform 會把所有
                                  # row 拉到「需求最高」的那個,所以三者必須給同一個值,
                                  # 否則會互相頂高、把視窗撐爆
BUFF_SCROLL_H = PANE_CONTENT_MIN_H
BUFF_HISTORY_MAX = 4000           # 存檔用的已結束區間上限 (與 damage_events 同性質)
BUFF_ACTIVE_MAX = 512             # 同時追蹤幾筆 buff。換場景時舊實體不會送 REM,
                                  # 沒有上限就是純漏水(自己的 buff 只有個位數,
                                  # 額度幾乎都花在場上其他實體身上)
DISCORD_INVITE_URL = "https://discord.gg/NaddqvBVvb"
# 日誌欄位布局: \t [傷害值 (右對齊)] \t [標籤 (左對齊)] \t [技能名稱 (可往右溢出)]
# 行首那個 tab 是必要的 — Tk 的 right tab stop 對齊的是「tab 之後到下一個 tab」的字,
# 第一欄要右對齊就得先有一個 tab 把它推到停靠點。
# 傷害值放第一欄且右緣固定,結構上不可能被其他欄位推走。
# 停靠點不寫死像素 — FONT_LOG 在 Windows(微軟正黑體)/macOS(PingFang TC) 字寬不同,
# 改成依實際字體量測樣本字串算出 (見 _scaled_tab_stops)
LOG_DMG_WIDTH = 10                      # 傷害欄右緣位置的取樣寬度 (幾個數字寬)
LOG_DMG_SAMPLE = "9,999,999,999"        # 傷害欄取樣 (涵蓋 UInt32 上限位數)
LOG_TAG_SAMPLE = "[爆擊+破防+多重打擊]"   # 標籤欄取樣;更長的組合會把名稱往右推,可接受
LOG_COL_GAP = 10                        # 欄間留白
# 標籤欄起點只留 LOG_DMG_GAP 的空隙:傷害欄的右緣就在 LOG_DMG_WIDTH 個數字寬處,
# 不必為取樣字串的完整寬度讓位。技能名欄的起點仍以取樣字串為準(位置不變),
# 縮掉的空間讓給標籤欄。單筆傷害寬過停靠點時 Tk 會改成從停靠點左對齊,只推開該行的標籤。
LOG_DMG_GAP = 11
RELEASE_BUILD = is_release_build()


def get_resource_path(filename):
    """取得資源檔的實際路徑。
    - 打包成執行檔後: 資料位於 PyInstaller 解壓的臨時目錄 sys._MEIPASS
    - 未打包 (直接跑 .py): 使用腳本所在資料夾
    定義必須排在 get_external_path 之前 — 後者在 macOS 打包版會呼叫它,
    而 load_skill_config() 是在模組層級就執行的。
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", "")
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, filename)


def get_external_path(filename):
    """取得 EXE 旁邊(或原始碼所在資料夾)的外部檔路徑。
    與 get_resource_path 不同,這是使用者可編輯的檔案位置,不是 PyInstaller bundled 資源。
    """
    if not getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

    if IS_MACOS:
        # .app 內的 Contents/MacOS 使用者根本不會去翻,而且 /Applications 通常
        # 也不可寫,所以改放 Application Support,並在首次執行時把 bundle 內的
        # 預設檔複製過去當種子。
        base = os.path.expanduser("~/Library/Application Support/MM Scribe")
        target = os.path.join(base, filename)
        if not os.path.exists(target):
            seed = get_resource_path(filename)
            if os.path.exists(seed):
                try:
                    import shutil
                    os.makedirs(base, exist_ok=True)
                    shutil.copy(seed, target)
                except OSError:
                    return seed  # 複製不過去就退回唯讀的 bundle 版本,至少能跑
        return target

    return os.path.join(os.path.dirname(sys.executable), filename)


def get_save_dir():
    """存檔資料夾路徑 (不保證存在,寫入前才 makedirs)。
    走 get_external_path 而非自己拼 __file__ —— 後者在 macOS 打包版會指向
    .app 內部的唯讀路徑,存檔一定失敗。代價是 macOS 上實際落在
    ~/Library/Application Support/MM Scribe/Save,不是字面上的「EXE 同資料夾」。
    """
    return get_external_path(SAVE_DIR_NAME)


def load_monster_names():
    """讀怪物碼 → 名字對照表 (5,743 筆,鍵是 8 字元大寫 hex)。

    目標按鈕要靠它把 entityId 顯示成怪物名,所以發布版也要載入。
    讀不到就整個功能靜默關閉 (目標欄位退回 hex),不影響任何統計。
    檔案與原始碼同層 (Source/),未打包時 get_resource_path 就找得到;
    get_external_path 排前面是讓使用者能用 EXE 旁邊的檔案蓋掉內建版。
    """
    tried = set()
    for path in (get_external_path(MOB_NAME_FILE),
                 get_resource_path(MOB_NAME_FILE)):
        if path in tried:
            continue
        tried.add(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            # 比對大小寫不敏感 → 統一存大寫鍵
            return {str(k).upper(): str(v) for k, v in data.items()}
    return {}


# 發布版一樣要載入 — 目標按鈕的名字來源就是它。啟動時 parse 200KB JSON
# 約數十毫秒,換掉「目標欄位只有一串 hex」值得。
MONSTER_NAMES = load_monster_names()


def load_skill_config():
    """從 EXE 同資料夾下的 skills.ini 讀取 skill_id 對照與合併群組。
    格式範例:
        [戰士]
        0x64d5b11d = 普攻
        0x21dd59c4 = 旋風斬

        [合併群組]                ; 全域合併群組
        [合併群組-戰士]           ; 也接受後綴 (-/:/./_/空白) 用於分類整理
        爆裂射擊 = 爆裂射擊, 爆裂射擊+, 爆裂射擊(火藥), 爆裂射擊+(火藥)

    後綴僅為註記,所有合併群組區段共用同一命名空間;群組名跨區段重複時會觸發衝突。

    回傳 (skill_names, merge_groups, conflicts, errors)
      - skill_names:  dict[int skill_id, str display_name]
      - merge_groups: dict[str member_name, str group_name]
      - conflicts:    list[(member, first_group, ignored_group)] 供 UI 提示
      - errors:       list[str] 解析過程中的錯誤訊息 (檔案級 or 逐行) 供 UI 顯示
    檔案不存在回傳空結果 (errors 為空);解析失敗回傳已成功部分 + 錯誤訊息。
    """
    path = get_external_path(SKILL_CFG_NAME)
    if not os.path.exists(path):
        return {}, {}, [], []
    errors = []
    parser = configparser.ConfigParser()
    parser.optionxform = str  # 保留原大小寫,避免 0x64D 被轉小寫影響閱讀
    try:
        parser.read(path, encoding="utf-8")
    except configparser.DuplicateOptionError as e:
        errors.append(f"重複的 key:[{e.section}] '{e.option}' (第 {e.lineno} 行) — INI 同一區段內不允許同名 key")
        return {}, {}, [], errors
    except configparser.DuplicateSectionError as e:
        errors.append(f"重複的區段:[{e.section}] (第 {e.lineno} 行)")
        return {}, {}, [], errors
    except configparser.MissingSectionHeaderError as e:
        errors.append(f"缺少區段標頭:第 {e.lineno} 行 '{e.line.strip()}' — 檔案開頭必須先有 [區段名]")
        return {}, {}, [], errors
    except configparser.ParsingError as e:
        errors.append(f"解析錯誤:{e}")
        return {}, {}, [], errors
    except UnicodeDecodeError as e:
        errors.append(f"編碼錯誤:檔案不是 UTF-8 (byte {e.start}: {e.reason}) — 請以 UTF-8 存檔")
        return {}, {}, [], errors
    except Exception as e:
        errors.append(f"未預期錯誤:{type(e).__name__}: {e}")
        return {}, {}, [], errors
    names = {}
    groups = {}
    conflicts = []

    def _is_merge_section(name):
        # 允許 [合併群組] 或 [合併群組<sep>xxx],sep 可為 - : . _ 或空白
        if name == MERGE_GROUP_SECTION:
            return True
        if name.startswith(MERGE_GROUP_SECTION):
            return name[len(MERGE_GROUP_SECTION):len(MERGE_GROUP_SECTION)+1] in ("-", ":", ".", "_", " ")
        return False

    for section in parser.sections():
        if _is_merge_section(section):
            for group_name, members_str in parser.items(section):
                group_name = group_name.strip()
                if not group_name:
                    continue
                for member in members_str.split(","):
                    member = member.strip()
                    if not member:
                        continue
                    if member in groups:
                        conflicts.append((member, groups[member], group_name))
                        continue
                    groups[member] = group_name
            continue
        for key, value in parser.items(section):
            try:
                skill_id = int(key.strip(), 16)  # 支援 "0x..." 或純十六進位
            except ValueError:
                errors.append(f"[{section}] '{key}' 不是有效的十六進位 skill ID,已略過")
                continue
            name = value.strip()
            if name:
                names[skill_id] = name
    return names, groups, conflicts, errors


# 每次按下「開始」都會重新讀取 (見 start_monitoring)
# 開程式時預先載一次,方便主程式建立初始狀態
SKILL_NAMES, MERGE_GROUPS, _, _ = load_skill_config()


def load_effect_names():
    """從 EXE 同資料夾下的 effects.ini 讀取 buffId → 效果名。

        [效果]
        0x0053830E = 傷害增加
        0x006B1FFF = 生命贈禮

    與 skills.ini 分開:buffId 和 skill_id 是**不同命名空間**,合在一起會互撞
    (見 Note/MM_Scribe_PacketNotes_Buff.md §3)。區段名不限,全部區段一起收。

    另有一個 [Ignore] 區段列出「不要顯示在面板上」的 buffId (假人、測量用的
    內部效果之類)。該區段只看 key,寫成 `0x1234ABCD` 或 `0x1234ABCD = 名稱`
    都可以 —— 有名稱時一併收進對照表,診斷 LOG 才看得懂是哪一個。

    回傳 (names, ignore, errors)。檔案不存在回傳空 dict —— 沒有對照表只是退回
    顯示 hex,不該讓程式起不來。
    """
    path = get_external_path(EFFECT_CFG_NAME)
    if not os.path.exists(path):
        return {}, set(), []
    errors = []
    # interpolation=None 是必要的:效果名裡有「移動速度+7%」這種百分比,
    # configparser 預設會把 % 當插值語法,在 items() 時丟 InterpolationSyntaxError
    # (而且是 read() 之後才炸,包在 read 的 try 裡攔不到)
    # allow_no_value=True 是必要的:[Ignore] 區段只寫 buffId、沒有 `= 值`,
    # 預設會在 read() 就丟 ParsingError,整份三千多筆一起解不出來
    parser = configparser.ConfigParser(interpolation=None, allow_no_value=True)
    parser.optionxform = str          # 保留原大小寫,0x1ADE8 不要被轉小寫
    names, ignore = {}, set()
    try:
        parser.read(path, encoding="utf-8")
        for section in parser.sections():
            is_ignore = section.strip().lower() == EFFECT_IGNORE_SECTION
            for key, value in parser.items(section):
                try:
                    buff_id = int(key.strip(), 16)
                except ValueError:
                    errors.append(f"[{section}] '{key}' 不是有效的十六進位 buffId,已略過")
                    continue
                if is_ignore:
                    ignore.add(buff_id)
                # value 在 allow_no_value 下可能是 None
                name = (value or "").strip()
                if name:
                    names[buff_id] = name
    except Exception as e:
        # 這份是唯讀對照表、使用者一般不會手改,不必像 skills.ini 那樣逐類報錯。
        # 已解出來的部分照樣回傳 —— 壞在最後一行不該讓前面三千筆全丟掉
        errors.append(f"{EFFECT_CFG_NAME} 解析失敗:{type(e).__name__}: {e}")
    return names, ignore, errors


EFFECT_NAMES, EFFECT_IGNORE, _ = load_effect_names()


def load_settings():
    """讀取 settings.ini,回傳 dict。缺檔或解析失敗回傳預設值。"""
    defaults = {
        "font_scale": FONT_SCALE_DEFAULT,
        "track_damage": True,
        "track_heal": False,
        # 連攜攻擊偵測 (見 DMG_CHAIN_SUFFIX):預設關閉 = 連攜傷害整筆剔除
        "detect_chain": False,
        "popout_log": False,
        "popout_skill": False,
        # 診斷 LOG 展開視窗的分類過濾 (dev_filter_<key>);預設全開
        **{f"dev_filter_{key}": True for key, _, _ in DEV_CATEGORIES},
        # 代理模式偵測要比對的遊戲執行檔名 (見 detect_local_game_proxy)。
        # 官方哪天改檔名時,使用者自己改 ini 就能救,不必等新版 exe。
        "game_processes": DEFAULT_GAME_PROCESSES,
    }
    path = get_external_path(SETTINGS_CFG_NAME)
    if not os.path.exists(path):
        return defaults
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return defaults
    result = dict(defaults)
    try:
        raw = parser.get("Display", "font_scale", fallback=str(FONT_SCALE_DEFAULT))
        scale = float(raw)
        # 夾到合法範圍,避免手改 ini 塞奇怪值
        result["font_scale"] = max(FONT_SCALE_MIN, min(FONT_SCALE_MAX, scale))
    except (ValueError, configparser.Error):
        pass
    try:
        result["track_damage"] = parser.getboolean("Tracking", "track_damage", fallback=True)
    except (ValueError, configparser.Error):
        pass
    try:
        result["track_heal"] = parser.getboolean("Tracking", "track_heal", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["detect_chain"] = parser.getboolean(
            "Tracking", "detect_chain", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["popout_log"] = parser.getboolean("Layout", "popout_log", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["popout_skill"] = parser.getboolean("Layout", "popout_skill", fallback=False)
    except (ValueError, configparser.Error):
        pass
    for key, _, _ in DEV_CATEGORIES:
        try:
            result[f"dev_filter_{key}"] = parser.getboolean(
                "DevLog", f"filter_{key}", fallback=True)
        except (ValueError, configparser.Error):
            pass
    try:
        raw = parser.get("Network", "game_processes",
                         fallback=",".join(DEFAULT_GAME_PROCESSES))
        names = tuple(n.strip().lower() for n in raw.split(",") if n.strip())
        # 整行被清空時退回預設,否則代理偵測會永遠比對不到任何行程
        result["game_processes"] = names or DEFAULT_GAME_PROCESSES
    except (ValueError, configparser.Error):
        pass
    return result


def save_settings(settings):
    """把 settings dict 寫回 settings.ini。寫入失敗靜默忽略 (下次載入用預設)。
    ini 內部以英文命名,避免非 ASCII 字元造成使用者手動編輯時的編碼疑慮。
    """
    path = get_external_path(SETTINGS_CFG_NAME)
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser["Display"] = {"font_scale": f"{settings.get('font_scale', FONT_SCALE_DEFAULT):.2f}"}
    parser["Tracking"] = {
        "track_damage": "true" if settings.get("track_damage", True) else "false",
        "track_heal": "true" if settings.get("track_heal", False) else "false",
        "detect_chain": "true" if settings.get("detect_chain", False) else "false",
    }
    parser["Layout"] = {
        "popout_log": "true" if settings.get("popout_log", False) else "false",
        "popout_skill": "true" if settings.get("popout_skill", False) else "false",
    }
    parser["DevLog"] = {
        f"filter_{key}": "true" if settings.get(f"dev_filter_{key}", True) else "false"
        for key, _, _ in DEV_CATEGORIES
    }
    # 這裡是整檔覆寫,不寫回去的話使用者手改的行程名會被下一次存檔洗掉
    parser["Network"] = {
        "game_processes": ",".join(
            settings.get("game_processes") or DEFAULT_GAME_PROCESSES),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)
    except Exception:
        pass


def display_units(text):
    """估算顯示寬度單位:CJK / 全形算 2,其餘算 1。只拿來估按鈕寬度,不必精確。"""
    return sum(2 if ord(ch) > 0x2E7F else 1 for ch in text)


def clip_units(text, limit):
    """依顯示單位截斷過長的名字,尾端補省略號。"""
    if display_units(text) <= limit:
        return text
    out, used = [], 0
    for ch in text:
        w = 2 if ord(ch) > 0x2E7F else 1
        if used + w > limit - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + "…"


def target_btn_width(text):
    return min(TARGET_BTN_MAX_W,
               max(TARGET_BTN_MIN_W, display_units(text) * TARGET_BTN_UNIT_W + 12))


def format_skill_name(skill_id):
    """把 skill_id 轉為顯示名稱。
    - 0x00000000  → 「疑似符文傷害」(依 PacketNotes §5,符文附加傷害的 skill ID 為 0)
    - SKILL_NAMES 有對應 → 使用者命名
    - 其他        → 顯示 hex ID
    """
    if skill_id == 0:
        return "疑似符文傷害"
    return SKILL_NAMES.get(skill_id) or f"0x{skill_id:08X}"


def format_buff_name(buff_id):
    """把 buffId 轉為顯示名稱。

    只查 effects.ini —— buffId 與 skill_id 是不同命名空間,查 SKILL_NAMES 只會
    撞出無關的技能名 (見 Note/MM_Scribe_PacketNotes_Buff.md §3)。
    查不到就退回 hex,方便使用者自己補進 effects.ini。
    """
    return EFFECT_NAMES.get(buff_id) or f"Buff 0x{buff_id:08X}"


def list_bpf_devices():
    """列出系統上所有 /dev/bpf* 裝置節點,依編號排序。
    scapy 的 get_dev_bpf() 會一路試到 /dev/bpf255,所以這裡也不能只看前幾個 —
    只掃 bpf0~3 的話,前幾個裝置被其他程式佔用時會誤判成「沒有權限」。
    """
    try:
        names = [n for n in os.listdir("/dev") if n.startswith("bpf") and n[3:].isdigit()]
    except OSError:
        return []
    return sorted(names, key=lambda n: int(n[3:]))


def check_capture_backend():
    """檢查抓封包所需的底層驅動是否就緒。
    - Windows: 需安裝 Npcap / WinPcap,檢查關鍵 DLL 是否存在
    - macOS:   libpcap 為系統內建,改為檢查是否有 BPF 裝置節點
    回傳 (ok: bool, hint: str) — hint 為失敗時要顯示給使用者的補救說明。
    """
    if IS_WINDOWS:
        candidates = [
            r"C:\Windows\System32\Npcap\wpcap.dll",       # Npcap 標準安裝路徑
            r"C:\Windows\System32\Npcap\Packet.dll",
            r"C:\Windows\SysWOW64\Npcap\wpcap.dll",       # 32-bit 相容位置
            r"C:\Windows\System32\wpcap.dll",             # 舊 WinPcap 或 Npcap 相容模式
            r"C:\Windows\SysWOW64\wpcap.dll",
        ]
        if any(os.path.exists(p) for p in candidates):
            return True, ""
        return False, "請至 https://npcap.com/ 下載並安裝"

    if IS_MACOS:
        # libpcap 自 macOS 11 起收進 dyld shared cache,檔案系統上看不到,
        # 因此不驗證 dylib,只確認 BPF 裝置節點存在 (權限另由 check_capture_permission 判斷)
        devices = list_bpf_devices()
        if devices:
            return True, ""
        return False, "系統找不到 /dev/bpf* 裝置節點"

    return False, f"尚未支援的作業系統: {sys.platform}"


def check_capture_permission():
    """檢查目前是否具備開啟抓包裝置的權限。
    - Windows: 是否以系統管理員身分執行
    - macOS:   /dev/bpf* 多半是 root:wheel 0600,但裝了 Wireshark 的 ChmodBPF 後
               一般使用者也能讀,所以直接測「能不能真的開起來」而非只看 euid
    回傳 (ok: bool, detail: str)
    """
    if IS_WINDOWS:
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                return True, "scapy sniff 具備所需權限"
        except Exception:
            pass
        return False, "請關閉程式後對 exe 右鍵 →「以系統管理員身分執行」"

    if IS_MACOS:
        if os.geteuid() == 0:
            return True, "以 root 執行,具備 BPF 存取權限"
        for name in list_bpf_devices():
            path = os.path.join("/dev", name)
            try:
                # 必須用 O_RDWR:scapy 的 get_dev_bpf() 就是這樣開的。
                # 只用 O_RDONLY 測的話,權限若設成唯讀會誤判為可用,
                # 但實際 sniff 仍會失敗 — 那種狀況極難除錯。
                os.close(os.open(path, os.O_RDWR))
                return True, "BPF 裝置可直接存取 (已套用 ChmodBPF)"
            except PermissionError:
                break
            except OSError:
                # 裝置存在但正被其他程式佔用 → 權限本身沒問題,換下一個試
                continue
        return False, ("BPF 裝置需要提權。建議安裝 Wireshark 內附的 ChmodBPF "
                       "(安裝後免 sudo),或改以 sudo 執行本程式")

    return False, f"尚未支援的作業系統: {sys.platform}"


def list_network_ifaces():
    """列舉可供 sniff 的網路介面,回傳統一格式的 dict 清單:
        {"name": 傳給 sniff(iface=) 的識別, "description": 顯示名稱, "ips": [IPv4...]}

    Windows 的 get_windows_if_list() 本來就是這個格式;macOS/Linux 走 scapy 的
    跨平台介面表,name 會是 BSD 名稱 (en0/en1/bridge100...)。
    """
    if IS_WINDOWS:
        from scapy.arch.windows import get_windows_if_list
        return list(get_windows_if_list())

    from scapy.config import conf
    all_ifaces = list((conf.ifaces or {}).values())

    # get_working_ifaces() 會逐張做 IFF_UP + BIOCSETIF 探測,能濾掉一堆掃了也是白掃的
    # 虛擬介面,所以優先用它。但它的判定完全交給平台 provider,遇上探測失敗就會
    # 整份空掉 — 那時得退回未過濾的 conf.ifaces,否則掃描階段會直接報「沒有可掃描的介面」。
    ifaces = []
    try:
        from scapy.interfaces import get_working_ifaces
        ifaces = list(get_working_ifaces())
    except Exception:
        ifaces = []
    if not ifaces:
        ifaces = all_ifaces

    out = []
    for itf in ifaces:
        name = getattr(itf, "name", None) or str(itf)
        # 一張介面可能掛多個 IPv4 (例如 en0 同時有 DHCP 位址與手動位址),
        # 只取 .ip 的話,主位址剛好是空的就會被下游的 IPv4 過濾整張丟掉。
        ips = []
        for ip in (getattr(itf, "ips", None) or {}).get(4, []) or []:
            if ip and ip not in ips:
                ips.append(str(ip))
        primary = getattr(itf, "ip", None)
        if primary and str(primary) not in ips:
            ips.insert(0, str(primary))
        out.append({
            "name": name,
            "description": getattr(itf, "description", None) or name,
            "ips": ips,
        })
    return out


def default_route_iface():
    """回傳預設路由所在的介面名稱,失敗則 None。
    掃描時把它排在最前面 — 遊戲流量幾乎都走這張。
    """
    try:
        from scapy.config import conf
        return conf.route.route("0.0.0.0")[0]
    except Exception:
        return None


# macOS 上這些介面依其用途就不可能承載遊戲流量,先剔除可省下大量掃描時間
# (一台開著虛擬機的 Mac 上,feth/bridge 之類的介面動輒十幾張)
_SKIP_IFACE_PREFIXES = ("lo", "feth", "gif", "stf", "awdl", "llw", "anpi", "ap")


def _is_never_game_traffic(name):
    """en/bridge/utun/vmenet 一律保留 — 實體網卡、虛擬機橋接、VPN 都可能是遊戲的出口。"""
    if not IS_MACOS or not name:
        return False
    return str(name).startswith(_SKIP_IFACE_PREFIXES)


def dmg_event_flags(tags, is_dot, is_sustain, is_chain=False):
    """把標籤列表壓成一個整數位元遮罩 (見 DMG_EVENT_TAG_BITS)。
    未知(...) 這種動態標籤不進遮罩 — 位元位置必須是固定語意,日後圖表才讀得懂。
    """
    bits = 0
    for i, name in enumerate(DMG_EVENT_TAG_BITS):
        if name in tags:
            bits |= 1 << i
    if is_dot:
        bits |= DMG_EVENT_DOT_BIT
    if is_sustain:
        bits |= DMG_EVENT_SUSTAIN_BIT
    if is_chain:
        bits |= DMG_EVENT_CHAIN_BIT
    return bits


def seq_before(a, b):
    """TCP seq 比較:a 是否排在 b 之前 (32-bit 環繞安全,RFC 1982 的作法)。

    直接用 `<` 在 seq 繞過 0xFFFFFFFF 時會整個反過來。長連線跑幾小時就會踩到。
    """
    return a != b and ((b - a) & 0xFFFFFFFF) < 0x80000000


IP_FILTER_NET = "43.0.0.0/8"
DEFAULT_BPF_FILTER = f"ip net {IP_FILTER_NET} and tcp"


# ================================================
# 本機代理 / 加速器偵測 (Windows)
#   奇游那類加速器會用 TUN 把遊戲連線整個接管,改接到本機的代理端口
#   (netstat 會看到遊戲行程連往 127.x 或本機 TUN 位址,例如 172.18.0.1:49335)。
#   這種情況下真實伺服器 IP (43.0.0.0/8) 不會出現在「任何」網卡的封包裡,
#   唯一看得到明文遊戲協議的位置,是 Loopback 上「遊戲 ↔ 代理端口」的往返流量。
#   ⚠ 未驗證:尚無實際加速器環境的封包樣本,以下推論待樣本佐證。
# ================================================
def _run_hidden(cmd):
    """跑外部命令並取回 stdout。打包成 --noconsole 時不會閃出黑窗。"""
    kwargs = {"text": True, "errors": "replace", "stderr": subprocess.DEVNULL}
    if IS_WINDOWS:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.check_output(cmd, **kwargs)


def detect_local_game_proxy(process_names=None):
    """偵測遊戲流量是否被本機代理 (加速器 / VPN) 接管。

    回傳 (代理端口 set, 代理程式名說明);遊戲沒開、直連伺服器、或偵測失敗都回 None。
    """
    if not IS_WINDOWS:
        return None
    names = tuple(n.lower() for n in (process_names or DEFAULT_GAME_PROCESSES))
    try:
        # 1) tasklist CSV → 找遊戲行程 PID。用 CSV 而非表格輸出,欄位位置才不受
        #    系統語言影響 (中文版 Windows 的表頭寬度跟英文版不一樣)
        pid_name = {}
        for row in csv.reader(io.StringIO(
                _run_hidden(["tasklist", "/FO", "CSV", "/NH"]))):
            if len(row) >= 2 and row[1].isdigit():
                pid_name[row[1]] = row[0]
        game_pids = {p for p, n in pid_name.items() if n.lower() in names}
        if not game_pids:
            return None

        # 2) 本機自有 IPv4 — 代理常綁在 TUN 位址 (如 172.18.0.1) 而非 127.0.0.1
        local_ips = {"127.0.0.1"}
        try:
            for itf in list_network_ifaces():
                for ip in (itf.get("ips") or []):
                    if ":" not in str(ip):
                        local_ips.add(str(ip))
        except Exception:
            pass

        # 3) netstat 一次撈完,順手記下每個監聽端口屬於哪個 PID (用來報代理程式名)
        rows, listen_pid = [], {}
        for line in _run_hidden(["netstat", "-ano", "-p", "TCP"]).splitlines():
            parts = line.split()
            if len(parts) != 5 or parts[0].upper() != "TCP":
                continue
            rows.append(parts)
            if parts[3].upper() == "LISTENING":
                listen_pid[parts[1].rsplit(":", 1)[-1]] = parts[4]

        # 遊戲行程自己持有的本地端點 — 用來排除遊戲連自己的內部 IPC
        game_locals = {local for _, local, _, state, pid in rows
                       if state.upper() == "ESTABLISHED" and pid in game_pids}

        proxy_ports = set()
        for _, local, remote, state, pid in rows:
            if state.upper() != "ESTABLISHED" or pid not in game_pids:
                continue
            rip, _, rport = remote.rpartition(":")
            if rip.startswith("43."):
                return None  # 有直連伺服器的連線 → 不需要代理模式
            if rip in local_ips and rport.isdigit() and remote not in game_locals:
                proxy_ports.add(int(rport))
        if not proxy_ports:
            return None

        pnames = sorted({pid_name.get(listen_pid.get(str(p), ""), "")
                         for p in proxy_ports} - {""})
        return proxy_ports, (", ".join(pnames) or "未知代理程式")
    except Exception:
        return None


def find_loopback_iface():
    """回傳可用於擷取本機往返流量的介面 dict,找不到回 None。

    Npcap 的 loopback 裝置 (\\Device\\NPF_Loopback) 不一定會掛上 127.0.0.1,
    所以名稱與 IP 兩種特徵都比對,只認 IP 會在裝好的機器上誤報「沒裝」。
    """
    try:
        ifaces = list_network_ifaces()
    except Exception:
        return None
    for itf in ifaces:
        if "127.0.0.1" in [str(ip) for ip in (itf.get("ips") or [])]:
            return itf
    for itf in ifaces:
        text = f"{itf.get('name') or ''} {itf.get('description') or ''}".lower()
        if "loopback" in text or "npf_loopback" in text:
            return itf
    return None


HIGHLIGHT_OPTIONS = ["無", "爆擊", "強擊", "破防", "無防備", "連擊", "多重打擊", "追擊",
                     "迎擊", "延長破防", "終結"]

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class LiveDamageMonitor:
    def __init__(self, root):
        self.root = root

        # 讀設定並在建立任何 widget 前先套用縮放 (widget/window scaling 都是全域狀態,
        # 提前設好 CTk 建立的元件會直接以正確尺寸誕生,不必事後重排)
        self.settings = load_settings()
        self.font_scale = self.settings["font_scale"]
        ctk.set_widget_scaling(self.font_scale)
        ctk.set_window_scaling(self.font_scale)

        self.root.title(f"MM Scribe {VERSION_STR}")
        # 初始高度 900 (三個資訊 pane 均分後各約 180px,一開就看得到內容);
        # 每個 popout 中的 pane 從初值扣 200,啟動就用正確高度,
        # 不能在 __init__ 尾端做 delta 調整 — 那時 winfo_height() 因視窗尚未 realize
        # 回傳 1,dcalc 後會被 clamp 到 200 → 主視窗變超小、看不到開始按鈕
        # 340 是「dmg_banner + 3 條控制列 + status_bar + padding」的合理下限,
        # 保證兩個都 popout 時也看得到計時器那排
        initial_h = 900
        if self.settings.get("popout_log", False):
            initial_h -= 200
        if self.settings.get("popout_skill", False):
            initial_h -= 200
        initial_h = max(340, initial_h)
        self._initial_geometry = f"500x{initial_h}"
        self.root.geometry(self._initial_geometry)
        # 這一發多半會被夾掉 (原因見 _apply_initial_geometry),真正生效的是
        # __init__ 尾端排的那輪重試。

        # 設定視窗標題列 icon (優先用 dev icon,找不到再退回一般 icon)
        # macOS 的 Tk 不吃 .ico,改用 iconphoto 讀 PNG;打包成 .app 後
        # Dock 圖示是由 bundle 的 CFBundleIconFile 提供,這裡失敗不影響功能。
        if IS_MACOS:
            candidates = ("icon_dev.png" if not RELEASE_BUILD else "icon.png", "icon.png")
        else:
            candidates = ("icon_dev.ico" if not RELEASE_BUILD else "icon.ico", "icon.ico")
        for candidate in candidates:
            icon_path = get_resource_path(candidate)
            if not os.path.exists(icon_path):
                continue
            try:
                if IS_MACOS:
                    self._app_icon = tk.PhotoImage(file=icon_path)
                    self.root.iconphoto(True, self._app_icon)
                else:
                    self.root.iconbitmap(icon_path)
                break
            except Exception:
                pass
        # 最小尺寸:寬 400 高 180 (剛好夠塞看板+兩排控制列+日誌 header)
        self.root.minsize(400, 180)

        # 狀態變數
        self.is_monitoring = False
        self.sniff_thread = None
        # 傷害解析的 TCP 接續狀態 (見 _dmg_feed);conn_key → 該連線的緩衝與進度
        self._dmg_streams = collections.OrderedDict()
        self.is_topmost = False
        # 診斷 LOG 現在是常駐區塊,沒有開關;發布版沒有 UI 入口就別花時間組字串
        self.is_dev_mode = not RELEASE_BUILD
        # 強制偵測 (見 toggle_force_all)。parse_payload 跑在 sniff 執行緒,
        # 讀這個 attribute 而不是 tk 變數 — 別在那條執行緒碰 tk widget。
        self.force_all = False
        self._tooltip_win = None
        self._tooltip_after_id = None
        # 角色身分偵測狀態 (見 _ident_reset / _scan_identity)。
        # 攔截執行緒獨立於「開始/停止」— 換地圖時的 0x4FFF/0x4E4F 一輩子只送那一次,
        # 沒在收就永遠錯過,所以程式一啟動就開始收 (見 _ensure_sniffer)。
        self._ident_reset()
        # 怪物登場包探針狀態 (見 _mob_reset / _mob_scan) — 與身分偵測完全分離
        self._mob_reset()
        # Buff 狀態 (見 _buff_reset / _buff_scan)
        self._buff_reset()
        # 攔截執行緒世代編號:換網卡時 +1,舊執行緒下一個封包就自行退出
        self._sniff_gen = 0

        # === 傷害統計:依攻擊對象分桶 ===
        # target_stats: {TARGET_ALL 或 target_id(int) → stat bucket}
        #   每筆傷害會同時累加到 TARGET_ALL 與該筆的 target_id 兩個桶,
        #   畫面永遠只讀「目前選取的那一桶」(見 _view)。
        # target_order:  target_id 依首次出現順序,決定下拉選單排列
        # selected_target: 目前選取的 key (TARGET_ALL 或某個 target_id)
        self.target_stats = {TARGET_ALL: self._new_stat_bucket()}
        self.target_order = []
        self.selected_target = TARGET_ALL
        self.target_buttons = {}      # key (TARGET_ALL 或 target_id) → CTkButton
        self._target_sort_after_id = None   # 目標排序輪詢的 after id
        # 讀存檔帶進來的目標名字 {target_id → (名字, 序號或 None)}。與 _entity_names
        # 分開放:那是本次執行實際收到的登場包,存檔的是別次執行 (甚至別人) 的 eid,
        # 混在一起會讓序號的意義變得不可信。
        self._loaded_names = {}

        # 攻擊事件緩衝:切換目標時要重畫日誌,所以每筆都要留下結構化紀錄。
        # deque(maxlen) 超量會自動丟最舊的,不必手動修剪。
        self.log_entries = collections.deque(maxlen=LOG_HISTORY_MAX)

        # 傷害時間序列:每筆傷害一列 (ts, target_id, skill_id, damage, flags)。
        # 只寫不讀 (日誌不顯示時間戳),留給日後的傷害曲線圖表。
        # append 在攔截執行緒上跑,deque.append 本身是 atomic 的,不另外加鎖。
        self.damage_events = collections.deque(maxlen=DMG_EVENT_MAX)

        # 日誌欄寬量測用的字體 (見 _scaled_tab_stops);字體物件需要 Tk root,
        # 故延後到第一次用到時才建立
        self._log_font = None

        # skill_rows: 已建立的顯示列 (以聚合後的 display name 為 key)
        self.skill_rows = {}

        # 用 CTkFont 給 tk.Canvas 的技能列文字使用,才能跟 CTkLabel (detail) 走
        # 同一套字體/縮放管線 (widget_scaling × DPI scaling 都會自動套用),
        # 兩邊視覺大小一致。共用同一份 font instance,scale 變更時 CTk 會自動更新。
        self._skill_name_font = ctk.CTkFont(
            family=FONT_UI, size=12, weight="normal")
        self._skill_value_font = ctk.CTkFont(
            family=FONT_LOG, size=12, weight="normal")

        # Resize debounce: 拖窗期間暫停技能排行更新,停下 150ms 後補一次
        self._is_resizing = False
        self._resize_after_id = None

        # 自動選定的收包網卡 (由掃描結果決定,None = 讓 scapy 用預設)
        self.chosen_iface = None
        # sniff 用的 BPF 過濾條件。預設抓 43/8 直連流量;偵測到加速器代理時
        # 由 _apply_chosen_iface 換成「tcp 代理端口」(見 _scan_ifaces_for_traffic)
        self.sniff_filter = DEFAULT_BPF_FILTER

        # 計時器:end_time 為 None 表示無倒數;after_id 用於取消已排程的 tick
        self.timer_end_time = None
        self.timer_after_id = None

        # 純檢視模式:讀取存檔後為 True,鎖住「開始/計時」直到按下「清除」
        # (見 _set_view_only)
        self.view_only = False

        # 追蹤模式旗標 (由 settings 載入,可從設定畫面切換)
        self.track_damage = self.settings["track_damage"]
        self.track_heal = self.settings["track_heal"]
        self.detect_chain = self.settings["detect_chain"]
        self.track_damage_var = tk.BooleanVar(value=self.track_damage)
        self.track_heal_var = tk.BooleanVar(value=self.track_heal)
        self.detect_chain_var = tk.BooleanVar(value=self.detect_chain)

        # Popout 旗標 (獨立視窗顯示攻擊日誌 / 技能排行)
        # popout_log_win / popout_skill_win: Toplevel 或 None
        self.popout_log = self.settings["popout_log"]
        self.popout_skill = self.settings["popout_skill"]
        self.popout_log_var = tk.BooleanVar(value=self.popout_log)
        self.popout_skill_var = tk.BooleanVar(value=self.popout_skill)
        self._log_popout_win = None
        self._skill_popout_win = None
        # 診斷 LOG 展開視窗:一律獨立 Toplevel (底部區塊點一下才開)
        self._dev_popout_win = None
        # 診斷 LOG 緩衝:底部區塊與展開視窗都從這裡取內容 (見 dev_log)
        # 每筆存 (文字, 顏色 tag, 分類 key);tag 為 None = 一般灰字,分類 None = 不歸類
        self._dev_lines = collections.deque(maxlen=DEV_LOG_MAX)
        # 分類過濾只影響「展開視窗顯示哪幾行」,緩衝一律照收 —— 事後把某類打開
        # 也看得到先前的訊息,不必重跑一場
        self._dev_filter = {key: bool(self.settings[f"dev_filter_{key}"])
                            for key, _, _ in DEV_CATEGORIES}
        self._dev_filter_vars = {}

        # 提前建立 collapse 狀態與 merge_var,讓 pane 重建 (dock/popout) 時值可延續
        self.log_collapsed = False
        self._prev_height = None
        self.skill_collapsed = False
        self.merge_var = tk.BooleanVar(value=False)
        self.buff_collapsed = False

        # 治癒統計 (heal_total = heal_self + heal_ally,累加自 0x5029 事件)
        self.heal_total = 0
        self.heal_self = 0
        self.heal_ally = 0
        # 本地玩家角色 ID:透過 0x502A ↔ 0x5029 交叉比對自動學習 (見 PacketNotes §5)
        # None 表示尚未學到;學到後整個 session 沿用
        # 護盾在 local_player_id 學到前無法可靠分類,一律走 heal_unknown (中性黃字)
        self.local_player_id = None

        # ----------------------------------------------------
        # 1. 頂部看板:傷害統計 (packing 交給 _apply_tracking_mode 依旗標控制)
        # ----------------------------------------------------
        self.dmg_banner = ctk.CTkFrame(root, corner_radius=0, fg_color="#1a1a1a")

        # 目標選擇列已移到「計時器列與攻擊事件日誌之間」(見 3.6 節)

        # -- 主要統計列: 累積傷害 + DPS --
        main_row = ctk.CTkFrame(self.dmg_banner, fg_color="transparent")
        main_row.pack(fill="x", pady=(8, 0))

        left_stats = ctk.CTkFrame(main_row, corner_radius=0, fg_color="transparent")
        left_stats.pack(side="left", expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(left_stats, text="累積傷害",
                     font=(FONT_UI, 12),
                     text_color="#888888").pack()
        self.lbl_total_dmg = ctk.CTkLabel(left_stats, text="0",
                                          font=(FONT_LOG, 24),
                                          text_color="#ff4d4d")
        self.lbl_total_dmg.pack(pady=(2, 0))

        right_stats = ctk.CTkFrame(main_row, corner_radius=0, fg_color="transparent")
        right_stats.pack(side="right", expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(right_stats, text="DPS (每秒傷害)",
                     font=(FONT_UI, 12),
                     text_color="#888888").pack()
        self.lbl_dps = ctk.CTkLabel(right_stats, text="0",
                                    font=(FONT_LOG, 24),
                                    text_color="#ffcc4d")
        self.lbl_dps.pack(pady=(2, 0))

        # -- 覆蓋率列: COVERAGE_TAGS (資料筆數 < COVERAGE_MIN_HITS 時顯示「—」) --
        cov_row = ctk.CTkFrame(self.dmg_banner, fg_color="transparent")
        cov_row.pack(fill="x", pady=(0, 8))

        self.lbl_cov = {}
        for tag_name in COVERAGE_TAGS:
            col = ctk.CTkFrame(cov_row, fg_color="transparent")
            col.pack(side="left", expand=True, fill="x", padx=4)
            ctk.CTkLabel(col, text=f"{tag_name}覆蓋率",
                         font=(FONT_UI, 12),
                         text_color="#888888").pack()
            lbl = ctk.CTkLabel(col, text="—",
                               font=(FONT_LOG, 16),
                               text_color="#88ccff")
            lbl.pack()
            self.lbl_cov[tag_name] = lbl

        # ----------------------------------------------------
        # 1.5 頂部看板:治癒統計 (packing 交給 _apply_tracking_mode)
        # ----------------------------------------------------
        self.heal_banner = ctk.CTkFrame(root, corner_radius=0, fg_color="#1a1a1a")

        # -- 主要統計: 治癒總量 --
        heal_total_row = ctk.CTkFrame(self.heal_banner, fg_color="transparent")
        heal_total_row.pack(fill="x")
        heal_total_col = ctk.CTkFrame(heal_total_row, fg_color="transparent")
        heal_total_col.pack(expand=True, fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(heal_total_col, text="治癒總量",
                     font=(FONT_UI, 12),
                     text_color="#888888").pack()
        self.lbl_heal_total = ctk.CTkLabel(heal_total_col, text="0",
                                            font=(FONT_LOG, 24),
                                            text_color="#4dd471")
        self.lbl_heal_total.pack(pady=(2, 0))

        # -- 子統計: 自身治癒 / 隊友治癒 --
        heal_sub_row = ctk.CTkFrame(self.heal_banner, fg_color="transparent")
        heal_sub_row.pack(fill="x", pady=(0, 8))
        self_col = ctk.CTkFrame(heal_sub_row, fg_color="transparent")
        self_col.pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkLabel(self_col, text="自身治癒",
                     font=(FONT_UI, 11),
                     text_color="#888888").pack()
        self.lbl_heal_self = ctk.CTkLabel(self_col, text="0",
                                           font=(FONT_LOG, 16),
                                           text_color="#4dd471")
        self.lbl_heal_self.pack()
        ally_col = ctk.CTkFrame(heal_sub_row, fg_color="transparent")
        ally_col.pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkLabel(ally_col, text="隊友治癒",
                     font=(FONT_UI, 11),
                     text_color="#888888").pack()
        self.lbl_heal_ally = ctk.CTkLabel(ally_col, text="0",
                                           font=(FONT_LOG, 16),
                                           text_color="#88ccff")
        self.lbl_heal_ally.pack()

        # ----------------------------------------------------
        # 2. 控制列 Row 1: 啟停/清除/置頂/強制偵測
        # ----------------------------------------------------
        self.ctrl_row1 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row1.pack(fill="x", padx=10, pady=3)
        ctrl_row1 = self.ctrl_row1  # local alias 保留現有引用

        self.btn_start = ctk.CTkButton(ctrl_row1, text="▶ 開始", width=70, corner_radius=8,
                                       command=self.start_monitoring)
        self.btn_start.pack(side="left", padx=(6, 2), pady=6)
        self.btn_stop = ctk.CTkButton(ctrl_row1, text="⏹ 停止", width=70, corner_radius=8,
                                      state="disabled", command=self.stop_monitoring)
        self.btn_stop.pack(side="left", padx=2, pady=6)
        # 記住停止按鈕預設樣式,用於停止監控後還原
        self._btn_stop_default_fg = self.btn_stop.cget("fg_color")
        self._btn_stop_default_hover = self.btn_stop.cget("hover_color")
        self.btn_clear = ctk.CTkButton(ctrl_row1, text="🧹 清除", width=70, corner_radius=8,
                                       fg_color="#6a5a5a", hover_color="#8a6a6a",
                                       command=self.clear_data)
        self.btn_clear.pack(side="left", padx=2, pady=6)

        self.topmost_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(ctrl_row1, text="📌 置頂", variable=self.topmost_var,
                        command=self.toggle_topmost, corner_radius=5,
                        checkbox_width=18, checkbox_height=18).pack(side="left", padx=(8, 4), pady=6)
        # 強制偵測:身分門檻的逃生門 (見 toggle_force_all)。不記進 settings.ini,
        # 每次啟動預設關閉 — 開著它拿到的數據不只屬於自己,不該在使用者不知情下沿用。
        # 發布版也要顯示 (跟「開發者」不同):角色 ID 偵測失敗時這是唯一的救急手段。
        self.force_all_var = tk.BooleanVar(value=False)
        # width 收窄:CTkCheckBox 預設 100,四個字用不完,尾巴的空白會把 ? 推很遠
        ctk.CTkCheckBox(ctrl_row1, text="強制偵測", variable=self.force_all_var,
                        command=self.toggle_force_all, corner_radius=5, width=80,
                        checkbox_width=18, checkbox_height=18).pack(side="left", padx=(8, 0), pady=6)
        # 說明鈕:圓圈裡一個問號。不用 Unicode 的 ⓘ / ❔ (字型支援不一,實際長相看系統),
        # 改成正方形 CTkLabel + corner_radius=一半邊長 — 畫出來就是實心圓,配色跟著主題走
        self._force_tip_btn = ctk.CTkLabel(
            ctrl_row1, text="?", width=18, height=18, corner_radius=9,
            fg_color="#3a3a3a", text_color="#cccccc", font=(FONT_UI, 11))
        self._force_tip_btn.pack(side="left", padx=(5, 4), pady=6)
        self._bind_tooltip(self._force_tip_btn, FORCE_ALL_TIP)
        # 滑過時亮一點,讓人知道它是可互動的
        self._force_tip_btn.bind(
            "<Enter>", lambda _e: self._force_tip_btn.configure(fg_color="#5a5a5a"), add="+")
        self._force_tip_btn.bind(
            "<Leave>", lambda _e: self._force_tip_btn.configure(fg_color="#3a3a3a"), add="+")
        # 「🛠 開發者」勾選已移除 — 診斷 LOG 改為視窗底部的常駐區塊 (見 §6)

        # ----------------------------------------------------
        # 3. 控制列 Row 2: 標籤高亮 + 視窗透明度
        # ----------------------------------------------------
        self.ctrl_row2 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row2.pack(fill="x", padx=10, pady=(0, 3))
        ctrl_row2 = self.ctrl_row2  # local alias 保留現有引用

        ctk.CTkLabel(ctrl_row2, text="🎯 高亮:").pack(side="left", padx=(8, 3), pady=6)
        self.highlight_var = tk.StringVar(value="無")
        # 切換高亮後整份日誌重畫,舊事件也跟著改色 (紅字判定在 _insert_log_line 即時算)
        self.highlight_combo = ctk.CTkComboBox(ctrl_row2, values=HIGHLIGHT_OPTIONS,
                                               variable=self.highlight_var, state="readonly",
                                               width=95, corner_radius=8,
                                               command=lambda _v: self._render_log())
        self.highlight_combo.pack(side="left", padx=(0, 8), pady=6)

        ctk.CTkLabel(ctrl_row2, text="🪟 透明度:").pack(side="left", padx=(4, 3), pady=6)
        self.alpha_slider = ctk.CTkSlider(ctrl_row2, from_=30, to=100, number_of_steps=70,
                                          width=140, command=self.set_alpha)
        self.alpha_slider.set(100)
        self.alpha_slider.pack(side="left", padx=(0, 4), pady=6)
        self.lbl_alpha = ctk.CTkLabel(ctrl_row2, text="100%", width=40)
        self.lbl_alpha.pack(side="left", padx=(0, 8), pady=6)

        # ----------------------------------------------------
        # 3.5 控制列 Row 3: 計時器 (分/秒輸入 + 開始 + 倒數顯示)
        # ----------------------------------------------------
        self.ctrl_row3 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row3.pack(fill="x", padx=10, pady=(0, 3))
        ctrl_row3 = self.ctrl_row3  # local alias 保留現有引用

        ctk.CTkLabel(ctrl_row3, text="⏱ 計時:").pack(side="left", padx=(8, 3), pady=6)
        self.timer_min_var = tk.StringVar(value="1")
        self.timer_sec_var = tk.StringVar(value="0")
        ctk.CTkEntry(ctrl_row3, textvariable=self.timer_min_var, width=45,
                     justify="center", corner_radius=6).pack(side="left", padx=(0, 2), pady=6)
        ctk.CTkLabel(ctrl_row3, text="分").pack(side="left", padx=(0, 4), pady=6)
        ctk.CTkEntry(ctrl_row3, textvariable=self.timer_sec_var, width=45,
                     justify="center", corner_radius=6).pack(side="left", padx=(0, 2), pady=6)
        ctk.CTkLabel(ctrl_row3, text="秒").pack(side="left", padx=(0, 8), pady=6)

        self.btn_timer = ctk.CTkButton(ctrl_row3, text="⏱ 計時開始", width=95,
                                       corner_radius=8,
                                       fg_color="#5a8a5a", hover_color="#6aa06a",
                                       command=self.start_timer)
        self.btn_timer.pack(side="left", padx=(0, 8), pady=6)
        # 記住預設(閒置)樣式,計時停止後還原用
        self._btn_timer_idle_fg = self.btn_timer.cget("fg_color")
        self._btn_timer_idle_hover = self.btn_timer.cget("hover_color")

        self.lbl_timer_remaining = ctk.CTkLabel(ctrl_row3, text="",
                                                 font=(FONT_LOG, 13),
                                                 text_color="#88ccff")
        self.lbl_timer_remaining.pack(side="left", padx=(0, 8), pady=6)

        # ----------------------------------------------------
        # 3.6 目標選擇列: 決定看板 + 技能排行 + 日誌顯示哪個攻擊對象的資料
        #     緊貼在攻擊事件日誌上方 (packing 交給 _apply_tracking_mode)
        # ----------------------------------------------------
        self.target_row = ctk.CTkFrame(root, corner_radius=0)
        ctk.CTkLabel(self.target_row, text="👤 目標:",
                     font=(FONT_UI, 12)).pack(side="left", padx=(8, 4))
        self.lbl_target_hits = ctk.CTkLabel(self.target_row, text="0 筆",
                                            font=(FONT_UI, 11),
                                            text_color="#888888")
        # 先 pack 右側的筆數,按鈕列才能吃掉剩餘寬度
        self.lbl_target_hits.pack(side="right", padx=(6, 8))
        # 橫向捲動:對象再多也只占一列高度,不會把下方日誌區擠掉
        self.target_bar = ctk.CTkScrollableFrame(self.target_row, orientation="horizontal",
                                                 height=34, corner_radius=0,
                                                 fg_color="transparent")
        self.target_bar.pack(side="left", fill="x", expand=True)

        # ----------------------------------------------------
        # 0. 頂部狀態列 (快捷按鈕:Discord / 免責聲明 靠左, 設定 靠右)
        #    放最上方,side="top" + before=ctrl_row1 保證它永遠是第一個元件
        #    網路檢測按鈕已搬到「設定」內,Npcap 狀態不再直接顯示於此
        # ----------------------------------------------------
        self.status_bar = ctk.CTkFrame(root, corner_radius=0, height=28, fg_color="#1a1a1a")
        self.status_bar.pack(side="top", fill="x", padx=10, pady=(8, 0),
                              before=self.ctrl_row1)

        # 左側:Discord + 免責聲明 (pack 順序決定顯示順序; side=left 是從左往右堆)
        ctk.CTkButton(self.status_bar, text="💬 Discord",
                      width=90, height=22, corner_radius=6,
                      fg_color="#5865f2", hover_color="#4752c4",
                      font=(FONT_UI, 10),
                      command=self.open_discord).pack(side="left", padx=(8, 4), pady=2)
        ctk.CTkButton(self.status_bar, text="⚠ 免責聲明",
                      width=90, height=22, corner_radius=6,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      font=(FONT_UI, 10),
                      command=self.show_disclaimer).pack(side="left", padx=4, pady=2)

        # 右側:設定
        ctk.CTkButton(self.status_bar, text="⚙ 設定",
                      width=70, height=22, corner_radius=6,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      font=(FONT_UI, 10),
                      command=self.show_settings).pack(side="right", padx=(4, 8), pady=2)

        # ----------------------------------------------------
        # 5. 即時攻擊事件日誌 + 5.5 技能傷害排行
        #    抽成 _build_*_pane(parent) 方法,dock/popout 兩情境共用建立邏輯
        #    起始時 parent = root,若 popout_* 為 True,__init__ 尾端會 pop 出去
        # ----------------------------------------------------
        # 三個資訊 pane 統一裝進 pane_container,高度由 _layout_panes 以 grid 均分
        self.pane_container = ctk.CTkFrame(root, fg_color="transparent")
        self._build_log_pane(self.pane_container)
        self._build_skill_pane(self.pane_container)
        self._build_buff_pane(self.pane_container)

        # ----------------------------------------------------
        # 5.6 治癒事件日誌 (可折疊,packing 交給 _apply_tracking_mode)
        # ----------------------------------------------------
        self.heal_log_pane = ctk.CTkFrame(root, corner_radius=0)

        self.heal_collapsed = False
        heal_header = ctk.CTkFrame(self.heal_log_pane, fg_color="transparent")
        heal_header.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_heal_toggle = ctk.CTkButton(
            heal_header,
            text="▼ 治癒事件日誌",
            font=(FONT_UI, 11),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_heal_collapse,
        )
        self.btn_heal_toggle.pack(side="left", fill="x", expand=True)

        self.heal_log_area = ctk.CTkTextbox(self.heal_log_pane, wrap="word",
                                             font=(FONT_LOG, 13),
                                             corner_radius=0)
        self.heal_log_area.pack(fill="both", expand=True, padx=6, pady=6)
        # 治療自己 (綠) / 治療他人 (藍) 顏色標籤
        self.heal_log_area._textbox.tag_config("heal_self", foreground="#4dd471")
        self.heal_log_area._textbox.tag_config("heal_ally", foreground="#88ccff")
        # 尚未識別本地玩家 ID 前的中性配色 (黃),用來標示「無法判定自己/他人」的事件
        self.heal_log_area._textbox.tag_config("heal_unknown", foreground="#ffcc4d")
        self.heal_log_area.configure(state="disabled")

        # ----------------------------------------------------
        # 6. 診斷 LOG 區塊 (視窗最底下,常駐)
        # ----------------------------------------------------
        # 收合狀態只顯示最新一行;點整塊 → 彈出獨立視窗看完整 LOG (診斷單行很長,
        # 壓在主畫面內看不完)。內容一律存在 self._dev_lines,視窗只是它的檢視器。
        #
        # side="bottom" 是關鍵:pack 在中段 pane 之前且靠底邊,
        # 中段那些 expand=True 的面板 (日誌/排行/治癒) 再怎麼撐都吃不掉這一條。
        self.dev_pane = None
        self.dev_log_area = None
        self.dev_strip = ctk.CTkButton(
            root, text=DEV_STRIP_EMPTY, font=(FONT_MONO, 11),
            fg_color="#1a1a1a", hover_color="#2a2a2a", text_color="#888888",
            anchor="w", corner_radius=6, height=26,
            command=self._popout_dev,
        )
        # 發布版不顯示 (等同舊版隱藏「🛠 開發者」勾選的處置);widget 仍建好,
        # dev_log 照寫緩衝,只是沒有 UI 入口
        if not RELEASE_BUILD:
            self.dev_strip.pack(side="bottom", fill="x", padx=10, pady=(0, 6))

        # ----------------------------------------------------
        # 7. 底部控制列: 紀錄 / 讀取存檔 (視窗最底下,診斷 LOG 的上方)
        # ----------------------------------------------------
        # 沒有併進 Row 1 —— 那列已經有六個元件,再塞會超出 minsize 的 400px 寬。
        # side="bottom" 且**必須 pack 在 dev_strip 之後**:同為 bottom 時,先 pack
        # 的貼最底邊,後 pack 的疊在它上面。理由同 dev_strip —— 中段那些
        # expand=True 的面板 (日誌/排行/治癒) 再怎麼撐都吃不掉這一條。
        # 發布版沒有 dev_strip,這列自然就成為最底下那條。
        self.ctrl_row4 = ctk.CTkFrame(root, corner_radius=0)
        self.ctrl_row4.pack(side="bottom", fill="x", padx=10, pady=(0, 3))
        ctrl_row4 = self.ctrl_row4  # local alias,與其他控制列一致

        self.btn_save = ctk.CTkButton(ctrl_row4, text="💾 紀錄", width=70, corner_radius=8,
                                      fg_color="#5a7a9a", hover_color="#6a8aaa",
                                      command=self.save_snapshot)
        self.btn_save.pack(side="left", padx=(6, 2), pady=6)
        self.btn_load = ctk.CTkButton(ctrl_row4, text="📂 讀取", width=70, corner_radius=8,
                                      fg_color="#5a7a9a", hover_color="#6a8aaa",
                                      command=self.load_snapshot)
        self.btn_load.pack(side="left", padx=2, pady=6)
        self.save_file_var = tk.StringVar(value=SAVE_COMBO_EMPTY)
        self.save_combo = ctk.CTkComboBox(ctrl_row4, values=[SAVE_COMBO_EMPTY],
                                          variable=self.save_file_var, state="readonly",
                                          width=170, corner_radius=8,
                                          font=(FONT_LOG, 11))
        self.save_combo.pack(side="left", padx=(6, 2), pady=6)
        # 手動丟檔進 Save/ 的人不必重開程式才看得到
        ctk.CTkButton(ctrl_row4, text="🔄", width=32, corner_radius=8,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      command=self.refresh_save_list).pack(side="left", padx=2, pady=6)

        # 監聽視窗 resize,拖動期間跳過技能排行更新,結束後補刷一次
        root.bind("<Configure>", self._on_root_configure)

        # 若 popout 設定為 True,把對應 pane 移到獨立 Toplevel
        # (順序:先 popout 再 apply_tracking_mode,避免主視窗還 pack 那些 pane)
        # 啟動時主視窗高度已在 geometry() 呼叫時預先扣減,這裡只做 popout 動作
        # 不再走 delta (winfo_height 此時未 realize 會回 1,delta 後會被夾到 200)
        if self.popout_log:
            self._popout_log()
        if self.popout_skill:
            self._popout_skill()

        # 建出初始的目標按鈕列 (此時只有 All);log_pane 已建好,_render_log 可安全呼叫
        self._refresh_target_options()

        # 每 3 秒依累積傷害重排目標按鈕列
        self._tick_target_sort()

        # Buff 倒數重繪的常駐 timer。與「開始/停止」無關 —— buff 是狀態,
        # 沒在收 ADD 就永遠等不到,倒數也不該因為按了停止就停在原地
        self._buff_tick()

        # 依 track_damage / track_heal 旗標,把 banner + pane 一次性 pack 到位
        self._apply_tracking_mode()

        # 掃一次 Save/ 填滿存檔下拉選單 (只讀檔名,不 parse 內容)
        self.refresh_save_list()

        # 開啟後自動在背景掃描一次收包網卡,結果會設到 self.chosen_iface
        # 500ms 延遲讓主視窗先完全渲染出來。
        # macOS 會先確認有沒有 BPF 權限 — 沒有的話掃描每張網卡都只會失敗,
        # 不如先把權限問題解決掉再掃。
        self.root.after(500, self._start_capture_access_flow)

        # 視窗高度要等 CTk 解開它自己的 min/max 鎖才套得上去 (見下方說明)
        self.root.after(200, self._apply_initial_geometry)

    def _apply_initial_geometry(self, tries=6):
        """把 __init__ 設的初始 geometry 補套上去,套不上就每 250ms 再試,最多 6 次。

        為什麼要重試:ctk.set_window_scaling() 會把 wm_minsize/wm_maxsize 暫時鎖在
        「CTk 預設視窗大小」(600x500),1 秒後才由它自己的 after 解開。這段期間送出的
        geometry 會被 WM 夾掉,接著 _refresh_minsize 又把視窗撐到 minsize —— 結果
        不管 initial_h 設多少,啟動高度永遠等於 minsize (實測固定 565)。
        只在「目前比預期矮」時才補,使用者若已自己拉大視窗就不會被縮回去。
        """
        want_h = int(self._initial_geometry.split("x")[1])
        if self.root.winfo_height() >= int(want_h * self.font_scale) - 2:
            return
        self.root.geometry(self._initial_geometry)
        if tries > 0:
            self.root.after(250, lambda: self._apply_initial_geometry(tries - 1))

    # ================================================
    # 事件處理
    # ================================================
    def _on_root_configure(self, event):
        """視窗 resize 事件:拖動中把 _is_resizing 設 True,結束後 150ms 補一次刷新。
        只認 root 自己的 Configure,忽略子元件的冒泡事件。
        """
        if event.widget is not self.root:
            return
        self._is_resizing = True
        if self._resize_after_id is not None:
            try:
                self.root.after_cancel(self._resize_after_id)
            except Exception:
                pass
        self._resize_after_id = self.root.after(150, self._end_resize)

    def _end_resize(self):
        self._is_resizing = False
        self._resize_after_id = None
        # 拖動期間累加的傷害,resize 結束後補一次完整刷新
        self.update_skill_ranking()

    # ================================================
    # 追蹤模式:banner + pane 的統一 pack 管理
    # ================================================
    # ================================================
    # Pane builders (可 pack 於 root 或 Toplevel,支援 dock ↔ popout 切換)
    # ================================================
    def _build_log_pane(self, parent):
        """建立即時攻擊事件日誌 pane。設定 self.log_pane / self.log_area /
        self.btn_log_toggle。呼叫方負責 pack self.log_pane 到適當位置。
        """
        self.log_pane = ctk.CTkFrame(parent, corner_radius=0)
        self.btn_log_toggle = ctk.CTkButton(
            self.log_pane,
            text=("▶ 即時攻擊事件日誌 (已折疊)" if self.log_collapsed
                  else "▼ 即時攻擊事件日誌"),
            font=(FONT_UI, 11),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_log_collapse,
        )
        self.btn_log_toggle.pack(fill="x", padx=6, pady=(6, 0))
        # wrap="none":單筆過長就往右凸出去,不折行。CTkTextbox 的水平捲軸會在
        # 需要時自動出現 (它每 200ms 檢查 xview),不必自己管。
        self.log_area = ctk.CTkTextbox(self.log_pane, wrap="none",
                                        font=(FONT_LOG, 13), corner_radius=0,
                                        height=PANE_CONTENT_MIN_H)
        # 折疊狀態下不 pack log_area,由 toggle_log_collapse 處理
        if not self.log_collapsed:
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_area._textbox.tag_config("highlight", foreground="#ff4d4d")
        # 角色 ID 狀態列:取得後綠字 (未取得走 highlight 紅字)
        self.log_area._textbox.tag_config("ident_ok", foreground="#4dd471")
        # 連攜傷害 (技能是隊友放的,傷害掛在自己身上):黃字
        self.log_area._textbox.tag_config("chain", foreground="#ffcc4d")
        self.log_area._textbox.configure(tabs=self._scaled_tab_stops())
        self.log_area.configure(state="disabled")
        return self.log_pane

    def _build_skill_pane(self, parent):
        """建立技能傷害排行 pane。設定 self.skill_pane / self.btn_skill_toggle /
        self.skill_scroll。self.skill_rows 需被清空並重建 (資料還在 skill_damage 內,
        呼叫 update_skill_ranking 即可補回)。
        """
        self.skill_pane = ctk.CTkFrame(parent, corner_radius=0)
        skill_header = ctk.CTkFrame(self.skill_pane, fg_color="transparent")
        skill_header.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_skill_toggle = ctk.CTkButton(
            skill_header,
            text=("▶ 技能傷害排行 (已折疊)" if self.skill_collapsed
                  else "▼ 技能傷害排行"),
            font=(FONT_UI, 11),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_skill_collapse,
        )
        self.btn_skill_toggle.pack(side="left", fill="x", expand=True)
        # merge_var 已在 __init__ 建立,重建時 checkbox 綁回同一個 var 保留勾選狀態
        ctk.CTkCheckBox(
            skill_header, text="合併同技能", variable=self.merge_var,
            command=self.update_skill_ranking,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 11),
        ).pack(side="right", padx=(6, 4))
        self.skill_scroll = ctk.CTkScrollableFrame(self.skill_pane,
                                                     corner_radius=0,
                                                     fg_color="#242424",
                                                     height=PANE_CONTENT_MIN_H)
        if not self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
        self.skill_pane.bind("<Enter>", self._skill_area_enter)
        self.skill_pane.bind("<Leave>", self._skill_area_leave)
        # 舊 row widgets 已隨舊 pane 銷毀,清空 dict;update_skill_ranking 會依
        # skill_damage 重建列
        self.skill_rows = {}
        return self.skill_pane

    def _build_buff_pane(self, parent):
        """建立「即時 Buff 監測」pane。結構與技能傷害排行同一套(可折疊 + 捲動區),
        差別是列不能展開、進度條是綠色、內容由 _buff_tick 自行倒數。
        """
        self.buff_pane = ctk.CTkFrame(parent, corner_radius=0)
        buff_header = ctk.CTkFrame(self.buff_pane, fg_color="transparent")
        buff_header.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_buff_toggle = ctk.CTkButton(
            buff_header,
            text=("▶ 即時Buff監測 (已折疊)" if self.buff_collapsed
                  else "▼ 即時Buff監測"),
            font=(FONT_UI, 11),
            fg_color="transparent",
            hover_color="#2a2a2a",
            anchor="w",
            corner_radius=6,
            height=26,
            command=self.toggle_buff_collapse,
        )
        self.btn_buff_toggle.pack(side="left", fill="x", expand=True)
        self.buff_scroll = ctk.CTkScrollableFrame(self.buff_pane,
                                                   corner_radius=0,
                                                   fg_color="#242424",
                                                   height=BUFF_SCROLL_H)
        if not self.buff_collapsed:
            self.buff_scroll.pack(fill="both", expand=True, padx=6, pady=6)
        self.buff_rows = {}
        return self.buff_pane

    def toggle_buff_collapse(self):
        """折疊/展開即時 Buff 監測。折疊時 buff_scroll 隱藏但 active_buffs 持續更新。"""
        if self.buff_collapsed:
            self.buff_scroll.pack(fill="both", expand=True, padx=6, pady=6)
            self.btn_buff_toggle.configure(text="▼ 即時Buff監測")
            self.buff_collapsed = False
        else:
            self.buff_scroll.pack_forget()
            self.btn_buff_toggle.configure(text="▶ 即時Buff監測 (已折疊)")
            self.buff_collapsed = True
        self._layout_panes()

    # 三個資訊 pane 共用的 grid uniform 群組名。同群組 + 相同 weight 的 row,
    # Tk grid 保證高度完全相等 —— 這就是「均分」的實作
    _PANE_UNIFORM = "ldm_info_pane"

    def _layout_panes(self):
        """把攻擊日誌 / 技能排行 / Buff 三個 pane 以 grid 排進 pane_container。

        - 未折疊:weight=1 + uniform 群組 → 彼此高度相等;只剩一個展開時它吃滿
        - 已折疊:weight=0 → 只佔標題列高度,所以三個標題永遠看得到
        - popout 出去的 pane 不在 container 內,自然不參與均分
        全部折疊時把 container 改成 expand=False,免得底下留一塊空白。
        """
        container = self.pane_container
        panes = []
        if not self.popout_log:
            panes.append((self.log_pane, self.log_collapsed))
        if not self.popout_skill:
            panes.append((self.skill_pane, self.skill_collapsed))
        panes.append((self.buff_pane, self.buff_collapsed))

        container.grid_columnconfigure(0, weight=1)
        for row in range(3):
            container.grid_rowconfigure(row, weight=0, uniform="")
        any_expanded = False
        for row, (pane, collapsed) in enumerate(panes):
            pane.grid(row=row, column=0, sticky="nsew", pady=(0, 3))
            if not collapsed:
                container.grid_rowconfigure(row, weight=1,
                                            uniform=self._PANE_UNIFORM)
                any_expanded = True
        if container.winfo_manager() == "pack":
            container.pack_configure(expand=any_expanded,
                                     fill="both" if any_expanded else "x")

    # ================================================
    # Popout / dock:攻擊日誌 & 技能排行的獨立視窗切換
    # ================================================
    def _popout_log(self):
        """把 log_pane 從 root 移到獨立 CTkToplevel。
        內容不搬 widget 文字,改由 _render_log() 依 log_entries 重畫 —— 這樣
        紅字高亮與目標篩選都會正確重建。
        """
        if self._log_popout_win is not None:
            return
        if hasattr(self, "log_pane") and self.log_pane:
            self.log_pane.destroy()
        win = ctk.CTkToplevel(self.root)
        win.title("MM Scribe — 即時攻擊事件日誌")
        win.geometry("500x400")
        win.minsize(300, 200)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_popout_closed("log"))
        self._log_popout_win = win
        self._build_log_pane(win)
        self.log_pane.pack(fill="both", expand=True, padx=6, pady=6)
        self._render_log()
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

    def _dock_log(self):
        """把 log_pane 從 Toplevel 收回 root。"""
        if hasattr(self, "log_pane") and self.log_pane:
            self.log_pane.destroy()
        if self._log_popout_win is not None:
            try:
                self._log_popout_win.destroy()
            except Exception:
                pass
            self._log_popout_win = None
        self._build_log_pane(self.pane_container)
        self._render_log()

    def _popout_skill(self):
        """把 skill_pane 從 root 移到獨立 CTkToplevel。
        skill_rows 資料 (skill_damage 等) 都在 self 層,重建 pane 後
        呼叫 update_skill_ranking 即可補回顯示。
        """
        if self._skill_popout_win is not None:
            return
        if hasattr(self, "skill_pane") and self.skill_pane:
            self.skill_pane.destroy()
        win = ctk.CTkToplevel(self.root)
        win.title("MM Scribe — 技能傷害排行")
        win.geometry("500x400")
        win.minsize(300, 200)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_popout_closed("skill"))
        self._skill_popout_win = win
        self._build_skill_pane(win)
        self.skill_pane.pack(fill="both", expand=True, padx=6, pady=6)
        self.update_skill_ranking()  # 重建 row widgets
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

    def _dock_skill(self):
        if hasattr(self, "skill_pane") and self.skill_pane:
            self.skill_pane.destroy()
        if self._skill_popout_win is not None:
            try:
                self._skill_popout_win.destroy()
            except Exception:
                pass
            self._skill_popout_win = None
        self._build_skill_pane(self.pane_container)
        self.update_skill_ranking()

    def _build_dev_pane(self, parent):
        """建立診斷 LOG 面板 (只會被 _popout_dev 呼叫,parent 恆為 Toplevel)。"""
        self.dev_pane = ctk.CTkFrame(parent, corner_radius=0)
        head = ctk.CTkFrame(self.dev_pane, fg_color="transparent")
        head.pack(fill="x", padx=10, pady=(6, 0))
        ctk.CTkLabel(head, text="🛠 診斷 LOG", font=(FONT_UI, 11)).pack(side="left")
        # 分類勾選:取消勾選只是不顯示,緩衝照收 (見 _dev_render_all)
        self._dev_filter_vars = {}
        for key, title, _ in DEV_CATEGORIES:
            var = tk.BooleanVar(value=self._dev_filter.get(key, True))
            self._dev_filter_vars[key] = var
            ctk.CTkCheckBox(head, text=title, variable=var, font=(FONT_UI, 11),
                            checkbox_width=16, checkbox_height=16,
                            command=lambda k=key: self._on_dev_filter_change(k)
                            ).pack(side="left", padx=(12, 0))
        # 診斷行很長 (flags 7 bytes + 技能 + DoT + 候選),用 none 不折行,靠橫向捲軸看完整
        self.dev_log_area = ctk.CTkTextbox(self.dev_pane, wrap="none", font=(FONT_MONO, 12),
                                           corner_radius=0)
        self.dev_log_area.pack(fill="both", expand=True, padx=6, pady=6)
        for tag, color in DEV_TAG_COLORS.items():
            self.dev_log_area._textbox.tag_config(tag, foreground=color)
        self.dev_log_area.configure(state="disabled")

    def _popout_dev(self):
        """點底部區塊 → 彈出完整診斷 LOG 視窗 (內容取自 _dev_lines)。
        已經開著就把它提到最前面,不重複開窗。
        """
        if self._dev_popout_win is not None:
            try:
                self._dev_popout_win.deiconify()
                self._dev_popout_win.lift()
                self._dev_popout_win.focus_force()
            except Exception:
                pass
            return
        win = ctk.CTkToplevel(self.root)
        win.title("MM Scribe — 診斷 LOG")
        # 單行長度約 110 字元,預設開寬一點免得還要手動拉
        win.geometry("820x420")
        win.minsize(400, 200)
        win.protocol("WM_DELETE_WINDOW", lambda: self._on_popout_closed("dev"))
        self._dev_popout_win = win
        self._build_dev_pane(win)
        self.dev_pane.pack(fill="both", expand=True, padx=6, pady=6)
        # 剛開窗時捲到最新一行;之後新訊息不再強拉 (見 dev_log)
        self._dev_render_all(scroll_end=True)
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

    def _dev_visible(self, cat):
        """cat 為 None (不歸類的訊息) 一律顯示。"""
        return cat is None or self._dev_filter.get(cat, True)

    def _dev_render_all(self, scroll_end=False):
        """依目前的分類勾選重畫整個診斷視窗 (內容取自 _dev_lines)。

        scroll_end=False 時維持原本的捲動位置 —— 使用者往上翻看舊訊息時
        切換勾選不該把畫面丟回底部。
        """
        if self.dev_log_area is None:
            return
        rows = [(t, tag) for t, tag, cat in self._dev_lines if self._dev_visible(cat)]
        box = self.dev_log_area._textbox
        top = box.yview()[0]
        self.dev_log_area.configure(state="normal")
        self.dev_log_area.delete("1.0", "end")
        if rows:
            # 一次 insert 全文再用行號補 tag (逐行 insert 數百筆會卡,同 _render_log)
            self.dev_log_area.insert("1.0", "\n".join(t for t, _ in rows) + "\n")
            for row, (_, tag) in enumerate(rows, start=1):
                if tag:
                    box.tag_add(tag, f"{row}.0", f"{row}.end+1c")
        if scroll_end:
            self.dev_log_area.see("end")
        else:
            box.yview_moveto(top)
        self.dev_log_area.configure(state="disabled")

    def _on_dev_filter_change(self, key):
        self._dev_filter[key] = bool(self._dev_filter_vars[key].get())
        self.settings[f"dev_filter_{key}"] = self._dev_filter[key]
        save_settings(self.settings)
        self._dev_render_all()

    def _close_dev_popout(self):
        """關閉診斷視窗。內容在 _dev_lines 裡,重開時原樣還原。"""
        if self._dev_popout_win is not None:
            try:
                self._dev_popout_win.destroy()
            except Exception:
                pass
            self._dev_popout_win = None
        self.dev_pane = None
        self.dev_log_area = None
        # 勾選狀態留在 self._dev_filter,var 跟著 widget 一起丟掉
        self._dev_filter_vars = {}

    def _on_popout_closed(self, kind):
        """使用者點 Toplevel 的 X → 對應 checkbox 取消勾選 → dock 回主視窗。
        dock 回來會增加主視窗高度,和 checkbox 走同一條 delta 調整。
        """
        if kind == "log":
            self.popout_log = False
            self.popout_log_var.set(False)
            self.settings["popout_log"] = False
            save_settings(self.settings)
            self._dock_log()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
            self._apply_tracking_mode()
        elif kind == "skill":
            self.popout_skill = False
            self.popout_skill_var.set(False)
            self.settings["popout_skill"] = False
            save_settings(self.settings)
            self._dock_skill()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
            self._apply_tracking_mode()
        elif kind == "dev":
            # 診斷視窗沒有 dock 回主畫面的形態 — 關掉就好,底部區塊照常收訊息
            self._close_dev_popout()

    # popout 出去時主視窗少一區,縮短高度;dock 回來時補回高度。
    # 200px 是「一個中段 pane 的合理視覺占比」估值,scale 會乘上去。
    _POPOUT_HEIGHT_ESTIMATE = 200

    def _adjust_root_height_delta(self, delta_px):
        """調整主視窗高度 delta 像素;寬度保持不變。
        考慮 font_scale:winfo_height 回實際像素,delta 也乘 scale 轉實際像素,
        傳給 geometry 時再除回 scale (因為 CTk 的 geometry 會再乘一次)。
        floor 340 邏輯像素 * scale = 實際像素,保證兩個 popout 時計時器仍看得到。
        """
        scale = self.font_scale
        curw = self.root.winfo_width()
        curh = self.root.winfo_height()
        floor_real = int(340 * scale)
        new_h = max(floor_real, curh + int(delta_px * scale))
        self.root.geometry(f"{int(curw / scale)}x{int(new_h / scale)}")

    def _on_popout_log_change(self):
        new_state = self.popout_log_var.get()
        if new_state == self.popout_log:
            return
        self.popout_log = new_state
        self.settings["popout_log"] = new_state
        save_settings(self.settings)
        if new_state:
            self._popout_log()
            self._adjust_root_height_delta(-self._POPOUT_HEIGHT_ESTIMATE)
        else:
            self._dock_log()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
        self._apply_tracking_mode()

    def _on_popout_skill_change(self):
        new_state = self.popout_skill_var.get()
        if new_state == self.popout_skill:
            return
        self.popout_skill = new_state
        self.settings["popout_skill"] = new_state
        save_settings(self.settings)
        if new_state:
            self._popout_skill()
            self._adjust_root_height_delta(-self._POPOUT_HEIGHT_ESTIMATE)
        else:
            self._dock_skill()
            self._adjust_root_height_delta(+self._POPOUT_HEIGHT_ESTIMATE)
        self._apply_tracking_mode()

    def _apply_tracking_mode(self):
        """依 self.track_damage / self.track_heal 重新佈局所有可切換的 banner / pane。
        - status_bar 位於視窗最上方 (side=top),不可被壓縮
        - Banner (dmg_banner, heal_banner) 用 `before=ctrl_row1` 插入到控制列上方
        - 三個資訊 pane (log/skill/buff) 一律裝在 pane_container 內,由
          _layout_panes 均分高度;這裡只決定 container 與 heal_log_pane 的 pack
        - 底部診斷區塊不在此處理:它 side="bottom" 常駐,不隨追蹤模式變動
        """
        # === Banners ===
        self.dmg_banner.pack_forget()
        self.heal_banner.pack_forget()
        if self.track_damage:
            self.dmg_banner.pack(fill="x", padx=10, pady=(6, 6),
                                  before=self.ctrl_row1)
        if self.track_heal:
            top_pad = 0 if self.track_damage else 6
            self.heal_banner.pack(fill="x", padx=10, pady=(top_pad, 6),
                                   before=self.ctrl_row1)

        # === 中段 panes ===
        # popout 中的 pane 已 pack 在自己的 Toplevel,主視窗這邊要跳過 (不能對它
        # 呼叫 pack_forget,因為 Toplevel 的 pack 不是 root 管的)
        self.target_row.pack_forget()
        self.pane_container.pack_forget()
        self.heal_log_pane.pack_forget()

        if self.track_damage:
            # 目標篩選同時作用於看板/技能排行/日誌,只要有追蹤傷害就顯示,
            # 不受 popout_log 影響
            self.target_row.pack(fill="x", padx=10, pady=(0, 3))
            self.pane_container.pack(fill="both", expand=True, padx=10, pady=(3, 0))
            self._layout_panes()
        if self.track_heal:
            self.heal_log_pane.pack(fill="both", expand=True, padx=10, pady=(0, 3))
        # 底部診斷區塊不參與這裡的重排 (side="bottom",__init__ 內一次 pack 到底)

        # 依當前佈局重算 minsize,確保 status_bar 不會被 log/skill/heal 這些
        # expand=True 的面板擠掉。用 after(0) 讓 Tk 完成本次 pack 再量高度
        self.root.after(0, self._refresh_minsize)

    def _refresh_minsize(self):
        """依「當前顯示的 banner + 4 條控制列 + status_bar」總高度,
        算出最小視窗高度並套用。
        - winfo_reqheight 回傳實際像素 (含 CTk scaling),要除回 font_scale 變成邏輯像素
        - **必須走 CTk 的 minsize()**,不能用 wm_minsize:CTk 會記住 minsize() 給的值,
          在之後的 scaling / Configure 事件把它重新套一次,直接寫 wm_minsize 會被蓋掉
          (實測:啟動後查到的仍是 __init__ 裡那組 400x180)
        """
        self.root.update_idletasks()
        parts = [self.ctrl_row1, self.ctrl_row2, self.ctrl_row3, self.ctrl_row4,
                 self.status_bar]
        # 底部診斷區塊是常駐的 (發布版除外),最小高度要把它算進去
        if self.dev_strip.winfo_manager():
            parts.append(self.dev_strip)
        if self.track_damage:
            parts.append(self.dmg_banner)
            parts.append(self.target_row)
            # 三個資訊 pane 都會伸縮,最小高度只算它們的標題列 —— 標題必須永遠
            # 看得到 (內容區的最小高度由下面那 80px slack 涵蓋)
            if not self.popout_log:
                parts.append(self.btn_log_toggle)
            if not self.popout_skill:
                parts.append(self.btn_skill_toggle)
            parts.append(self.btn_buff_toggle)
        if self.track_heal:
            parts.append(self.heal_banner)
        req_h = sum(w.winfo_reqheight() for w in parts)
        # 再留 80px 給日誌區最小可視高度 + padding,不然 status_bar 剛好貼滿反而擠日誌
        min_h = (req_h + 80) / max(self.font_scale, 0.1)
        self.root.minsize(400, int(min_h))

    def _on_track_damage_change(self):
        self.track_damage = self.track_damage_var.get()
        self.settings["track_damage"] = self.track_damage
        save_settings(self.settings)
        self._apply_tracking_mode()

    def _on_track_heal_change(self):
        self.track_heal = self.track_heal_var.get()
        self.settings["track_heal"] = self.track_heal
        save_settings(self.settings)
        self._apply_tracking_mode()

    def _on_detect_chain_change(self):
        """連攜攻擊偵測開關。只影響之後收到的封包,不重算已累積的統計 ——
        中途切換會讓同一場的資料前後定義不一致,要乾淨就按「清除」重來。"""
        self.detect_chain = self.detect_chain_var.get()
        self.settings["detect_chain"] = self.detect_chain
        save_settings(self.settings)

    def toggle_heal_collapse(self):
        """折疊/展開治癒事件日誌。折疊時 heal_log_area 隱藏但持續寫入。"""
        if self.heal_collapsed:
            self.heal_log_area.pack(fill="both", expand=True, padx=6, pady=6)
            self.heal_log_pane.pack_configure(expand=True, fill="both")
            self.btn_heal_toggle.configure(text="▼ 治癒事件日誌")
            self.heal_collapsed = False
        else:
            self.heal_log_area.pack_forget()
            self.heal_log_pane.pack_configure(expand=False, fill="x")
            self.btn_heal_toggle.configure(text="▶ 治癒事件日誌 (已折疊)")
            self.heal_collapsed = True

    def open_discord(self):
        """開啟預設瀏覽器前往 Discord 邀請連結。"""
        try:
            webbrowser.open(DISCORD_INVITE_URL)
        except Exception as e:
            self.log(f"❌ 無法開啟 Discord 連結: {e}")

    def show_network_check(self):
        """建立網路環境檢測覆蓋層,列出各項診斷結果讓使用者判斷抓不到封包的原因。"""
        if getattr(self, "_netcheck_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._netcheck_overlay = overlay

        # 標題 + 按鈕列
        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="🌐 網路環境檢測",
                     font=(FONT_UI, 16),
                     text_color="#4dccff").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_LOG, 14),
                      command=self.hide_network_check).pack(side="right", padx=6)
        ctk.CTkButton(header, text="🔄 重新檢測", width=100, height=32,
                      corner_radius=8,
                      command=lambda: self._run_network_checks()).pack(side="right", padx=6)
        self._btn_scan_iface = ctk.CTkButton(
            header, text="🔍 掃描收包網卡", width=140, height=32, corner_radius=8,
            command=self._start_iface_scan,
        )
        self._btn_scan_iface.pack(side="right", padx=6)

        # 結果顯示區
        self._netcheck_result = ctk.CTkTextbox(overlay, wrap="word",
                                                font=(FONT_LOG, 11),
                                                corner_radius=0,
                                                fg_color="#1a1a1a")
        self._netcheck_result.pack(fill="both", expand=True, padx=16, pady=12)

        # 狀態顏色
        self._netcheck_result._textbox.tag_config("tag_ok", foreground="#4dd471")
        self._netcheck_result._textbox.tag_config("tag_warn", foreground="#ffcc4d")
        self._netcheck_result._textbox.tag_config("tag_fail", foreground="#ff5555")
        self._netcheck_result._textbox.tag_config("tag_info", foreground="#4dccff")
        self._netcheck_result._textbox.tag_config("tag_active", foreground="#66ffa0")
        self._netcheck_result._textbox.tag_config("tag_header",
                                                   foreground="#ffffff",
                                                   font=(FONT_UI, 12))

        self._run_network_checks()

    def hide_network_check(self):
        overlay = getattr(self, "_netcheck_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._netcheck_overlay = None
        self._netcheck_result = None

    def _append_netcheck(self, status, title, *details):
        """在檢測結果區加一段訊息 (執行在 main thread)。"""
        area = getattr(self, "_netcheck_result", None)
        if area is None:
            return
        icon = {"ok": "✓", "warn": "⚠", "fail": "✗",
                "info": "ℹ", "active": "⭐"}.get(status, "•")
        area.configure(state="normal")
        area._textbox.insert("end", f"[{icon}] {title}\n", f"tag_{status}")
        for d in details:
            area._textbox.insert("end", f"    {d}\n")
        area._textbox.insert("end", "\n")
        area._textbox.see("end")
        area.configure(state="disabled")

    # ---- 收包網卡掃描:核心邏輯,供啟動時自動偵測與手動按鈕共用 ----
    def _scan_ifaces_for_traffic(self, per_iface_timeout, on_progress, on_done):
        """對每張有 IPv4 的介面短暫 sniff,回報收到多少目標封包。
        - per_iface_timeout: 每張介面掃多久 (秒)
        - on_progress(status, title, *details): 每張介面掃完 & 開始時的即時回報
        - on_done(best_iface_dict or None, hits_list): 全部掃完時的最終回呼
        本函式會在自己的背景 thread 執行,呼叫方不需自己開 thread。
        """
        def _worker():
            try:
                from scapy.all import sniff as _sniff

                def _extract_ipv4(raw):
                    out = []
                    if isinstance(raw, dict):
                        for iplist in raw.values():
                            if isinstance(iplist, (list, tuple)):
                                out.extend(iplist)
                    elif isinstance(raw, (list, tuple)):
                        out = list(raw)
                    return [str(ip) for ip in out
                            if ":" not in str(ip)
                            and str(ip) != "0.0.0.0"
                            and not str(ip).startswith("169.254.")]

                # ── 代理模式:加速器把遊戲連線接到本機端口時,43/8 流量在任何
                # 網卡上都不存在,唯一看得到的位置是 Loopback 上的往返流量 ──
                proxy = detect_local_game_proxy(self.settings.get("game_processes"))
                if proxy:
                    ports, pdesc = proxy
                    port_str = ", ".join(str(p) for p in sorted(ports))
                    flt = ("tcp and ("
                           + " or ".join(f"port {p}" for p in sorted(ports)) + ")")
                    lo = find_loopback_iface()
                    if lo is None:
                        self.root.after(0, lambda d=pdesc: on_progress(
                            "warn", f"偵測到本機網路代理 ({d}),但找不到 Loopback 擷取介面",
                            "請重新安裝 Npcap 並勾選「Support loopback traffic」",
                            "先改用一般網卡掃描"))
                    else:
                        lo_name = str(lo.get("description") or lo.get("name") or "Loopback")
                        # 用 active 而非 info:這是要讓使用者看到的狀態切換,
                        # info 會被啟動流程的日誌過濾當成逐張網卡的細節擋掉
                        self.root.after(0, lambda d=pdesc, p=port_str: on_progress(
                            "active", f"偵測到本機網路代理 ({d})",
                            f"遊戲連線被接到本機 port {p},改掃 Loopback"))
                        count = 0
                        try:
                            # loopback 上的遊戲封包比實體網卡稀疏 (只有真的在傳資料
                            # 才有),掃太短容易誤判成沒有
                            count = len(_sniff(iface=lo.get("name"), filter=flt,
                                               timeout=max(per_iface_timeout, 3),
                                               store=True))
                        except Exception as e:
                            self.root.after(0, lambda n=lo_name, err=e: on_progress(
                                "warn", f"{n}", f"sniff 失敗: {err}"))
                        if count > 0:
                            chosen = dict(lo)
                            chosen["description"] = (
                                f"Loopback 代理模式 — {pdesc} (port {port_str})")
                            chosen["_filter"] = flt
                            self.root.after(0, lambda d=chosen["description"], c=count:
                                            on_progress("ok", f"✓ {d}",
                                                        f"收到 {c} 個目標封包"))
                            self.root.after(0, lambda c=chosen, cnt=count: on_done(
                                c, [(c, cnt, c["description"])]))
                            return
                        self.root.after(0, lambda: on_progress(
                            "warn", "Loopback 沒收到遊戲封包", "改用一般網卡掃描"))

                try:
                    raw_ifs = list_network_ifaces()
                except Exception as e:
                    self.root.after(0, lambda err=e: on_progress(
                        "warn", f"無法列出介面: {err}"))
                    self.root.after(0, lambda: on_done(None, []))
                    return

                ifs = [i for i in raw_ifs if _extract_ipv4(i.get("ips"))]
                ifs = [i for i in ifs if not _is_never_game_traffic(i.get("name"))]
                if not ifs:
                    self.root.after(0, lambda: on_progress(
                        "warn", "沒有可掃描的介面 (無介面有有效 IPv4)"))
                    self.root.after(0, lambda: on_done(None, []))
                    return

                # 預設路由那張排最前面:絕大多數情況遊戲就走這張,先掃到就能提早收工
                preferred = default_route_iface()
                ifs.sort(key=lambda i: i.get("name") != preferred)

                total_time = len(ifs) * per_iface_timeout
                self.root.after(0, lambda: on_progress(
                    "info", f"開始掃描 {len(ifs)} 張介面,每張測 {per_iface_timeout} 秒 (最多約 {total_time} 秒)"))

                hits = []
                for iface in ifs:
                    name = str(iface.get("description") or iface.get("name") or "?")
                    iface_key = iface.get("name")
                    try:
                        pkts = _sniff(iface=iface_key, filter=DEFAULT_BPF_FILTER,
                                      timeout=per_iface_timeout, store=True)
                        count = len(pkts)
                    except Exception as e:
                        self.root.after(0, lambda n=name, err=e: on_progress(
                            "warn", f"{n}", f"sniff 失敗: {err}"))
                        continue

                    if count > 0:
                        hits.append((iface, count, name))
                        self.root.after(0, lambda n=name, c=count: on_progress(
                            "ok", f"✓ {n}", f"收到 {c} 個目標封包"))
                        # 預設路由那張已經收到流量就不必再試其他張,省下數十秒
                        # (macOS 上虛擬介面動輒十幾張,全掃完使用者早就等到不耐煩)
                        if iface_key == preferred:
                            break
                    else:
                        self.root.after(0, lambda n=name: on_progress(
                            "info", f"  {n}", "沒收到"))

                if not hits:
                    self.root.after(0, lambda: on_done(None, []))
                else:
                    best = max(hits, key=lambda x: x[1])
                    self.root.after(0, lambda b=best: on_done(b[0], hits))
            except Exception as e:
                self.root.after(0, lambda err=e: on_progress(
                    "warn", f"掃描發生錯誤: {err}"))
                self.root.after(0, lambda: on_done(None, []))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_chosen_iface(self, iface_dict):
        """把掃描結果套用到 self.chosen_iface / self.sniff_filter,
        之後 sniff() 就會用這組網卡與過濾條件。"""
        prev = (self.chosen_iface, self.sniff_filter)
        self.chosen_iface = None if iface_dict is None else iface_dict.get("name")
        # 代理模式的掃描結果會多帶一個 _filter (掃 loopback 上的代理端口)
        self.sniff_filter = (iface_dict or {}).get("_filter") or DEFAULT_BPF_FILTER
        # 攔截執行緒是常駐的 (見 _ensure_sniffer),換卡或換過濾條件都要重開一條
        if (self.chosen_iface, self.sniff_filter) != prev:
            self._ensure_sniffer(restart=True)

    # ================================================
    # macOS: BPF 權限引導
    #   /dev/bpf* 預設是 root:wheel 0600,不提權就抓不到封包。
    #   .app 又沒有「以管理員身分執行」這種選項,所以第一次啟動時直接在
    #   程式裡引導使用者做一次性設定,之後就不必再輸入密碼。
    # ================================================
    def _start_capture_access_flow(self):
        """啟動流程第一步:確認抓包權限,不足時引導設定。
        非 macOS、或已經有權限 (含以 sudo 執行),就直接進入網卡自動偵測。
        """
        if not IS_MACOS:
            self._auto_detect_iface_on_startup()
            return
        ok, _ = check_capture_permission()
        if ok:
            self._auto_detect_iface_on_startup()
            return
        self._show_bpf_access_dialog()

    def _bpf_helper_script_path(self):
        """找出 macos-bpf-access.sh:打包版在 bundle 內,原始碼版在專案根目錄。"""
        path = get_resource_path(BPF_HELPER_NAME)
        if os.path.exists(path):
            return path
        alt = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), BPF_HELPER_NAME)
        return alt if os.path.exists(alt) else None

    def _show_bpf_access_dialog(self):
        """說明清楚要改什麼、有什麼代價,再讓使用者決定。"""
        win = ctk.CTkToplevel(self.root)
        win.title("需要封包擷取權限")
        win.geometry("500x430")
        win.resizable(False, False)
        win.transient(self.root)
        # macOS 的 CTkToplevel 要延遲一下才吃得到 lift/grab,否則會躲到主視窗後面
        win.after(150, lambda: (win.lift(), win.focus_force(), win.grab_set()))
        self._bpf_dialog = win

        ctk.CTkLabel(win, text="需要封包擷取權限",
                     font=(FONT_UI, 16)).pack(pady=(18, 6))

        body = (
            "MM Scribe 需要讀取網路封包才能統計傷害,但 macOS 預設只允許\n"
            "管理員存取封包擷取裝置 (/dev/bpf*),因此每次都得用 sudo 從\n"
            "終端機啟動。\n\n"
            "可以做一次性設定,之後直接點開就能用:\n\n"
            "  1. 建立 access_bpf 群組,並把你的帳號加入\n"
            "  2. 安裝一個開機執行的背景項目,把擷取裝置交給該群組\n\n"
            "這與 Wireshark 的 ChmodBPF 是同一套做法,兩者可並存。"
        )
        ctk.CTkLabel(win, text=body, font=(FONT_UI, 12),
                     justify="left").pack(padx=24, anchor="w")

        warn = ("⚠ 設定後,該群組的成員不需要密碼就能監聽這台電腦上的\n"
                "   所有網路流量。不想長期開著,隨時可以還原。")
        ctk.CTkLabel(win, text=warn, font=(FONT_UI, 11),
                     text_color="#ff9944", justify="left").pack(padx=24, pady=(12, 0), anchor="w")

        self._bpf_status_label = ctk.CTkLabel(win, text="", font=(FONT_UI, 11),
                                              text_color="#9ad", wraplength=440, justify="left")
        self._bpf_status_label.pack(padx=24, pady=(10, 0), anchor="w")

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=16)

        script = self._bpf_helper_script_path()
        self._bpf_setup_btn = ctk.CTkButton(
            btn_row, text="設定 (需要輸入密碼)", width=190,
            font=(FONT_UI, 12), command=self._run_bpf_setup)
        self._bpf_setup_btn.pack(side="left", padx=6)
        if script is None:
            # 找不到腳本就別給一個按了會失敗的按鈕
            self._bpf_setup_btn.configure(state="disabled")
            self._bpf_status_label.configure(
                text=f"找不到 {BPF_HELPER_NAME},請改用 sudo 啟動,或從專案目錄執行該腳本。",
                text_color="#ff6666")

        ctk.CTkButton(btn_row, text="稍後再說", width=120,
                      font=(FONT_UI, 12), fg_color="#555", hover_color="#666",
                      command=self._skip_bpf_setup).pack(side="left", padx=6)

    def _skip_bpf_setup(self):
        """略過設定:照樣進入偵測流程,讓日誌把失敗原因寫出來。"""
        try:
            self._bpf_dialog.grab_release()
            self._bpf_dialog.destroy()
        except Exception:
            pass
        self.log("=== 未設定抓包權限,請改以 sudo 啟動,否則收不到封包 ===")
        self._auto_detect_iface_on_startup()

    def _run_bpf_setup(self):
        """以系統授權對話框提權執行設定腳本 (背景執行,不凍結 UI)。"""
        import shlex
        import subprocess

        script = self._bpf_helper_script_path()
        if script is None:
            return

        self._bpf_setup_btn.configure(state="disabled")
        self._bpf_status_label.configure(
            text="等待授權中 — 請在系統跳出的對話框輸入密碼...", text_color="#9ad")

        user = os.environ.get("USER") or ""

        def _worker():
            # 腳本用 /bin/bash 呼叫,不依賴檔案的執行權限 —
            # PyInstaller 打包的 data file 不保證會保留 +x
            inner = f"/bin/bash {shlex.quote(script)} install --yes"
            if user:
                inner += f" --user {shlex.quote(user)}"
            # 內容要嵌進 AppleScript 的字串裡,反斜線與雙引號都得跳脫
            esc = inner.replace("\\", "\\\\").replace('"', '\\"')
            osa = f'do shell script "{esc}" with administrator privileges'
            try:
                proc = subprocess.run(["osascript", "-e", osa],
                                      capture_output=True, text=True, timeout=180)
                rc, err = proc.returncode, (proc.stderr or "").strip()
            except Exception as e:
                rc, err = -1, str(e)
            self.root.after(0, lambda: self._on_bpf_setup_done(rc, err))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_bpf_setup_done(self, rc, err):
        if rc != 0:
            # osascript 在使用者按取消時回報 -128
            cancelled = "-128" in err or "User canceled" in err
            self._bpf_status_label.configure(
                text="已取消授權。" if cancelled else f"設定失敗:{err[:150]}",
                text_color="#ff9944" if cancelled else "#ff6666")
            self._bpf_setup_btn.configure(state="normal")
            return

        ok, detail = check_capture_permission()
        if ok:
            try:
                self._bpf_dialog.grab_release()
                self._bpf_dialog.destroy()
            except Exception:
                pass
            self.log("=== 抓包權限設定完成,之後啟動不需要再輸入密碼 ===")
            self._auto_detect_iface_on_startup()
            return

        # 群組成員資格要新的 process 才會生效,這種情況重開程式即可
        self._bpf_status_label.configure(
            text="設定已完成,但這個程式的執行階段還沒取得新的群組身分。\n"
                 "請關閉並重新開啟 MM Scribe。",
            text_color="#ff9944")
        self._bpf_setup_btn.configure(state="disabled")

    def _auto_detect_iface_on_startup(self):
        """程式開啟時的自動偵測 (背景執行,不阻擋 UI)。
        結果會設到 self.chosen_iface,後續按「開始」時 sniff 會用這張卡。
        """
        self.log("=== 自動偵測收包網卡中... (背景執行,可正常操作) ===")
        # 角色身分偵測不等「開始」— 先用 scapy 預設卡把攔截跑起來,
        # 偵測完成後 _apply_chosen_iface 會重開一條綁到選定的網卡
        self._ensure_sniffer()
        self._ident_status_line()
        self.dev_log_startup_hints()

        def on_progress(status, title, *details):
            # 僅把有意義的訊息推到主日誌 (略過每張介面的細節,避免刷屏)
            if status in ("ok", "warn", "active"):
                self.log(f"  {title}")

        def on_done(best_iface, hits):
            if best_iface is None:
                self.log("=== 無法獲取遊戲封包,可能是使用加速器/VPN等網路代理 ===")
                self.log("    將先使用 scapy 預設介面")
                self.log("    若監控後仍抓不到,請按「網路檢測 → 掃描收包網卡」重試")
            else:
                self._apply_chosen_iface(best_iface)
                name = str(best_iface.get("description") or best_iface.get("name") or "?")
                self.log(f"=== 已自動選定收包網卡:{name} ===")

        self._scan_ifaces_for_traffic(
            per_iface_timeout=2,
            on_progress=on_progress,
            on_done=on_done,
        )

    def _start_iface_scan(self):
        """網路檢測畫面的「掃描收包網卡」按鈕:掃描並套用結果。"""
        if getattr(self, "_iface_scan_running", False):
            return
        self._iface_scan_running = True
        self._btn_scan_iface.configure(state="disabled", text="🔍 掃描中...")

        def on_progress(status, title, *details):
            self._append_netcheck(status, title, *details)

        def on_done(best_iface, hits):
            if best_iface is None:
                self._append_netcheck(
                    "warn", "無法獲取遊戲封包,可能是使用加速器/VPN等網路代理",
                    "可能原因:",
                    "  1. 加速器/VPN 接管了遊戲連線 → 請先關閉後重試",
                    "  2. 遊戲未連線 / 未啟動",
                    "  3. 目標伺服器不在監控範圍內",
                    "  4. 沒有以系統管理員身分執行 → sniff 靜默失敗",
                    "  5. 防毒/防火牆阻擋")
            else:
                self._apply_chosen_iface(best_iface)
                name = str(best_iface.get("description") or best_iface.get("name") or "?")
                count = max(h[1] for h in hits)
                self._append_netcheck(
                    "active", f"掃描結束:已套用「{name}」為抓包網卡",
                    f"收到 {count} 個目標封包 (最多)",
                    "下次按「開始」時會綁這張卡進行 sniff")
            self._iface_scan_running = False
            try:
                self._btn_scan_iface.configure(state="normal", text="🔍 掃描收包網卡")
            except Exception:
                pass

        self._scan_ifaces_for_traffic(
            per_iface_timeout=2,
            on_progress=on_progress,
            on_done=on_done,
        )

    def _run_network_checks(self):
        """執行所有網路環境檢測項目並輸出結果。"""
        area = self._netcheck_result
        area.configure(state="normal")
        area.delete("1.0", "end")

        def write(status, title, *details):
            icon = {"ok": "✓", "warn": "⚠", "fail": "✗", "info": "ℹ", "active": "⭐"}.get(status, "•")
            area._textbox.insert("end", f"[{icon}] {title}\n", f"tag_{status}")
            for d in details:
                area._textbox.insert("end", f"    {d}\n")
            area._textbox.insert("end", "\n")

        def section(title):
            area._textbox.insert("end", f"── {title} ──\n\n", "tag_header")

        # === 1. 抓包權限 ===
        section("1. 執行權限")
        perm_ok, perm_detail = check_capture_permission()
        if perm_ok:
            write("ok", "已具備抓包權限", perm_detail)
        else:
            write("fail", "權限不足",
                  "★ 這是抓不到封包最常見的原因 ★",
                  perm_detail)

        # === 2. 抓包驅動 ===
        driver_name = "Npcap 驅動" if IS_WINDOWS else "libpcap / BPF"
        section(f"2. {driver_name}")
        backend_ok, backend_hint = check_capture_backend()
        if backend_ok:
            write("ok", f"{driver_name} 已就緒",
                  *([] if IS_WINDOWS else ["libpcap 為 macOS 內建,無須另外安裝"]))
        else:
            write("fail", f"未偵測到 {driver_name}", backend_hint)

        # ── 共用工具 ──
        def extract_ipv4_list(raw):
            """相容 scapy 各版本的 .ips 型別 → 回傳 IPv4 字串列表。"""
            out = []
            if isinstance(raw, dict):
                for iplist in raw.values():
                    if isinstance(iplist, (list, tuple)):
                        out.extend(iplist)
                    elif iplist:
                        out.append(iplist)
            elif isinstance(raw, (list, tuple)):
                out = list(raw)
            return [str(ip) for ip in out if ":" not in str(ip)]

        def has_usable_ipv4(iface):
            """有沒有真正能用的 IPv4:非空、非 0.0.0.0、非 APIPA (169.254.x.x)。"""
            for ip in extract_ipv4_list(iface.get("ips")):
                if ip and ip != "0.0.0.0" and not ip.startswith("169.254."):
                    return True
            return False

        # ── 先偵測 scapy 目前用哪張卡 (兩處都會用到) ──
        active_iface_str = ""
        active_guid = ""
        active_name = ""
        try:
            from scapy.config import conf
            active_iface = conf.iface
            active_iface_str = str(active_iface)
            v = getattr(active_iface, "guid", None)
            if v:
                active_guid = str(v)
            for attr in ("description", "network_name", "name"):
                v = getattr(active_iface, attr, None)
                if v and not active_name:
                    active_name = str(v)
        except Exception:
            pass

        def is_active_iface(iface):
            guid = str(iface.get("guid") or "")
            name = str(iface.get("name") or "")
            desc = str(iface.get("description") or "")
            if guid and (guid in active_iface_str or guid == active_guid):
                return True
            if name and (name == active_iface_str or name == active_name):
                return True
            if desc and desc == active_name:
                return True
            return False

        # === 3. 網路介面 ===
        section("3. 網路介面偵測 (已過濾無 IPv4 的介面)")
        try:
            ifs = list_network_ifaces()
            if not ifs:
                write("warn", "沒有找到任何網路介面")
            else:
                usable = [i for i in ifs if has_usable_ipv4(i)]
                skipped = len(ifs) - len(usable)
                write("info",
                      f"共 {len(ifs)} 個介面,顯示 {len(usable)} 個有 IPv4 的 (排除 {skipped} 個)")
                for i in usable:
                    name = str(i.get("name", "?"))
                    desc = str(i.get("description", ""))
                    ipv4 = extract_ipv4_list(i.get("ips"))
                    ip_str = ", ".join(ipv4) if ipv4 else "(無 IPv4)"

                    # macOS 的 description 就是 BSD 名稱,所以連 name 一起比對:
                    # utun=VPN, bridge/vmenet=虛擬機橋接, awdl/llw=AirDrop, feth/gif/stf=虛擬
                    lower_desc = (desc + " " + name).lower()
                    tag = ""
                    if any(kw in lower_desc for kw in
                           ["virtual", "vmware", "vbox", "hyper-v", "tap", "tun",
                            "wireguard", "wsl", "loopback",
                            "utun", "bridge", "vmenet", "awdl", "llw", "feth",
                            "gif", "stf", "anpi", "lo0"]):
                        tag = " ⚠虛擬/VPN"

                    if is_active_iface(i):
                        write("active", f"{desc or name}{tag}  ← scapy 目前用這張",
                              f"IPv4: {ip_str}",
                              f"裝置名稱: {name}")
                    else:
                        write("info", f"{desc or name}{tag}",
                              f"IPv4: {ip_str}")
        except Exception as e:
            write("warn", f"無法列出介面: {type(e).__name__}: {e}")

        # === 4. scapy 目前綁定的介面 ===
        section("4. scapy 目前綁定介面")
        try:
            friendly = active_name
            desc = ""
            ipv4 = extract_ipv4_list(getattr(active_iface, "ips", None)) if active_iface_str else []

            # 沒抓到就從介面清單反查
            if active_iface_str and (not friendly or not ipv4):
                for iface in list_network_ifaces():
                    if is_active_iface(iface):
                        if not friendly:
                            friendly = str(iface.get("description") or iface.get("name") or "")
                        if not desc:
                            desc = str(iface.get("description") or "")
                        if not ipv4:
                            ipv4 = extract_ipv4_list(iface.get("ips"))
                        break

            if not active_iface_str:
                write("warn", "無法取得 scapy 預設介面")
            else:
                details = []
                if friendly:
                    details.append(f"友善名稱: {friendly}")
                if desc and desc != friendly:
                    details.append(f"描述: {desc}")
                if ipv4:
                    details.append(f"IPv4: {', '.join(ipv4)}")
                details.append(f"裝置路徑: {active_iface_str}")
                details.append("---")
                details.append("sniff() 若沒特別指定 iface,就是抓這張卡")
                details.append("若這張卡不是你連遊戲用的那張,就永遠抓不到")
                write("active", "scapy 現在綁的網卡:", *details)
        except Exception as e:
            write("warn", f"取得預設介面失敗: {type(e).__name__}: {e}")

        area.configure(state="disabled")

    def show_disclaimer(self):
        """建立一個覆蓋整個視窗的免責聲明畫面。已顯示時不重複建立。"""
        if getattr(self, "_disclaimer_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._disclaimer_overlay = overlay

        # 標題列 + 關閉按鈕
        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="⚠ 免責聲明",
                     font=(FONT_UI, 16),
                     text_color="#ff9944").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_LOG, 14),
                      command=self.hide_disclaimer).pack(side="right", padx=6)

        # 內文區
        content = (
            "【 MM Scribe 使用免責聲明 】\n\n"
            "一、本工具由社群個人開發,與任何遊戲廠商、發行商並無合作、\n"
            "    授權或關聯關係,亦非任何官方認可之工具。\n\n"
            "二、本工具僅供個人學習研究與傷害分析用途,\n"
            "    請勿用於任何商業行為或不當競技目的。\n\n"
            "三、透過網路封包擷取遊戲資訊,可能違反相關遊戲之服務條款。\n"
            "    使用者需自行評估風險與後果,包含但不限於\n"
            "    帳號警告、停權或永久封鎖。\n\n"
            "四、本工具僅在本機端解析封包內容,\n"
            "    不會蒐集、儲存或傳送任何個人資料至外部伺服器。\n\n"
            "五、開發者不對使用本工具所產生之任何直接或間接損失\n"
            "    負任何法律或道義責任。\n\n"
            "六、使用本工具即視為您已閱讀並同意上述所有條款。\n"
            "    若不同意,請立即停止使用並刪除本程式。\n"
        )
        textbox = ctk.CTkTextbox(overlay, wrap="word",
                                 font=(FONT_UI, 12),
                                 corner_radius=8, fg_color="#1a1a1a")
        textbox.pack(fill="both", expand=True, padx=16, pady=12)
        textbox.insert("end", content)
        textbox.configure(state="disabled")

    def hide_disclaimer(self):
        overlay = getattr(self, "_disclaimer_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._disclaimer_overlay = None

    # ---- 設定畫面 ----
    def _scaled_tab_stops(self):
        """依實際字體量測算出三個欄位停靠點,再乘 font_scale 換成像素。
        量測固定在基準字級做 — CTk 的字體也是乘同一個 font_scale,兩者等比。

        第一個停靠點帶 "right":傷害欄靠它右對齊,不靠空白補齊,
        所以 FONT_LOG 是不是等寬字都無所謂 (微軟正黑體的空白只有數字的一半寬,
        用補空白的舊做法會歪掉)。
        """
        if self._log_font is None:
            self._log_font = tkfont.Font(family=FONT_LOG, size=13)
        measure = self._log_font.measure
        # 傷害欄:右緣落在 LOG_DMG_WIDTH 個數字寬的位置
        stop0 = measure("9" * LOG_DMG_WIDTH)
        # 標籤欄:貼著傷害欄右緣,只留 LOG_DMG_GAP
        stop1 = stop0 + LOG_DMG_GAP
        # 技能名欄:仍以傷害取樣字串為基準,不受上面縮排影響 (位置固定)
        stop2 = measure(LOG_DMG_SAMPLE) + measure(LOG_TAG_SAMPLE) + LOG_COL_GAP * 2
        px = [str(int(v * self.font_scale)) for v in (stop0, stop1, stop2)]
        return (px[0], "right", px[1], "left", px[2], "left")

    def show_settings(self):
        """建立覆蓋整個視窗的設定畫面。已顯示時不重複建立。"""
        if getattr(self, "_settings_overlay", None) is not None:
            return

        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._settings_overlay = overlay

        header = ctk.CTkFrame(overlay, fg_color="transparent", height=44)
        header.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(header, text="⚙ 設定",
                     font=(FONT_UI, 16),
                     text_color="#88ccff").pack(side="left", padx=6)
        ctk.CTkButton(header, text="✕", width=32, height=32, corner_radius=16,
                      fg_color="#3a3a3a", hover_color="#c94a4a",
                      font=(FONT_LOG, 14),
                      command=self.hide_settings).pack(side="right", padx=6)

        # 用 ScrollableFrame,視窗過矮時內容自動可捲 (原本用 CTkFrame 會被截掉)
        body = ctk.CTkScrollableFrame(overlay, fg_color="#1a1a1a", corner_radius=8)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        # ── 「顯示」區塊 ──
        section = ctk.CTkFrame(body, fg_color="transparent")
        section.pack(fill="x", padx=12, pady=(12, 4))
        ctk.CTkLabel(section, text="── 顯示 ──",
                     font=(FONT_UI, 12),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        # 字體縮放列
        scale_row = ctk.CTkFrame(section, fg_color="transparent")
        scale_row.pack(fill="x", pady=4)
        ctk.CTkLabel(scale_row, text="字體縮放:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        # 顯示當前倍率的 Entry (唯讀,只當顯示用) + 右側 ▲▼ 兩顆微型按鈕
        # 每次 ▲ / ▼ 步進 0.1,夾在 FONT_SCALE_MIN ~ FONT_SCALE_MAX 之間
        self._scale_entry = ctk.CTkEntry(
            scale_row, width=64, justify="center",
            font=(FONT_LOG, 13), corner_radius=6,
        )
        self._scale_entry.insert(0, f"{self.font_scale:.1f}x")
        self._scale_entry.configure(state="readonly")
        self._scale_entry.pack(side="left", padx=(0, 2))

        step_col = ctk.CTkFrame(scale_row, fg_color="transparent")
        step_col.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            step_col, text="▲", width=22, height=14, corner_radius=3,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=(FONT_LOG, 9),
            command=lambda: self._step_scale(0.1),
        ).pack(pady=(0, 1))
        ctk.CTkButton(
            step_col, text="▼", width=22, height=14, corner_radius=3,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=(FONT_LOG, 9),
            command=lambda: self._step_scale(-0.1),
        ).pack()

        ctk.CTkButton(
            scale_row, text="🔄", width=32, corner_radius=6,
            fg_color="#4a4a4a", hover_color="#6a6a6a",
            font=("Segoe UI Emoji", 13),
            command=self._reset_scale,
        ).pack(side="left", padx=(0, 8))

        # 提示:視窗尺寸不會自動跟著縮放,由使用者手動調整
        ctk.CTkLabel(section,
                     text="※ 縮放後如視窗過小,請手動拖曳邊緣調整尺寸",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w").pack(fill="x", pady=(8, 0))

        # 獨立視窗 (popout) 選項
        popout_row = ctk.CTkFrame(section, fg_color="transparent")
        popout_row.pack(fill="x", pady=(10, 0))
        ctk.CTkLabel(popout_row, text="獨立視窗:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        ctk.CTkCheckBox(
            popout_row, text="攻擊事件日誌",
            variable=self.popout_log_var,
            command=self._on_popout_log_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(side="left", padx=(0, 12))
        ctk.CTkCheckBox(
            popout_row, text="技能傷害排行",
            variable=self.popout_skill_var,
            command=self._on_popout_skill_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(section,
                     text="※ 勾選後日誌會以獨立視窗開啟;直接關閉獨立視窗會自動收回主視窗",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w").pack(fill="x", pady=(4, 0))

        # ── 「追蹤」區塊 ──
        track_section = ctk.CTkFrame(body, fg_color="transparent")
        track_section.pack(fill="x", padx=12, pady=(16, 4))
        ctk.CTkLabel(track_section, text="── 追蹤 ──",
                     font=(FONT_UI, 12),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        ctk.CTkCheckBox(
            track_section,
            text="攻擊數值  (顯示攻擊事件日誌、技能傷害排名、傷害/DPS/覆蓋率)",
            variable=self.track_damage_var,
            command=self._on_track_damage_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(anchor="w", pady=4)

        ctk.CTkCheckBox(
            track_section,
            text="治癒數值 (Beta)  (顯示治癒事件日誌、治癒總量/自身/隊友)",
            variable=self.track_heal_var,
            command=self._on_track_heal_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(anchor="w", pady=4)

        ctk.CTkCheckBox(
            track_section,
            text="連攜攻擊偵測  (隊友掛在你身上觸發的傷害,例如治癒師 1 技的光波)",
            variable=self.detect_chain_var,
            command=self._on_detect_chain_change,
            corner_radius=5, checkbox_width=18, checkbox_height=18,
            font=(FONT_UI, 12),
        ).pack(anchor="w", pady=4)

        ctk.CTkLabel(track_section,
                     text="※ 攻擊數值/治癒數值可同時勾選;至少留一個開啟以免主畫面空白\n"
                          "※ 攻擊數值只統計「攻擊者 = 自己」的傷害,寵物/隊友/敵人不計入;\n"
                          "　 尚未偵測到角色 ID 時一律不記錄,可用控制列的「強制偵測」暫時全收\n"
                          "※ 連攜傷害「一律不計入」總傷害/DPS/技能排名 —— 那是隊友的技能;\n"
                          "　 未勾選:整筆剔除,日誌也不顯示\n"
                          "　 已勾選:日誌以黃字標註 (連攜) 並寫進存檔,但仍不計入統計\n"
                          "　 「強制偵測」下分不出誰是誰,連攜一律照常顯示並計入",
                     font=(FONT_UI, 10),
                     text_color="#888888", anchor="w", justify="left").pack(fill="x", pady=(8, 0))

        # ── 「診斷」區塊 ──
        diag_section = ctk.CTkFrame(body, fg_color="transparent")
        diag_section.pack(fill="x", padx=12, pady=(16, 4))
        ctk.CTkLabel(diag_section, text="── 診斷 ──",
                     font=(FONT_UI, 12),
                     text_color="#ffffff", anchor="w").pack(fill="x", pady=(0, 8))

        diag_row = ctk.CTkFrame(diag_section, fg_color="transparent")
        diag_row.pack(fill="x", pady=4)
        ctk.CTkLabel(diag_row, text="網路環境:", width=90,
                     font=(FONT_UI, 12),
                     anchor="w").pack(side="left", padx=(0, 8))
        ctk.CTkButton(diag_row, text="🌐 網路檢測",
                      width=120, corner_radius=6,
                      fg_color="#3a6a9a", hover_color="#4a7ab0",
                      font=(FONT_UI, 11),
                      command=self.show_network_check).pack(side="left", padx=(0, 8))

    def hide_settings(self):
        overlay = getattr(self, "_settings_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._settings_overlay = None
        # entry 隨 overlay 一起銷毀,清空參照免得後續誤觸
        self._scale_entry = None

    def _on_scale_change(self, value):
        """套用縮放 → 更新日誌 tab stops → 更新 skill Canvas → 存檔。
        呼叫來源:▲/▼ 步進、還原預設。
        """
        self.font_scale = round(float(value), 2)
        ctk.set_widget_scaling(self.font_scale)
        ctk.set_window_scaling(self.font_scale)
        self.log_area._textbox.configure(tabs=self._scaled_tab_stops())
        # 技能列的 tk.Canvas 不受 CTk widget_scaling 影響,需手動同步
        self._apply_scale_to_skill_rows()
        if getattr(self, "_scale_entry", None) is not None:
            # Entry 是 readonly,更新前要先解鎖
            self._scale_entry.configure(state="normal")
            self._scale_entry.delete(0, "end")
            self._scale_entry.insert(0, f"{self.font_scale:.1f}x")
            self._scale_entry.configure(state="readonly")
        self.settings["font_scale"] = self.font_scale
        save_settings(self.settings)

    def _step_scale(self, delta):
        """▲/▼ 按鈕步進;夾在 FONT_SCALE_MIN..MAX,四捨五入到小數一位避免浮點誤差。"""
        new_val = round(self.font_scale + delta, 1)
        new_val = max(FONT_SCALE_MIN, min(FONT_SCALE_MAX, new_val))
        if new_val != self.font_scale:
            self._on_scale_change(new_val)

    def _reset_scale(self):
        self._on_scale_change(FONT_SCALE_DEFAULT)

    def set_alpha(self, value):
        alpha = float(value) / 100
        self.root.attributes("-alpha", alpha)
        self.lbl_alpha.configure(text=f"{int(float(value))}%")

    def toggle_topmost(self):
        self.is_topmost = self.topmost_var.get()
        self._apply_topmost_all()
        status = "已開啟" if self.is_topmost else "已關閉"
        self.log(f"=== 視窗置頂 {status} ===")

    def toggle_force_all(self):
        """強制偵測:無視角色 ID 門檻,所有解析到的傷害全部計入統計。

        角色 ID 偵測失敗時 (換場景沒收到自己的登場訊息、串流被重傳打斷、沒裝 brotli)
        統計會整個停擺,這個勾選是逃生門。代價是隊友/寵物/敵人的傷害也會一起算進來。
        兩種口徑不該混在同一份統計裡,所以切換時直接歸零重來。
        """
        self.force_all = self.force_all_var.get()
        self.clear_data()
        if self.force_all:
            self.log_error("=== ⚡ 強制偵測 已開啟 — 所有人的傷害都會計入,"
                           "數據不再只屬於自己 ===")
        else:
            self.log("=== 強制偵測 已關閉 — 恢復成只統計自己的傷害 ===")

    def _bind_tooltip(self, widget, text):
        """滑鼠停在 widget 上 TOOLTIP_DELAY_MS 後跳出小提示,移開即消失。"""
        widget.bind("<Enter>", lambda _e: self._tooltip_schedule(widget, text))
        widget.bind("<Leave>", lambda _e: self._tooltip_hide())
        widget.bind("<Button-1>", lambda _e: self._tooltip_hide())

    def _tooltip_schedule(self, widget, text):
        self._tooltip_hide()
        self._tooltip_after_id = self.root.after(
            TOOLTIP_DELAY_MS, lambda: self._tooltip_show(widget, text))

    def _tooltip_show(self, widget, text):
        """提示視窗:overrideredirect 的 Toplevel,永遠置頂。
        它是短命視窗,不納入 _apply_topmost_all 的清單 (主視窗置頂時也不能被蓋掉)。
        任何例外都吞掉 — 提示壞了不能影響主功能。
        """
        self._tooltip_after_id = None
        try:
            win = tk.Toplevel(self.root)
            win.overrideredirect(True)
            win.attributes("-topmost", True)
            ctk.CTkLabel(win, text=text, font=(FONT_UI, 11),
                         fg_color="#2b2b2b", text_color="#dddddd",
                         justify="left", anchor="w", wraplength=360,
                         corner_radius=6).pack(padx=1, pady=1)
            win.update_idletasks()
            # 以 widget 為中心置中,再夾回螢幕內 —— ? 鈕靠右時直接置中會有一半跑出畫面
            tip_w = win.winfo_width()
            x = widget.winfo_rootx() + widget.winfo_width() // 2 - tip_w // 2
            x = max(0, min(x, self.root.winfo_screenwidth() - tip_w))
            win.geometry(f"+{x}+{widget.winfo_rooty() + widget.winfo_height() + 4}")
            self._tooltip_win = win
        except Exception:
            self._tooltip_win = None

    def _tooltip_hide(self):
        if self._tooltip_after_id is not None:
            try:
                self.root.after_cancel(self._tooltip_after_id)
            except Exception:
                pass
            self._tooltip_after_id = None
        if self._tooltip_win is not None:
            try:
                self._tooltip_win.destroy()
            except Exception:
                pass
            self._tooltip_win = None

    def _apply_topmost_all(self):
        """對主視窗與所有 popout Toplevel 一併套用 topmost 狀態。
        呼叫時機:toggle_topmost / _popout_log / _popout_skill / _popout_dev (新視窗建立時)。
        """
        try:
            self.root.attributes("-topmost", self.is_topmost)
        except Exception:
            pass
        for w in (self._log_popout_win, self._skill_popout_win, self._dev_popout_win):
            if w is None:
                continue
            try:
                w.attributes("-topmost", self.is_topmost)
            except Exception:
                pass

    def toggle_log_collapse(self):
        """折疊/展開事件日誌。折疊時 log_area 隱藏但仍持續寫入。
        高度重分配交給 _layout_panes (未折疊的 pane 均分),不再動視窗 geometry。
        """
        if self.log_collapsed:
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
            self.btn_log_toggle.configure(text="▼ 即時攻擊事件日誌")
            self.log_collapsed = False
        else:
            self.log_area.pack_forget()
            self.btn_log_toggle.configure(text="▶ 即時攻擊事件日誌 (已折疊)")
            self.log_collapsed = True
        self._layout_panes()

    def toggle_skill_collapse(self):
        """折疊/展開技能傷害排行區塊。折疊時 skill_scroll 隱藏但 target_stats 持續累計。"""
        if self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
            self.btn_skill_toggle.configure(text="▼ 技能傷害排行")
            self.skill_collapsed = False
        else:
            self.skill_scroll.pack_forget()
            self.btn_skill_toggle.configure(text="▶ 技能傷害排行 (已折疊)")
            self.skill_collapsed = True
        self._layout_panes()

    def _skill_area_enter(self, event):
        """滑鼠進入技能排行區,暫時接管 wheel 事件並禁止 CTk 內建 handler 打架。"""
        self.root.bind_all("<MouseWheel>", self._on_skill_wheel_all)

    def _skill_area_leave(self, event):
        """滑鼠離開技能排行區,交還 wheel 事件給其他元件 (log/dev/etc)。
        重要:tkinter 的 Leave 事件在游標「移入子元件」時也會觸發,
        必須用座標檢查游標是否真的離開了 skill_pane 的範圍,否則會誤解綁。
        """
        try:
            x, y = event.x_root, event.y_root
            sx = self.skill_pane.winfo_rootx()
            sy = self.skill_pane.winfo_rooty()
            sw = self.skill_pane.winfo_width()
            sh = self.skill_pane.winfo_height()
            if sx <= x < sx + sw and sy <= y < sy + sh:
                return  # 仍在 skill_pane 內 (只是移入子 widget),不要解綁
            self.root.unbind_all("<MouseWheel>")
        except Exception:
            pass

    def _on_skill_wheel_all(self, event):
        """統一的 wheel handler,直接操作 skill_scroll 內部的 canvas。

        平台差異:Windows 的 event.delta 是 ±120 的倍數,除以 40 換算成捲動格數
        (與 CTk 內建速度一致);macOS Tk 送出的 delta 已經是格數本身 (±1~3),
        再除 40 會被整數截斷成 0,滾輪等同失效,所以直接使用原值。
        """
        SCROLL_SPEED = 3
        try:
            if IS_MACOS:
                step = int(-event.delta) * SCROLL_SPEED
            else:
                step = int(-event.delta / 40) * SCROLL_SPEED
            self.skill_scroll._parent_canvas.yview_scroll(step, "units")
        except Exception:
            pass
        return "break"

    def _create_skill_row(self, display_name):
        """建立單一技能的排行列。
        改用 tk.Canvas 繪製,因為 Canvas 上的 create_text 沒有背景框,
        文字底色天然透明,可讓 fill 橘色直接透過去 (CTkLabel 的 transparent
        只會顯示 parent bg = 深灰,做不到真正透過)。

        結構:
          Container (CTkFrame, 透明)
            ├── Canvas (bar):
            │     - fill_id  : 進度填充矩形 (橘)
            │     - name_id  : 名稱文字 (左貼 10px)
            │     - value_id : 傷害/占比文字 (右貼 10px)
            └── detail_lbl (CTkLabel, 展開時才 pack 於 bar 下方)

        font_scale 變更時需呼叫 _apply_scale_to_skill_rows() 手動重算尺寸
        (tk.Canvas 不受 CTk widget scaling 影響)。
        """
        container = ctk.CTkFrame(self.skill_scroll, fg_color="transparent")
        container.pack(fill="x", padx=0, pady=1)

        canvas_h, name_font, value_font = self._skill_row_metrics()

        bar = tk.Canvas(container, height=canvas_h, bg="#3a3a3a",
                         highlightthickness=0, bd=0, cursor="hand2")
        bar.pack(fill="x")

        # 進度條填充色:暗紅 #a03020 以 60% alpha 疊在 canvas 深灰底 (#3a3a3a) 上。
        # tk.Canvas 不支援真正的 alpha,但在單色底上,預先算出的混色 = 真正透明的視覺結果:
        #   R = 0.6*0xA0 + 0.4*0x3A = 0x77
        #   G = 0.6*0x30 + 0.4*0x3A = 0x34
        #   B = 0.6*0x20 + 0.4*0x3A = 0x2A
        # → #77342A
        # (若之後把 canvas bg 換色,這裡也要重算)
        fill_id = bar.create_rectangle(0, 0, 0, canvas_h,
                                        fill="#77342A", outline="")
        name_id = bar.create_text(10, canvas_h // 2,
                                    text="", anchor="w",
                                    font=name_font, fill="#ffffff")
        value_id = bar.create_text(0, canvas_h // 2,
                                     text="", anchor="e",
                                     font=value_font, fill="#ffffff")

        # 詳細統計:字體與技能列 name 相同 (12pt),展開時才 pack
        detail_lbl = ctk.CTkLabel(container, text="", anchor="w",
                                   justify="left",
                                   font=(FONT_UI, 12),
                                   text_color="#88ccff")

        row = {
            "container": container, "canvas": bar,
            "fill_id": fill_id, "name_id": name_id, "value_id": value_id,
            "canvas_h": canvas_h,
            "pct": 0.0,        # 記住當前占比,Canvas resize / 縮放時重算 fill 寬
            "detail": detail_lbl,
            "expanded": False,
            "sids": [],
        }

        # Canvas resize:重新調整 fill 寬度與 value_id 位置
        def _on_configure(event, r=row):
            w = event.width
            r["canvas"].coords(r["fill_id"], 0, 0, int(w * r["pct"]), r["canvas_h"])
            r["canvas"].coords(r["value_id"], w - 10, r["canvas_h"] // 2)
        bar.bind("<Configure>", _on_configure)

        # 點擊條上任一處都能展開 (Canvas 是單一 widget,不會被 label 吃掉事件)
        bar.bind("<Button-1>",
                  lambda e, n=display_name: self._toggle_skill_detail(n))

        return row

    def _skill_row_metrics(self):
        """依當前 font_scale 算 canvas 高度與 canvas 上文字用的字體。
        - canvas 高度手動乘 scale (tk.Canvas 本身不受 CTk 的 widget_scaling 影響)
        - 字體用共用的 CTkFont instance;CTk 會自動處理 widget/DPI 縮放
        """
        scale = self.font_scale
        canvas_h = int(30 * scale)
        return canvas_h, self._skill_name_font, self._skill_value_font

    def _apply_scale_to_skill_rows(self):
        """font_scale 變更後同步更新所有既有技能列的 canvas 高度與文字座標。
        字體本身不用重指:CTkFont instance 會自動因應 set_widget_scaling 更新,
        Canvas 只需 itemconfigure 觸發重繪即可 (以確保新尺寸生效)。
        """
        canvas_h, name_font, value_font = self._skill_row_metrics()
        # buff 列與技能列用同一組 metrics,一起重算
        for row in list(self.skill_rows.values()) + list(self.buff_rows.values()):
            c = row["canvas"]
            c.configure(height=canvas_h)
            row["canvas_h"] = canvas_h
            # 觸發字體 re-apply,讓 Canvas 拿到更新後的 CTkFont 尺寸
            c.itemconfigure(row["name_id"], font=name_font)
            c.itemconfigure(row["value_id"], font=value_font)
            # 重算文字 y 座標 (垂直置中);x 由後續 Configure 事件補
            c.coords(row["name_id"], 10, canvas_h // 2)
            w = c.winfo_width()
            c.coords(row["value_id"], w - 10, canvas_h // 2)
            c.coords(row["fill_id"], 0, 0, int(w * row["pct"]), canvas_h)

    def _create_buff_row(self, key):
        """建立單一 buff 的顯示列。結構與 _create_skill_row 相同但更精簡:
        沒有展開的詳細統計、填充色改綠色、右側文字是剩餘秒數。
        """
        container = ctk.CTkFrame(self.buff_scroll, fg_color="transparent")
        container.pack(fill="x", padx=0, pady=1)

        canvas_h, name_font, value_font = self._skill_row_metrics()
        bar = tk.Canvas(container, height=canvas_h, bg="#3a3a3a",
                         highlightthickness=0, bd=0)
        bar.pack(fill="x")

        fill_id = bar.create_rectangle(0, 0, 0, canvas_h,
                                        fill=BUFF_FILL_COLOR, outline="")
        name_id = bar.create_text(10, canvas_h // 2, text="", anchor="w",
                                   font=name_font, fill="#ffffff")
        value_id = bar.create_text(0, canvas_h // 2, text="", anchor="e",
                                    font=value_font, fill="#ffffff")

        row = {
            "container": container, "canvas": bar,
            "fill_id": fill_id, "name_id": name_id, "value_id": value_id,
            "canvas_h": canvas_h,
            "pct": 1.0,   # 進度條預設滿格,倒數時才往下掉
        }

        def _on_configure(event, r=row):
            w = event.width
            r["canvas"].coords(r["fill_id"], 0, 0, int(w * r["pct"]), r["canvas_h"])
            r["canvas"].coords(r["value_id"], w - 10, r["canvas_h"] // 2)
        bar.bind("<Configure>", _on_configure)
        return row

    def _buff_tick(self):
        """每 BUFF_TICK_MS 重畫一次 buff 列。

        倒數完全靠本地時鐘 (time.monotonic),不等伺服器 —— 封包只給「開始那一刻
        的總秒數」,中間不會再送。倒數到 0 時**保持在 0 不清除**:到期是由 REM
        封包宣告的,自行清掉會在漏包時讓畫面與遊戲不符。
        """
        try:
            self.update_buff_list()
        except Exception:
            pass
        finally:
            # 一律排下一次 —— 這是常駐 timer,不隨開始/停止或折疊中斷
            self._buff_tick_id = self.root.after(BUFF_TICK_MS, self._buff_tick)

    def update_buff_list(self):
        """重建/更新 buff 列。只顯示掛在自己身上的 buff。

        面板有三種狀態 —— 快取 (active_buffs) 一直在背景累積,這裡只決定顯示什麼:
          1. 還沒按過開始 → 一列都不顯示 (快取照收,按開始就會一次列出來)
          2. 監控中       → 依快取即時顯示,倒數走真實時鐘
          3. 已按停止     → 顯示按停止那一刻的快照,秒數定格

        Resize 進行中跳過視覺更新(與 update_skill_ranking 同一套規則);
        折疊時仍照跑,列是隱藏不是銷毀,展開後不必等下一個封包才有畫面。
        """
        if self._is_resizing:
            return
        if self._buff_frozen_at is not None:
            source, now = (self._buff_frozen_view or {}), self._buff_frozen_at
        elif self.is_monitoring:
            source, now = self.active_buffs, time.monotonic()
        else:
            source, now = {}, 0.0
        me = self.ident_self_entity
        # 還沒認出自己就一列都不顯示 —— 沒有身分就無從判斷 buff 是不是自己的
        live = {} if me is None else {
            k: v for k, v in source.items() if v["owner"] == me}

        for key, info in live.items():
            if key not in self.buff_rows:
                self.buff_rows[key] = self._create_buff_row(key)
            row = self.buff_rows[key]
            if info["infinite"]:
                pct, value_txt = 1.0, BUFF_INFINITE_TEXT
            else:
                remain = max(0.0, info["end"] - now)
                pct = (remain / info["dur"]) if info["dur"] > 0 else 0.0
                value_txt = f"{remain:.1f}s"
            row["pct"] = pct
            # 層數接在名稱後面。1 層不標 —— 大部分 buff 一輩子都是 1 層,
            # 每列都掛個 ×1 只是雜訊
            stacks = info["stacks"]
            name_txt = info["name"] if stacks <= 1 else f"{info['name']}  ×{stacks}"
            c = row["canvas"]
            c.itemconfigure(row["name_id"], text=name_txt)
            c.itemconfigure(row["value_id"], text=value_txt)
            w = c.winfo_width()
            # Canvas 剛建立時 winfo_width 可能為 1,交給 Configure 事件補畫
            if w > 1:
                c.coords(row["fill_id"], 0, 0, int(w * pct), row["canvas_h"])

        # 收到 REM (或換角色/換場景導致 owner 不再是自己) 的列直接銷毀
        for key in list(self.buff_rows.keys()):
            if key not in live:
                self.buff_rows[key]["container"].destroy()
                del self.buff_rows[key]

    def update_skill_ranking(self):
        """把「目前選取目標」的 skill_damage (raw by skill_id) 聚合後重排技能列。
        聚合分兩層:
          A) 依 format_skill_name(sid) 得到的顯示名稱聚合 —— 永遠生效,
             處理同一招在遊戲內產生多個 skill_id 但名稱相同的雜訊。
          B) 勾選「合併同技能」時,再依 MERGE_GROUPS 把成員名稱替換為群組名。
        Resize 進行中會跳過視覺更新 (資料仍會累加,resize 結束後補刷)。
        """
        if self._is_resizing:
            return
        view = self._view()
        if not view["skill_damage"]:
            # row 的 top-level widget 是 "container" (改 Canvas 版時從 "frame" 改名),
            # 忘了同步這裡的 destroy → 清除後首次進這分支會 KeyError,
            # 導致 clear_data 中斷、下次 start_monitoring 也在 update_skill_ranking 掛掉
            for row in self.skill_rows.values():
                row["container"].destroy()
            self.skill_rows.clear()
            return

        merge = self.merge_var.get()
        agg = {}       # display_name → damage
        agg_ids = {}   # display_name → [skill_id, ...] (供詳細統計聚合)
        for sid, dmg in view["skill_damage"].items():
            name = format_skill_name(sid)
            if merge:
                name = MERGE_GROUPS.get(name, name)
            agg[name] = agg.get(name, 0) + dmg
            agg_ids.setdefault(name, []).append(sid)

        if not agg:
            return
        max_dmg = max(agg.values())
        total = sum(agg.values())
        sorted_names = sorted(agg.keys(), key=lambda k: agg[k], reverse=True)

        seen = set()
        for name in sorted_names:
            dmg = agg[name]
            seen.add(name)
            if name not in self.skill_rows:
                self.skill_rows[name] = self._create_skill_row(name)
            row = self.skill_rows[name]
            row["sids"] = agg_ids[name]  # 存起來供詳細統計 (即使收合時也要保持最新)
            pct = (dmg / max_dmg) if max_dmg else 0
            row["pct"] = pct
            c = row["canvas"]
            w = c.winfo_width()
            # Canvas 剛建立時 winfo_width 可能為 1;此時交給 Configure 事件補畫,
            # 這裡只更新文字內容,fill 座標留空 (Configure 觸發時會依當前寬度重算)
            c.itemconfigure(row["name_id"], text=name)
            c.itemconfigure(row["value_id"],
                             text=f"{dmg:,}  ({dmg * 100 / total:.1f}%)")
            if w > 1:
                c.coords(row["fill_id"], 0, 0, int(w * pct), row["canvas_h"])
            # 展開中的列即時更新詳細統計
            if row["expanded"]:
                row["detail"].configure(
                    text=self._format_skill_detail(row["sids"]))
            # 重新 pack 以強制照排序順序顯示
            row["container"].pack_forget()
            row["container"].pack(fill="x", padx=0, pady=1)

        # 清掉不在 seen 中的舊 row (例如切換合併模式或 clear_data 後又跑新資料)
        for name in list(self.skill_rows.keys()):
            if name not in seen:
                self.skill_rows[name]["container"].destroy()
                del self.skill_rows[name]

    def _toggle_skill_detail(self, display_name):
        """點擊技能列時切換該列的詳細統計 (強擊/連擊/爆擊率) 顯示與否。"""
        row = self.skill_rows.get(display_name)
        if not row:
            return
        if row["expanded"]:
            row["detail"].pack_forget()
            row["expanded"] = False
        else:
            row["detail"].configure(text=self._format_skill_detail(row["sids"]))
            row["detail"].pack(fill="x", padx=10, pady=(2, 4))
            row["expanded"] = True

    def _format_skill_detail(self, sids):
        """把多個 skill_id 的命中次數與各標籤次數合計,格式化為顯示字串。
        沒有命中資料時回傳「(無資料)」。
        覆蓋率分母與上方看板同一套規則:爆擊排除 DoT,其餘標籤再排除持續傷害。
        """
        view = self._view()
        hits = 0
        cov_hits = 0   # 爆擊分母
        cov_main = 0   # 強擊/連擊/追擊分母
        # split["dir"/"ind"] = [傷害合計, 次數, 最小, 最大]
        split = {}
        counts = {name: 0 for name in COVERAGE_TAGS}
        for sid in sids:
            hits += view["skill_hits"].get(sid, 0)
            cov_hits += view["skill_cov_hits"].get(sid, 0)
            cov_main += view["skill_cov_main"].get(sid, 0)
            for kind, e in view["skill_split"].get(sid, {}).items():
                acc = split.get(kind)
                if acc is None:
                    split[kind] = list(e)
                else:
                    acc[0] += e[0]
                    acc[1] += e[1]
                    acc[2] = min(acc[2], e[2])
                    acc[3] = max(acc[3], e[3])
            per = view["skill_tags"].get(sid, {})
            for tag_name in counts:
                counts[tag_name] += per.get(tag_name, 0)
        if hits == 0:
            return "  (無資料)"
        # 傷害行:平均/最小/最大 —— 分母用該分類自己的次數 (含 DoT),
        # 「綜合」的次數即上一行的「共 N 次」。
        # 偵測到間接傷害時才拆成 綜合/直傷/間傷 三行,否則維持單行。
        dmg_lines = self._format_dmg_lines(split)
        # 顯示順序沿用既有的 強擊 → 連擊 → 爆擊,新標籤接在後面
        order = ("強擊", "連擊", "爆擊") + tuple(
            n for n in COVERAGE_TAGS if n not in ("強擊", "連擊", "爆擊"))
        if cov_hits == 0:
            # 全部都是 DoT → 覆蓋率無意義,只報次數
            return (f"  (全為 DoT,不計覆蓋率)    (共 {hits} 次)\n" + dmg_lines)
        parts = []
        for name in order:
            den = cov_hits if name in COVERAGE_TAGS_SUSTAIN else cov_main
            # 整段技能都是持續傷時 den = 0 → 該項無意義,顯示「—」而不是 0%
            parts.append(f"{name}率 —" if den == 0
                         else f"{name}率 {counts[name] * 100 / den:.1f}%")
        tail = f"    (共 {hits} 次"
        if cov_hits != hits:
            tail += f",DoT {hits - cov_hits} 次不計"
        if cov_main != cov_hits:
            tail += f",間接 {cov_hits - cov_main} 次只計爆擊"
        return "  " + "  |  ".join(parts) + tail + ")\n" + dmg_lines

    @staticmethod
    def _format_dmg_lines(split):
        """把 {"dir"/"ind": [傷害合計, 次數, 最小, 最大]} 排成傷害統計行。
        沒有間接傷害 → 單行 (不加分類前綴);有 → 綜合/直傷/間傷 三行。
        """
        def _row(prefix, dmg, n, mn, mx, total=False):
            cells = [
                f"平均傷害 {dmg / n:,.0f}",
                f"最小傷害 {mn:,}",
                f"最大傷害 {mx:,}",
            ]
            # 綜合的總傷害就是排行條上的數字,不重複顯示
            if total:
                cells.append(f"總傷害 {dmg:,}")
            return prefix + "  |  ".join(cells)

        d = split.get("dir")
        i = split.get("ind")
        if i is None:
            return "  " if d is None else _row("  ", *d)
        if d is None:
            # 整段技能都是間接傷害 → 綜合等於間傷,不必重複三行
            return _row("  (間傷)  ", *i, total=True)
        both = (d[0] + i[0], d[1] + i[1], min(d[2], i[2]), max(d[3], i[3]))
        return "\n".join((
            _row("  (綜合)  ", *both),
            _row("  (直傷)  ", *d, total=True),
            _row("  (間傷)  ", *i, total=True),
        ))

    def dev_log_startup_hints(self):
        """啟動時先把環境狀況寫進診斷 LOG,底部區塊一開始就有東西可看。"""
        if _BROTLI is None:
            self.dev_log("⚠ 未安裝 brotli,enc=1 的封包只看得到壓縮位元組 "
                         "(pip install brotli),角色 ID 偵測也會失效")
        if self.ident_self is None:
            self.dev_log("[ID] ⚠ 尚未取得自己的身分 — 等 0x4FFF「我的角色資料」出現"
                         "(換地圖時會送)")
        else:
            acc, idx = self.ident_self
            bound = ("0x%08X" % self.ident_self_entity
                     if self.ident_self_entity is not None else "未綁定")
            mark = "★" if self.ident_self_entity is not None else "⚠"
            self.dev_log(f"[ID] {mark} 目前身分: 帳號碼={acc} 角色索引={idx} | "
                         f"自己 = {bound}")
        if MONSTER_NAMES:
            self.dev_log(f"[MOB] 怪物名對照表已載入 {len(MONSTER_NAMES):,} 筆 — "
                         f"0x{MOB_APPEAR_TYPE:04X} 登場包探針啟用 (純觀測,不進統計)")
        else:
            self.dev_log(f"[MOB] 找不到 {MOB_NAME_FILE},目標欄位只能顯示 hex")

    # ================================================
    # 攻擊事件日誌
    #   所有寫入都先進 log_entries (deque),再視「目前選取的目標」決定要不要
    #   畫到 log_area。切換目標時用 _render_log() 依緩衝重畫整份。
    # ================================================
    def _log_visible(self, entry):
        """系統訊息 (target=None) 永遠顯示;傷害事件只在 All 或該目標被選取時顯示。"""
        return (entry["target"] is None
                or self.selected_target == TARGET_ALL
                or entry["target"] == self.selected_target)

    def _insert_log_line(self, entry):
        """把單筆 entry 寫進 log_area。
        紅字判定放在這裡即時算 (而非存進 entry),這樣切換高亮標籤後重畫,
        舊事件也會依新的高亮設定重新上色。
        """
        highlight = self.highlight_var.get()
        red = entry["error"] or (highlight != "無" and highlight in entry["tags"])
        tag = "highlight" if red else entry.get("color")
        self.log_area.configure(state="normal")
        if tag:
            self.log_area._textbox.insert("end", entry["text"] + "\n", tag)
        else:
            self.log_area.insert("end", entry["text"] + "\n")
        # 只捲垂直:wrap="none" 下 see() 會連帶水平捲到行尾,把傷害值欄推出視野
        self.log_area._textbox.yview_moveto(1.0)
        self.log_area.configure(state="disabled")

    def _append_log(self, text, target=None, tags=(), error=False, color=None):
        """新事件的快速路徑:進緩衝,看得到才畫 (不重畫整份)。
        color = 額外的文字色 tag (目前只有 ident_ok);紅字優先權高於它。
        """
        entry = {"text": text, "target": target, "tags": tags,
                 "error": error, "color": color}
        self.log_entries.append(entry)
        if self._log_visible(entry):
            self._insert_log_line(entry)

    def _render_log(self):
        """清空 log_area 後依 log_entries 重畫 (只畫目前目標看得到的)。
        呼叫時機:切換目標 / 切換高亮 / 清除資料 / log_pane popout-dock 重建。

        重畫走批次路徑:整份文字一次 insert 進底層 tk.Text,紅字事後用行號
        tag_add 補上,state 切換與捲動各只做一次。逐行呼叫 CTkTextbox.insert()
        會每次觸發捲軸需求檢查 (yview 計算 + grid 調整),數百筆就會卡到約一秒。
        """
        highlight = self.highlight_var.get()
        lines = []
        tagged_rows = []          # [(行號, tag)];tk.Text 行號從 1 起算
        for entry in self.log_entries:
            if not self._log_visible(entry):
                continue
            lines.append(entry["text"])
            if entry["error"] or (highlight != "無" and highlight in entry["tags"]):
                tagged_rows.append((len(lines), "highlight"))
            elif entry.get("color"):
                tagged_rows.append((len(lines), entry["color"]))
        tb = self.log_area._textbox
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        if lines:
            tb.insert("1.0", "\n".join(lines) + "\n")
            for row, tag in tagged_rows:
                tb.tag_add(tag, f"{row}.0", f"{row + 1}.0")
        tb.configure(state="disabled")
        # 只捲垂直,理由同 _insert_log_line
        tb.yview_moveto(1.0)

    def log(self, text):
        """系統訊息:不屬於任何目標,任何篩選下都會顯示。"""
        self._append_log(text)

    def log_error(self, text):
        """紅字錯誤訊息(共用 highlight tag)。"""
        self._append_log(text, error=True)

    def log_damage(self, text, tags, target_id, color=None):
        """攻擊事件:記下受擊目標,供切換目標時過濾。
        color 目前只有 "chain" (連攜傷害,黃字);高亮標籤的紅字優先權仍在它之上。"""
        self._append_log(text, target=target_id, tags=tags, color=color)


    @staticmethod
    def _dev_tag_of(text):
        """依訊息裡的標記決定顏色 tag (見 DEV_TAG_MARKS);沒有標記回 None。"""
        for mark, tag in DEV_TAG_MARKS:
            if mark in text:
                return tag
        return None

    def dev_log(self, text, tag=None):
        """診斷訊息:進緩衝 → 更新底部單行 → 展開視窗開著就一併寫入。

        tag 省略時依訊息裡的 ✗ / ⚠ / ★ 自動上色 —— 身分偵測失敗那幾行
        (抓不到角色 ID / 本場尚未綁定) 才不會被淹沒在整片灰字裡。

        分類由訊息開頭的 [XXX] 決定 (見 DEV_CATEGORIES),被勾掉的分類只是不寫進
        展開視窗,緩衝與底部單行照舊。
        """
        if tag is None:
            tag = self._dev_tag_of(text)
        cat = DEV_PREFIX_CAT.get(text.split(" ", 1)[0])
        self._dev_lines.append((text, tag, cat))
        # 底部只有一行,換行字元會把 button 撐高,長行也要截斷
        line = text.replace("\n", " ")
        if len(line) > DEV_STRIP_MAX_CHARS:
            line = line[:DEV_STRIP_MAX_CHARS - 1] + "…"
        try:
            # 收合狀態下只看得到這一條,顏色跟著最新一行走
            self.dev_strip.configure(
                text=line, text_color=DEV_TAG_COLORS.get(tag, DEV_STRIP_IDLE_COLOR))
        except Exception:
            pass
        # 視窗關閉時 widget 不存在 (寫入是 after() 排程,可能晚於關窗)
        if self.dev_log_area is None or not self._dev_visible(cat):
            return
        # 不呼叫 see("end") —— 新訊息不搶捲軸,使用者往上翻的位置留得住。
        # 要看最新的自己捲到底,或關掉重開視窗 (開窗時會停在最後一行)
        self.dev_log_area.configure(state="normal")
        if tag:
            self.dev_log_area._textbox.insert("end", text + "\n", tag)
        else:
            self.dev_log_area.insert("end", text + "\n")
        self.dev_log_area.configure(state="disabled")

    # ================================================
    # 依攻擊對象分桶的統計
    # ================================================
    @staticmethod
    def _new_stat_bucket():
        """單一攻擊對象 (或 TARGET_ALL) 的統計容器。
        欄位語意與舊版的 self.total_damage / tag_counts / skill_* 一一對應。
        """
        return {
            "damage": 0,                                  # 累積傷害
            "hits": 0,                                    # 命中筆數 (含 DoT)
            "cov_hits": 0,                                # 爆擊覆蓋率分母 (排除 DoT)
            "cov_main": 0,                                # 強擊/連擊/追擊分母 (再排除持續傷)
            "tags": {name: 0 for name in COVERAGE_TAGS},  # 各標籤出現次數
            "skill_damage": {},                           # skill_id → 傷害
            "skill_hits": {},                             # skill_id → 命中次數
            "skill_cov_hits": {},                         # skill_id → 非 DoT 命中次數
            "skill_cov_main": {},                         # skill_id → 再排除持續傷的次數
            "skill_tags": {},                             # skill_id → {tag: 次數}
            # skill_id → {"dir"/"ind": [傷害合計, 次數, 最小, 最大]}
            #   dir = 直傷 (含 DoT),ind = 間接傷害 (is_sustain)
            "skill_split": {},
            "first": None,                                # 首筆時間 (DPS 用)
            "last": None,                                 # 末筆時間
        }

    def _bucket(self, key):
        """取得指定 key 的統計桶,不存在則建立。"""
        b = self.target_stats.get(key)
        if b is None:
            b = self.target_stats[key] = self._new_stat_bucket()
        return b

    def _view(self):
        """目前畫面應該顯示的統計桶 (依下拉選單選取的目標)。"""
        return self._bucket(self.selected_target)

    def _register_target(self, target_id):
        """記錄新出現的攻擊對象並刷新下拉選單。已知對象則不動作。
        判重靠 target_stats:parse_payload 是「先 _register_target 再建桶」,
        所以首次出現時這裡還查不到,之後就查得到。順序不可對調。
        """
        if target_id in self.target_stats:
            return
        self.target_order.append(target_id)
        self.root.after(0, self._refresh_target_options)

    def _target_label(self, key):
        """目標按鈕文字:登場包 (0x4E4C) 認得出來就顯示怪物名,否則退回 0x + 8 碼 hex。

        同名的怪加上「#出現序」才分得出個體;全場只出現過一隻就不加 —
        單體 Boss 掛個 #1 只是雜訊。
        """
        if key == TARGET_ALL:
            return TARGET_ALL_LABEL
        entry = self._entity_names.get(key) or self._loaded_names.get(key)
        if entry is None:
            return f"0x{key:08X}"
        name, ordinal = entry
        label = clip_units(name, TARGET_NAME_MAX_UNITS)
        # 本次執行收到的:序號隨「目前看過幾隻同名的」浮動,只有一隻就不掛 #1。
        # 存檔帶來的:序號是存檔當下就定死的 (None = 當時只有一隻),不能拿
        # 現在的 _name_count 重算 —— 那是另一次執行的計數。
        if key in self._entity_names:
            ordinal = ordinal if self._name_count[name] > 1 else None
        return f"{label} #{ordinal}" if ordinal else label

    def _refresh_target_labels(self):
        """只更新既有按鈕的文字/寬度,不重建 widget。
        一場幾十則登場包,每則都重建整條列會閃到不能看。
        """
        for key, btn in self.target_buttons.items():
            if key == TARGET_ALL:
                continue
            text = self._target_label(key)
            if btn.cget("text") != text:
                btn.configure(text=text, width=target_btn_width(text))

    def _refresh_target_options(self):
        """依 target_order 重建目標按鈕列;維持目前選取不變。
        按鈕文字刻意不含傷害數字,這樣只有「出現新對象」時才需要重建,
        不必每筆傷害都動 widget;名字晚到則走 _refresh_target_labels 原地改字。
        """
        for btn in self.target_buttons.values():
            btn.destroy()
        self.target_buttons.clear()

        def add(key, text, width):
            btn = ctk.CTkButton(self.target_bar, text=text, width=width, height=26,
                                corner_radius=6, font=(FONT_LOG, 12),
                                fg_color=TARGET_BTN_IDLE, hover_color="#4a4a4a",
                                command=lambda k=key: self._on_target_change(k))
            btn.pack(side="left", padx=(0, 4))
            self.target_buttons[key] = btn

        add(TARGET_ALL, TARGET_ALL_LABEL, 46)
        for tid in self.target_order:
            text = self._target_label(tid)
            add(tid, text, target_btn_width(text))

        # 選取的目標已不存在 (例如 clear_data 之後) → 退回 All
        if self.selected_target not in self.target_buttons:
            self.selected_target = TARGET_ALL
            self._refresh_stats_view()
            self._render_log()
        self._update_target_buttons_style()

    def _sort_target_order(self):
        """把 target_order 依累積傷害由大到小重排 (傷害相同維持原順序)。
        回傳是否真的有變動,沒變就不必動 widget。
        """
        ordered = sorted(self.target_order,
                         key=lambda tid: -self._bucket(tid)["damage"])
        if ordered == self.target_order:
            return False
        self.target_order[:] = ordered
        return True

    def _reorder_target_buttons(self):
        """依現有 target_order 重新 pack 既有按鈕 (All 固定第一個)。
        不重建 widget,避免每 3 秒閃一次。
        """
        for key in (TARGET_ALL, *self.target_order):
            btn = self.target_buttons.get(key)
            if btn is None:
                continue
            btn.pack_forget()
            btn.pack(side="left", padx=(0, 4))

    def _tick_target_sort(self):
        """每 TARGET_SORT_INTERVAL_MS 依累積傷害重排目標按鈕列。"""
        try:
            if self._sort_target_order():
                self._reorder_target_buttons()
        finally:
            self._target_sort_after_id = self.root.after(
                TARGET_SORT_INTERVAL_MS, self._tick_target_sort)

    def _update_target_buttons_style(self):
        """選中的目標按鈕用亮藍底,其餘用深灰底。"""
        for key, btn in self.target_buttons.items():
            btn.configure(fg_color=(TARGET_BTN_SELECTED if key == self.selected_target
                                    else TARGET_BTN_IDLE))

    def _on_target_change(self, key):
        """點選目標按鈕 → 看板 / 技能排行 / 攻擊日誌三者一起換成該目標的資料。"""
        self.selected_target = key
        self._update_target_buttons_style()
        self._refresh_stats_view()
        self._render_log()

    def _refresh_stats_view(self):
        """把「目前選取目標」的統計重新畫到看板 + 技能排行。"""
        b = self._view()
        self.lbl_total_dmg.configure(text=f"{b['damage']:,}")
        self.lbl_target_hits.configure(text=f"{b['hits']:,} 筆")
        self.update_dps()
        self.update_coverage()
        self.update_skill_ranking()

    def update_coverage(self):
        """更新 COVERAGE_TAGS 各項覆蓋率顯示。樣本不足 COVERAGE_MIN_HITS 時維持「—」。"""
        b = self._view()
        # 分母排除 DoT (不觸發任何標籤);強擊/連擊/追擊 再排除持續傷害。
        # 兩個分母各自判斷樣本數 —— 打法偏持續傷時,爆擊率可能已經夠樣本,
        # 強擊率卻還沒收滿 COVERAGE_MIN_HITS,這時只有後者顯示「—」。
        for tag_name, lbl in self.lbl_cov.items():
            den = self._cov_den(b, tag_name)
            if den < COVERAGE_MIN_HITS:
                lbl.configure(text="—")
            else:
                lbl.configure(text=f"{b['tags'][tag_name] * 100 / den:.1f}%")

    @staticmethod
    def _cov_den(b, tag_name):
        """該標籤的覆蓋率分母:爆擊用 cov_hits (只排除 DoT),
        其餘標籤用 cov_main (再排除持續傷害)。"""
        return b["cov_hits"] if tag_name in COVERAGE_TAGS_SUSTAIN else b["cov_main"]

    def update_dps(self):
        b = self._view()
        if b["first"] is None or b["last"] is None:
            self.lbl_dps.configure(text="0")
            return
        elapsed = max(b["last"] - b["first"], 1.0)
        self.lbl_dps.configure(text=f"{b['damage'] / elapsed:,.0f}")

    # ================================================
    # 封包解析
    # ================================================
    @staticmethod
    def _read_skill_tlv(payload, off):
        """payload[off] 起若是合法的 0x4FEC (size 35),回傳
        (skill_id, 施法者 ID, 目標 ID, 7 bytes 旗標);否則 None。

        欄位位置見筆記 §5:key1 在 +25,userId 在 +9,targetId 在 +17,
        旗標 7 bytes 在 +33 (= content+24),與 0x5235 的 +41 是同一組值。
        """
        if off + 9 + 35 > len(payload) or payload[off:off+4] != SKILL_TLV_MAGIC:
            return None
        try:
            if struct.unpack("<I", payload[off+4:off+8])[0] != 35:
                return None
            return (struct.unpack("<I", payload[off+25:off+29])[0],
                    struct.unpack("<I", payload[off+9:off+13])[0],
                    struct.unpack("<I", payload[off+17:off+21])[0],
                    bytes(payload[off + SKILL_TLV_FLAG_BASE:
                                  off + SKILL_TLV_FLAG_BASE + DMG_FLAG_LEN]))
        except Exception:
            return None

    def find_dmg_skill(self, payload, dmg_off, size, target_id, flags):
        """替一筆 0x5235 找出它的 0x4FEC,回傳 (skill_id, 施法者 ID)。

        雙向掃 ±DMG_SKILL_NEAR_WINDOW,只收「目標 ID 相同 + 7 bytes 旗標全等」
        的候選,取距離最近的那個。理由與實測數據見 DMG_SKILL_NEAR_WINDOW 上方註解。

        舊版的單向往後掃有兩個 bug,一併解掉:
          1. 連攜傷害的 0x4FEC 在自己的 0x5235 前面 → 整批技能名往後錯一格,
             最後一筆抓不到變 "??????"
          2. 掃到 size != 35 的 0x4FEC 就 return None 提早中止,不再往後找
        找不到就回 (None, None) —— DoT 那種本來就沒有伴生 0x4FEC 的照舊不列入排行。
        """
        want = bytes(flags)
        dmg_end = dmg_off + 9 + (size if size > 0 else DMG_EVENT_SIZE)
        lo = max(0, dmg_off - DMG_SKILL_NEAR_WINDOW)
        hi = min(len(payload), dmg_end + DMG_SKILL_NEAR_WINDOW)
        best = (None, None)
        best_dist = None
        pos = payload.find(SKILL_TLV_MAGIC, lo, hi)
        while pos != -1:
            got = self._read_skill_tlv(payload, pos)
            if got is not None and got[2] == target_id and got[3] == want:
                dist = abs(pos - dmg_off)
                if best_dist is None or dist < best_dist:
                    best, best_dist = (got[0], got[1]), dist
            pos = payload.find(SKILL_TLV_MAGIC, pos + 1, hi)
        return best

    @staticmethod
    def _brotli_head(data, n):
        """解壓 Brotli content,回傳前 n bytes;無法解壓則 None。

        優先走串流式 Decompressor — 跨 TCP 分段被截斷的封包餵進去仍能吐出開頭
        幾十 bytes,而 entityId 就在最前面 4 bytes,這正是我們要的。方法名在新舊版
        分別是 decompress / process,兩個都試;串流式失敗才退回一次性 decompress。
        純診斷用,任何例外都吞掉回 None,不得影響掃描。
        """
        if _BROTLI is None or not data:
            return None
        try:
            dec = _BROTLI.Decompressor()
            for method in ("decompress", "process"):
                fn = getattr(dec, method, None)
                if fn is None:
                    continue
                try:
                    out = fn(bytes(data))
                except Exception:
                    continue
                if out:
                    return out[:n]
        except Exception:
            pass
        try:
            return _BROTLI.decompress(bytes(data))[:n]
        except Exception:
            return None

    # ================================================
    # 角色身分偵測 (純觀測)
    # 規則見檔頭 IDENT_* 常數的註解;實作分三塊:
    #   _scan_identity      每個封包的入口
    #   _ident_*_self       A 訊息 (0x4FFF) → 我的身分
    #   _ident_*_appear     B 訊息 (0x4E4F) → 實體 ID ↔ 身分,比對出「自己」
    # ================================================

    def _ident_reset(self):
        """清空身分偵測狀態 (開檔即呼叫,「清除」也會重來一次)。"""
        self.ident_self = None            # (accountInfo, characterIndex)
        self.ident_self_entity = None     # 本場綁定的「自己」實體 ID
        self._ident_appear_cache = collections.OrderedDict()   # eid → 解壓後的明文
        self._ident_streams = collections.OrderedDict()        # 連線 key → 進行中的訊息
        self._ident_self_hdr_seen = 0     # 總共掃到幾次 A 訊息標頭
        self._ident_ok_logged = False     # 綠字「已獲得角色ID資訊」只寫一次
        self._ident_new_scene()

    def _ident_new_scene(self):
        """每收到一則 A 訊息 (= 換場景 / 重新載入角色資料) 就重來一輪統計。"""
        self._ident_scene_appear = 0      # 本場收到幾筆玩家出現訊息
        self._ident_scene_full = 0        # 其中 body 完整收齊的幾筆
        self._ident_scene_hit = 0         # 命中自己的幾筆
        self._ident_scene_reject = 0      # 命中但被判為參照欄位、拒絕改綁的幾筆
        self._ident_bind_offs = ()        # 本場綁定那筆的 characterId 出現位移
        self._ident_scene_warned = False  # 開發者面板的「本場尚未綁定」是否已警告過
        self._ident_no_id_logged = False  # 攻擊日誌的紅字本場是否已寫過

    def _ident_log(self, msg):
        self.root.after(0, lambda m=msg: self.dev_log(m))

    def _ident_notify_ok(self):
        """首次取得角色 ID 時寫一行綠字 (由 sniff 執行緒呼叫,故走 after)。

        只寫「第一次」— 換場景會不斷解除/重新綁定,每次都報一遍只是洗版;
        按「開始」「清除」也不再重報。使用者真正需要被提醒的是「還沒有 ID」那個狀態。
        """
        if self._ident_ok_logged:
            return
        self._ident_ok_logged = True
        self.root.after(0, lambda: self._append_log(IDENT_MSG_OK, color="ident_ok"))

    def _ident_warn_no_id(self):
        """尚未取得角色 ID → 紅字提醒 (本場只寫一次)。"""
        if self._ident_no_id_logged:
            return
        self._ident_no_id_logged = True
        msg = IDENT_MSG_NONE if _BROTLI is not None else IDENT_MSG_NO_BROTLI
        self.root.after(0, lambda m=msg: self.log_error(m))

    def _ident_status_line(self):
        """啟動 / 按「開始」/ 按「清除」時的狀態提示 (主執行緒)。
        只在「還沒有角色 ID」時出聲 — 有 ID 是正常狀態,不需要每次都報。
        """
        if self.force_all:
            return          # 強制偵測下傷害照收,沒有角色 ID 也不是問題
        if self.ident_self_entity is None:
            self._ident_no_id_logged = True
            self.log_error(IDENT_MSG_NONE if _BROTLI is not None else IDENT_MSG_NO_BROTLI)

    def _scan_identity(self, payload, key=None):
        """身分偵測入口 — 任何例外都不得影響其他解析。

        payload 走「訊息狀態機」而非逐封包獨立解析:一則訊息的 body 常跨好幾個
        TCP 分段 (玩家出現 1~3KB、我的角色資料 100KB+),而 characterId 可能落在
        解壓後 2600 bytes 之後 —— 只解單一分段內那一截永遠讀不到。
        """
        try:
            self._ident_walk(payload, key)
        except Exception:
            pass

    def _ident_walk(self, payload, key):
        n = len(payload)
        pos = 0
        # 1. 前面的位元組若屬於還沒收完的訊息,先交給它
        st = self._ident_streams.get(key)
        if st is not None:
            take = min(st["need"], n)
            self._ident_feed(key, payload[:take])
            pos = take
        # 2. 剩下的位元組繼續找下一則訊息的 9-byte 標頭
        while pos + 9 <= n:
            cand, kind = -1, None
            for magic, k in ((IDENT_SELF_MAGIC, "self"), (IDENT_APPEAR_MAGIC, "appear")):
                p = payload.find(magic, pos)
                if p >= 0 and (cand < 0 or p < cand):
                    cand, kind = p, k
            if cand < 0 or cand + 9 > n:
                return
            size = struct.unpack("<i", payload[cand+4:cand+8])[0]
            enc = payload[cand+8]
            lo = IDENT_SELF_MIN_SIZE if kind == "self" else IDENT_APPEAR_MIN_SIZE
            if enc != 1 or not (lo <= size <= IDENT_MAX_SIZE):
                pos = cand + 1        # 對錯位撞出來的假標頭,往後挪 1 byte 重找
                continue
            self._ident_open(key, kind, size, payload[cand+9:cand+9+size])
            pos = cand + 9 + size     # 訊息跨段時 pos > n,迴圈結束,剩下的由下個封包接

    def _ident_open(self, key, kind, size, body):
        """開一則新訊息:建串流解壓器,餵入本封包內已有的那一截。"""
        if kind == "self":
            self._ident_self_hdr_seen += 1
            self._ident_log(f"[ID] 我的角色資料 type=0x{IDENT_SELF_TYPE:04X} "
                            f"len={size} enc=1 (第{self._ident_self_hdr_seen}次)")
        fn = None
        if _BROTLI is not None:
            try:
                dec = _BROTLI.Decompressor()
                # 方法名在新舊版分別是 decompress / process,只挑一個 (兩個都呼叫會重複餵)
                fn = getattr(dec, "decompress", None) or getattr(dec, "process", None)
            except Exception:
                fn = None
        if fn is None:
            if kind == "self":
                self._ident_log("[ID] ✗ 未安裝 brotli,無法解出自己的身分 "
                                "(pip install brotli)")
            kind = "skip"
        st = {"kind": kind, "size": size, "need": size, "got": 0,
              "fn": fn, "out": bytearray(), "done": False}
        self._ident_streams[key] = st
        while len(self._ident_streams) > IDENT_STREAM_MAX:
            self._ident_streams.popitem(last=False)
        self._ident_feed(key, body)

    def _ident_feed(self, key, data):
        """把 data 當成該連線目前這則訊息的後續 body。

        kind 三態:
          appear — 邊收邊解壓,湊到 IDENT_APPEAR_HEAD_BYTES 或收完就結算
          self   — 同上,但吐出前 8 bytes 就夠了,之後轉 skip
          skip   — 只倒數 need、不解壓。A 訊息 body 有 100KB+,不轉 skip 的話
                   後續幾十個封包的壓縮位元組會被當成訊息邊界亂掃
        """
        st = self._ident_streams.get(key)
        if st is None:
            return
        st["got"] += len(data)
        st["need"] -= len(data)
        if data and st["kind"] != "skip":
            try:
                out = st["fn"](bytes(data))
            except Exception as exc:
                if st["kind"] == "self":
                    self._ident_log(f"[ID] ⚠ 我的角色資料解壓中斷 ({exc.__class__.__name__}),"
                                    f"已收 {st['got']}B — 本工具不做 TCP 重組,"
                                    f"重傳或亂序會直接打斷串流")
                st["kind"] = "skip"
                out = b""
            if out:
                st["out"] += out
            if st["kind"] == "self":
                if len(st["out"]) >= 8:
                    self._ident_apply_self(bytes(st["out"][:8]), st["got"])
                    st["kind"] = "skip"
                    st["out"] = bytearray()
                elif st["got"] >= IDENT_SELF_FEED_MAX:
                    self._ident_log(f"[ID] ⚠ 已收 {st['got']}B 仍吐不出前 8 bytes,"
                                    f"放棄本則 — 本場可能因此抓不到角色 ID")
                    st["kind"] = "skip"
            elif st["kind"] == "appear" and len(st["out"]) >= IDENT_APPEAR_HEAD_BYTES:
                self._ident_finish_appear(st)
                st["kind"] = "skip"
        if st["need"] <= 0:
            if st["kind"] == "appear":
                self._ident_finish_appear(st)
            self._ident_streams.pop(key, None)

    def _ident_apply_self(self, head8, got):
        """解出的前 8 bytes → 我的身分。reserved 必須是 0,拿來擋假陽性。

        A 訊息 = 換場景 (或換角色) 的信號:實體 ID 一定跟著換,所以**一律解除舊綁定**,
        身分保留下來去比對新場景的玩家。沿用舊綁定會把「自己」指到別人身上。
        """
        index, account, reserved = struct.unpack("<HIH", head8)
        if reserved != 0:
            self._ident_log(f"[ID] ⚠ 解出 reserved={reserved} ≠ 0 → 判為假陽性,丟棄")
            return
        ident = (account, index)
        prev_entity = self.ident_self_entity
        self.ident_self_entity = None
        self._ident_new_scene()   # 紅字提醒也重新武裝:本場真的打不進統計時才會出聲
        if ident == self.ident_self:
            old = f"0x{prev_entity:08X}" if prev_entity is not None else "無"
            self._ident_log(f"[ID] 場景更新 (身分不變: 帳號碼={account} 角色索引={index}),"
                            f"解除舊綁定 {old},等待重新比對")
            return
        if self.ident_self is not None:
            self._ident_log(f"[ID] 身分改變 {self.ident_self} → {ident} = 換角色,"
                            f"清掉舊綁定重新偵測")
        self.ident_self = ident
        self._ident_log(f"[ID] 我的身分: 帳號碼={account} 角色索引={index} | "
                        f"characterId=0x{(account << 16 | index):016X} "
                        f"(收 {got}B 後解出)")
        self._ident_rescan_cache()

    # ---- B: 玩家出現 0x4E4F ----

    def _ident_finish_appear(self, st):
        """一則玩家出現訊息收尾:解壓內容 → 實體 ID + 比對身分,並記一行診斷。"""
        if st["done"]:
            return
        st["done"] = True
        plain = bytes(st["out"])
        full = st["need"] <= 0
        self._ident_scene_appear += 1
        if full:
            self._ident_scene_full += 1
        eid = struct.unpack("<I", plain[:4])[0] if len(plain) >= 4 else None
        offs = ()
        if eid is not None:
            if self.ident_self is None:
                # 身分還沒到手 → 先留著,等 A 訊息來了回頭掃 (兩個方向都要做)
                self._ident_appear_cache.pop(eid, None)
                self._ident_appear_cache[eid] = plain
                while len(self._ident_appear_cache) > IDENT_APPEAR_CACHE_MAX:
                    self._ident_appear_cache.popitem(last=False)
            else:
                offs = self._ident_match_offsets(plain)
        # 別人的出現訊息不寫 LOG (一次換圖十幾筆,只會洗版) — 只累計數字,
        # 供「本場尚未綁定」那行診斷用
        if offs:
            self._ident_scene_hit += 1
            self._ident_bind(eid, offs)

    def _ident_match_offsets(self, plain):
        """在解壓內容裡找 u64 characterId == 我的身分,回傳「所有」出現位移。

        比對鍵是帳號碼與角色索引「兩個都要相等」— 拆開比會綁到同帳號的別隻角色,
        或撞到別的帳號 (角色索引 4、5 這種小數字滿地都是)。

        回全部而不是第一個:命中不代表這則訊息「就是在講我」—— 別人的登場訊息
        裡也可能帶著我的 characterId 當參照欄位 (見 _ident_bind)。位移與出現
        次數是事後分辨誰是誰的唯一線索,兩個都要留在 LOG 裡。
        """
        if self.ident_self is None:
            return ()
        account, index = self.ident_self
        needle = struct.pack("<Q", account << 16 | index)
        offs = []
        pos = plain.find(needle)
        while pos >= 0 and len(offs) < IDENT_MATCH_OFF_MAX:
            offs.append(pos)
            pos = plain.find(needle, pos + 1)
        return tuple(offs)

    @staticmethod
    def _fmt_offs(offs):
        return "+" + ", +".join(str(o) for o in offs) if offs else "無"

    def _ident_bind(self, eid, offs):
        """把「自己」綁到某個實體;offs = 我的 characterId 在該則訊息裡的所有位移。

        **同一場只認第一個命中者。** A 訊息 (換場景) 一律解除綁定,所以一場裡
        「自己」的實體 ID 不會變;同場再冒出第二個帶著我 characterId 的實體,
        那個 characterId 必然是別人訊息裡的**參照欄位**,不是他的身分。

        已知來源 (使用者回報,尚無本地封包樣本佐證):自己是隊長時,新成員加入
        隊伍會送出登場訊息,內容帶著隊長的 characterId。舊版「後者覆蓋前者」
        因此把自己綁到新成員身上,之後的傷害統計整場報廢。當隊員時不會發生
        —— 別人訊息裡帶的是隊長的 ID,不是自己的。
        """
        if self.ident_self_entity == eid:
            return
        if self.ident_self_entity is not None:
            self._ident_reject_rebind(eid, offs)
            return
        self.ident_self_entity = eid
        self._ident_bind_offs = offs
        self._ident_log(f"[ID] ★ 自己 = 實體 0x{eid:08X} (本場首次綁定) | "
                        f"characterId 位於解壓後位移 {self._fmt_offs(offs)}")
        self._ident_notify_ok()
        # 治癒端的 0x502A 學習是唯一獨立於本規則的自身 ID 來源 (見 parse_heal_shield §5),
        # 學到的話拿來當第二個佐證 —— 只有一個來源就分不出對錯
        lp = self.local_player_id
        if lp is not None:
            same = "一致" if (lp & 0xFFFFFFFF) == eid else "不一致"
            self._ident_log(f"[ID] 對照治癒端學到的本地 ID 0x{lp:X}: {same}")

    def _ident_reject_rebind(self, eid, offs):
        """本場已綁定,又有別的實體帶著我的 characterId → 預設拒絕改綁。

        唯一的例外是治癒端學到的 local_player_id (見 parse_heal_shield §5):
        那是獨立於本規則的第二個來源,它指向新候選就代表目前綁的才是錯的。
        """
        self._ident_scene_reject += 1
        lp = self.local_player_id
        if lp is not None and (lp & 0xFFFFFFFF) == eid:
            old = self.ident_self_entity
            self.ident_self_entity = eid
            self._ident_bind_offs = offs
            self._ident_log(
                f"[ID] ⚠ 改綁 0x{old:08X} → ★ 0x{eid:08X} — 治癒端學到的本地 ID "
                f"0x{lp:X} 指向後者,以獨立來源為準")
            return
        if self._ident_scene_reject > IDENT_REJECT_LOG_MAX:
            return
        self._ident_log(
            f"[ID] ⚠ 忽略候選 0x{eid:08X} (位移 {self._fmt_offs(offs)}) — 本場已綁定 "
            f"0x{self.ident_self_entity:08X} (位移 {self._fmt_offs(self._ident_bind_offs)})。"
            f"同一場的實體 ID 不會變,多出來的命中是別人訊息裡的參照欄位 "
            f"(已知:自己當隊長時,新成員的登場訊息帶著隊長的 characterId)")

    def _ident_rescan_cache(self):
        """A 訊息晚到:回頭掃已快取的 B 訊息。"""
        if not self._ident_appear_cache:
            return
        hits = 0
        for eid, plain in list(self._ident_appear_cache.items()):
            offs = self._ident_match_offsets(plain)
            if offs:
                hits += 1
                self._ident_bind(eid, offs)
        self._ident_log(f"[ID] 回掃 {len(self._ident_appear_cache)} 筆已快取的玩家出現訊息,"
                        f"命中 {hits} 筆 (採用第 1 筆,其餘視為參照欄位)")
        self._ident_appear_cache.clear()

    # ================================================
    # 怪物登場包探針 (0x4E4C) — 只寫診斷 LOG,不進統計
    # ================================================

    def _mob_reset(self):
        """清空探針狀態。與身分偵測分開,免得互相干擾。"""
        self._mob_streams = collections.OrderedDict()   # 連線 key → 進行中的訊息
        self._mob_seen = collections.OrderedDict()      # entityId → 已印過的怪物碼
        # 目標欄位要顯示的名字。獨立於 _mob_seen — 後者是 256 筆的洗版防護,
        # 會把還在打的怪的名字擠掉。這份只增不改,直到超過 ENTITY_NAME_MAX。
        self._entity_names = collections.OrderedDict()  # entityId → (怪物名, 同名第幾隻)
        self._name_count = collections.Counter()        # 怪物名 → 已見過幾隻 (給序號)
        self._mob_lines = 0        # 已印的詳細行數 (上限 MOB_LOG_MAX)
        self._mob_n_msg = 0        # 收到幾則「完整收齊」的登場包
        self._mob_n_named = 0      # 掃到碼且查得到名字
        self._mob_n_unknown = 0    # 掃到碼但查不到 — 分辨「本來就沒名字」vs「取碼取錯」
        self._mob_n_nocode = 0     # 解壓成功但掃不到碼
        self._mob_n_broken = 0     # 解壓中斷 (不做 TCP 重組,重傳/亂序就斷)
        self._mob_n_round2 = 0     # 第一輪沒中、第二輪(只認前哨)卻查到名字的次數

    def _mob_log(self, msg):
        self.root.after(0, lambda m=msg: self.dev_log(m))

    def _mob_note(self, msg):
        """詳細行有上限 — 一場幾十隻怪,不設限會把其他診斷洗掉。"""
        self._mob_lines += 1
        if self._mob_lines <= MOB_LOG_MAX:
            self._mob_log(msg)
        elif self._mob_lines == MOB_LOG_MAX + 1:
            self._mob_log(f"[MOB] 詳細行已達 {MOB_LOG_MAX} 行上限,之後只印累計")

    def _mob_tally(self):
        self._mob_log(f"[MOB] 累計 登場{self._mob_n_msg} | 有名{self._mob_n_named} "
                      f"查無此碼{self._mob_n_unknown} 掃不到碼{self._mob_n_nocode} "
                      f"斷流{self._mob_n_broken} | 第二輪可疑{self._mob_n_round2}")

    def _mob_scan(self, payload, key):
        """探針入口 — 任何例外都不得影響其他解析。"""
        try:
            self._mob_walk(payload, key)
        except Exception:
            pass

    def _mob_walk(self, payload, key):
        """在 TCP 位元組流裡找 0x4E4C 的 9-byte 標頭並接續 body。

        結構與 _ident_walk 相同但狀態完全分開。這裡不做「跳過已知訊息」的最佳化,
        所以掃描範圍含別種訊息的壓縮 body — 假標頭靠 enc/size 檢查與解壓失敗擋掉,
        擋不掉的也只是多印一行診斷。
        """
        n = len(payload)
        pos = 0
        # 1. 前面的位元組若屬於還沒收完的登場包,先交給它
        st = self._mob_streams.get(key)
        if st is not None:
            take = min(st["need"], n)
            self._mob_feed(key, payload[:take])
            pos = take
        # 2. 剩下的位元組繼續找下一則登場包的標頭
        while pos + 9 <= n:
            cand = payload.find(MOB_APPEAR_MAGIC, pos)
            if cand < 0 or cand + 9 > n:
                return
            size = struct.unpack("<i", payload[cand+4:cand+8])[0]
            enc = payload[cand+8]
            if enc != 1 or not (MOB_MIN_SIZE <= size <= MOB_MAX_SIZE):
                pos = cand + 1        # 對錯位撞出來的假標頭,往後挪 1 byte 重找
                continue
            self._mob_open(key, size, payload[cand+9:cand+9+size])
            pos = cand + 9 + size     # 訊息跨段時 pos > n,迴圈結束,剩下的由下個封包接

    def _mob_open(self, key, size, body):
        """開一則新登場包:建串流解壓器,餵入本封包內已有的那一截。"""
        if _BROTLI is None:
            return
        try:
            dec = _BROTLI.Decompressor()
            # 方法名在新舊版分別是 decompress / process,只挑一個
            fn = getattr(dec, "decompress", None) or getattr(dec, "process", None)
        except Exception:
            fn = None
        if fn is None:
            return
        st = {"size": size, "need": size, "got": 0, "fn": fn, "dec": dec,
              "out": bytearray(), "dead": False, "done": False}
        self._mob_streams[key] = st
        while len(self._mob_streams) > MOB_STREAM_MAX:
            self._mob_streams.popitem(last=False)
        self._mob_feed(key, body)

    def _mob_feed(self, key, data):
        """把 data 當成該連線目前這則登場包的後續 body。

        跟身分偵測不同,這裡**要整則解完**才有用 — 怪物碼在尾端。串流一斷就整則
        作廢 (開頭的 entityId 拿得到也沒意義,沒有碼就查不到名字)。
        """
        st = self._mob_streams.get(key)
        if st is None:
            return
        st["got"] += len(data)
        st["need"] -= len(data)
        if data and not st["dead"]:
            try:
                out = st["fn"](bytes(data))
            except Exception as exc:
                st["dead"] = True
                self._mob_n_broken += 1
                self._mob_note(f"[MOB] 解壓中斷 ({exc.__class__.__name__}),已收 "
                               f"{st['got']}/{st['size']}B — 本工具不做 TCP 重組")
                out = b""
            if out:
                st["out"] += out
                if len(st["out"]) > MOB_PLAIN_MAX:
                    st["dead"] = True
                    self._mob_n_broken += 1
                    self._mob_note(f"[MOB] 解壓超過 {MOB_PLAIN_MAX}B,放棄本則 "
                                   f"(多半是撞到假標頭)")
        if st["need"] <= 0:
            if st["dead"]:
                pass
            elif self._mob_stream_incomplete(st):
                self._mob_n_broken += 1
                self._mob_note(f"[MOB] body 收滿 {st['size']}B 但 brotli 串流沒收尾 "
                               f"(只解出 {len(st['out'])}B),整則作廢")
            else:
                self._mob_finish(st)
            self._mob_streams.pop(key, None)

    @staticmethod
    def _mob_stream_incomplete(st):
        """body 收滿了但解壓器還沒收尾 = 中間漏了位元組。

        怪物碼在尾端,漏了就一定取不到 — 必須跟「掃不到碼」分開計數,否則分不出
        是取碼邏輯有問題還是根本沒收完。舊版 brotli 沒有 is_finished 就當它完整。
        """
        fin = getattr(st["dec"], "is_finished", None)
        try:
            return fin is not None and not fin()
        except Exception:
            return False

    def _mob_finish(self, st):
        """一則登場包收完:entityId + 掃怪物碼 + 查表,寫一行診斷。"""
        if st["done"]:
            return
        st["done"] = True
        plain = bytes(st["out"])
        self._mob_n_msg += 1
        if len(plain) < 12:
            self._mob_n_nocode += 1
            self._mob_note(f"[MOB] 解壓內容只有 {len(plain)}B,不足以取碼")
        else:
            eid = struct.unpack("<I", plain[:4])[0]
            if eid == 0:
                self._mob_n_nocode += 1
            else:
                self._mob_report(eid, plain)
        if self._mob_n_msg % MOB_TALLY_EVERY == 0:
            self._mob_tally()

    def _mob_report(self, eid, plain):
        code = self._mob_find_code(plain)
        if code is None:
            self._mob_n_nocode += 1
            # 第二輪(只認前哨)在台版會誤命中 — 同一個錨點位置放的是 RGBA 顏色值,
            # 03 00 00 00 這種樣式會自然出現。這裡**不採用**,只在「它查得到名字」
            # 時記一筆,用來估「若開第二輪會錯多少」。
            alt = self._mob_find_code(plain, head_only=True)
            hint = ""
            if alt is not None and alt in MONSTER_NAMES:
                self._mob_n_round2 += 1
                hint = f" | 第二輪得 {alt}→{MONSTER_NAMES[alt]} (未採用)"
            self._mob_note(f"[MOB] eid={eid} 掃不到怪物碼 (解壓 {len(plain)}B){hint}")
            return
        name = MONSTER_NAMES.get(code)
        if name:
            self._mob_n_named += 1
            self._remember_entity_name(eid, name)
        else:
            self._mob_n_unknown += 1
        # 同一隻 (eid + 同一個碼) 只印一次 — 登場包會重送
        if self._mob_seen.get(eid) == code:
            return
        self._mob_seen[eid] = code
        while len(self._mob_seen) > MOB_SEEN_MAX:
            self._mob_seen.popitem(last=False)
        if name:
            self._mob_note(f"[MOB] eid={eid} code={code} → {self._target_label(eid)}")
        else:
            self._mob_note(f"[MOB] eid={eid} code={code} → 查表無此碼 "
                           f"(Monster {eid})")

    def _remember_entity_name(self, eid, name):
        """登場包認出一隻怪 → 記下 eid → (名字, 同名第幾隻),並補刷目標按鈕文字。

        序號在「第一次看到這個 eid」時就固定,登場包會重送,不固定就會一直往上跳。
        序號不用 eid & 0xFF — 實測同一場的不同怪會撞號 (38624132 與 38624900 都是 132)。
        """
        if eid in self._entity_names:
            return
        self._name_count[name] += 1
        self._entity_names[eid] = (name, self._name_count[name])
        while len(self._entity_names) > ENTITY_NAME_MAX:
            self._entity_names.popitem(last=False)
        # 這隻可能已經在目標列上了 (傷害先到 / 名字晚到),同名第二隻出現時
        # 也要回頭把第一隻的序號補上 → 一律重刷文字,不重建 widget。
        self.root.after(0, self._refresh_target_labels)

    @staticmethod
    def _mob_find_code(plain, head_only=False):
        """從尾端往前掃哨兵取 4-byte 怪物碼,回傳 8 字元大寫 hex;沒有則 None。

        預設只跑第一輪 (前後哨都要對)。head_only 是第二輪,台版會誤命中,
        只拿來對照觀察,不當結果採用。

        ⚠ 回傳的是「線序 bytes 的 hex」,不是「讀成 u32 再格式化」—
        後者會左右顛倒 (C9DEC814 變 14C8DEC9),整張表查不到而且不會報錯。
        """
        span = 8 if head_only else 12
        # 下界 4:前 4 bytes 是 entityId,不可能是哨兵
        for p in range(len(plain) - span, 3, -1):
            if plain[p:p+4] != MOB_HEAD_SENTINEL:
                continue
            if not head_only and plain[p+8:p+12] != MOB_TAIL_SENTINEL:
                continue
            code = plain[p+4:p+8].hex().upper()
            if code not in MOB_CODE_IGNORE:
                return code
        return None

    # ------------------------------------------------------------------
    # Buff 探針 (0x1D4FD / 0x1D4FF / 0x1D4FE) — 純觀測,只寫診斷 LOG
    #   _buff_reset   清狀態 (每次重建視窗)
    #   _buff_scan    每個封包的入口,任何例外都不得影響其他解析
    # 佈局與驗證過程見 Note/MM_Scribe_PacketNotes_Buff.md
    # ------------------------------------------------------------------
    def _buff_reset(self):
        """清空 buff 狀態。與身分偵測 / 怪物探針完全分開。"""
        # 面板資料:(owner, buffKey hex) → {owner, buff_id, name, dur, end, infinite}
        # **key 一定要含 owner** —— buffKey 不是全域唯一的,實測同一個 key
        # 會同時掛在三隻怪身上(見 Note/MM_Scribe_PacketNotes_Buff.md),
        # 只用 key 當索引會互相覆蓋、REM 一隻就把另一隻的也刪掉。
        # 只有 REM 封包會刪 —— 倒數到 0 不清除,見 _buff_tick
        self.active_buffs = collections.OrderedDict()
        self._buff_tick_id = None
        # 停止後的凍結快照。按停止時記下當下的 monotonic 與當時的列,面板就定格在
        # 那一瞬間;按開始時兩者清回 None 恢復走動。
        # **凍結的是畫面,不是 active_buffs** —— 快取一直在背景更新 (見 _buff_scan),
        # 所以按開始時直接就有正確的剩餘秒數,不必等下一個封包。
        # (也不是把 tick 停掉 —— tick 還要負責 resize / 折疊後的重繪)
        self._buff_frozen_at = None
        self._buff_frozen_view = None
        # 存檔用的「已結束」區間:(buffId, 名稱, 起, 迄, 層數),時間是 time.time() 牆鐘 ——
        # 要和 damage_events 對得起來就必須同一個時鐘 (倒數另外用 monotonic,
        # 那是為了不受系統時間調整影響)。REM 時才寫進來,還在身上的那些
        # 由 _buff_intervals() 於存檔當下補上
        self.buff_history = collections.deque(maxlen=BUFF_HISTORY_MAX)
        # 按下「開始」的牆鐘時刻。存檔時所有 buff 區間的起點都夾到這裡 ——
        # 開始前就掛在身上的持久型 buff (例如無限持續的) 起點可能是幾十分鐘前,
        # 不夾的話覆蓋率會算出超過 100%
        self._monitor_start_wall = None
        # (op, 擁有者 eid, buffKey) → 已印過。ADD 會重送,不去重會洗版
        self._buff_seen = collections.OrderedDict()
        self._buff_lines = 0       # 已印的詳細行數 (上限 BUFF_LOG_MAX)

    def _buff_log(self, msg):
        self.root.after(0, lambda m=msg: self.dev_log(m))

    def _buff_note(self, msg):
        """詳細行有上限 — 一場下來 buff 事件不少,不設限會把其他診斷洗掉。

        面板不受這裡影響:_buff_scan 一律跑,只有診斷輸出看開發者模式
        (檢查在 _buff_report 內,見那裡的註解)。
        """
        self._buff_lines += 1
        if self._buff_lines <= BUFF_LOG_MAX:
            self._buff_log(msg)
        elif self._buff_lines == BUFF_LOG_MAX + 1:
            self._buff_log(f"[BUFF] 詳細行已達 {BUFF_LOG_MAX} 行上限,之後不再輸出")

    @staticmethod
    def _buff_parse_duration(raw):
        """持續時間欄位 → (是否無限, 秒數)。判定規則見 BUFF_DUR_MAX 的註解。"""
        secs = struct.unpack("<f", struct.pack("<I", raw))[0]
        # NaN 兩邊比較都是 False,會落到「無限」那一支,不必另外判
        if 0 < secs < BUFF_DUR_MAX:
            return False, secs
        return True, 0.0

    @classmethod
    def _buff_duration_text(cls, raw):
        """診斷 LOG 用的時長文字。無限的情況把 raw 一併印出來 ——
        這欄會漂移,原始值留著才看得出表示法有沒有再變。
        """
        infinite, secs = cls._buff_parse_duration(raw)
        return f"無限({raw:08X})" if infinite else f"{secs:g}s"

    def _buff_first_seen(self, seen_key):
        """去重:同一則事件會重送,只有第一次回報 True。"""
        if seen_key in self._buff_seen:
            return False
        self._buff_seen[seen_key] = True
        while len(self._buff_seen) > MOB_SEEN_MAX:
            self._buff_seen.popitem(last=False)
        return True

    def _buff_scan(self, payload):
        """探針入口 — 任何例外都不得影響其他解析。"""
        try:
            self._buff_walk(payload)
        except Exception:
            pass

    def _buff_walk(self, payload):
        """逐 payload 掃三個 buff opcode 的 9-byte 標頭。

        整則訊息只有 25/45 bytes,不做跨封包接續:被 TCP 切中的那幾則就是漏掉,
        與傷害事件同樣的已知代價 (見 PacketNotes_Damage §2「已知漏包來源」)。
        守門是三重的 —— opcode 相符、contentLength 與該 opcode 的固定長度**完全**
        相等、encodingType == 0;三個都對還撞上的機率低到可以忽略。
        """
        n = len(payload)
        hits = []
        for magic, clen, name in BUFF_OPS.values():
            pos = 0
            while True:
                off = payload.find(magic, pos)
                if off < 0 or off + 9 + clen > n:
                    break
                pos = off + 1
                if struct.unpack_from("<I", payload, off + 4)[0] != clen:
                    continue
                if payload[off + 8] != 0:
                    continue
                hits.append((off, name, payload[off + 9:off + 9 + clen]))
        # 三種 opcode 分開找,但要照線序印 —— 同一個封包裡 ADD 與 UPD 的先後
        # 就是層數變化的順序,依 opcode 分組會把它洗掉
        hits.sort(key=lambda h: h[0])
        for _off, name, body in hits:
            self._buff_report(name, body)

    def _buff_report(self, name, body):
        # 擁有者 / 來源取 u64 的低 32 位 — 與傷害事件的 attacker/target 同一套實體 ID,
        # 這樣才能直接套 _target_label 顯示怪物名
        owner = struct.unpack_from("<I", body, 0)[0]
        key = body[8:16].hex().upper()
        if name == "REM":
            # 面板:收到 REM 直接清掉(去重只管診斷輸出,資料一定要刪)
            gone = self.active_buffs.pop((owner, key), None)
            if gone is not None and owner == self.ident_self_entity:
                # 只記自己身上的 —— 圖表畫的是「我的 buff 軸」,場上幾十隻怪的
                # debuff 進來只會把 history 灌爆
                self.buff_history.append(
                    (gone["buff_id"], gone["name"], gone["start_wall"],
                     time.time(), gone["stacks"]))
            if not self.is_dev_mode:
                return
            if not self._buff_first_seen((name, owner, key)):
                return
            self._buff_note(f"[BUFF] REM 對象:{self._target_label(owner)} key={key}")
            return
        buff_id, dur_raw, stacks = struct.unpack_from("<III", body, 16)
        src = struct.unpack_from("<I", body, 28)[0]
        # 面板:ADD 與 UPD 都當成「重新開始倒數」——
        # 封包只在事件當下給一次總秒數,中間不會再送,所以每次收到就重設 end。
        infinite, dur = self._buff_parse_duration(dur_raw)
        # effects.ini 的 [Ignore] 清單:不進面板。診斷 LOG 仍會印(標上「已忽略」)——
        # 那是開發者模式限定的,留著才查得出「某個 buff 為什麼沒出現」
        # effects.ini 的 [Ignore] 清單:不進面板。診斷 LOG 仍會印(標上「已忽略」)——
        # 那是開發者模式限定的,留著才查得出「某個 buff 為什麼沒出現在面板上」
        ignored = buff_id in EFFECT_IGNORE
        # 先 pop 再 set:OrderedDict 的汰換順序要跟著「最後一次更新」走,
        # 直接指派不會把既有的 key 移到尾端。被忽略的只 pop 不 set —— 使用者
        # 中途把某個 buffId 加進 [Ignore] 並按重新開始時,面板上那筆要消失
        prev = self.active_buffs.pop((owner, key), None)
        if not ignored:
            wall = time.time()
            # 層數變了就把前一段收掉、從這一刻重新起算 —— 圖表要能把
            # 「10 層那段」與「32 層那段」畫成兩塊。純粹的重送 (層數沒變)
            # 不切,否則同一個層級會被切成一堆碎塊
            if prev is not None and prev["stacks"] != stacks                     and owner == self.ident_self_entity:
                self.buff_history.append(
                    (prev["buff_id"], prev["name"], prev["start_wall"],
                     wall, prev["stacks"]))
            self.active_buffs[(owner, key)] = {
                "owner": owner,
                "buff_id": buff_id,
                "name": format_buff_name(buff_id),
                "dur": dur,
                "end": time.monotonic() + dur,
                "infinite": infinite,
                "stacks": stacks,
                # 牆鐘起訖,只給存檔/圖表用。start_wall 是「目前這個層級」的起點:
                # 層數沒變就沿用 (重送不切段),變了就從現在重新起算 (見上面)
                "start_wall": (wall if prev is None or prev["stacks"] != stacks
                               else prev["start_wall"]),
                "end_wall": None if infinite else wall + dur,
            }
            while len(self.active_buffs) > BUFF_ACTIVE_MAX:
                self.active_buffs.popitem(last=False)
        # 以下只為診斷 LOG。f-string 的參數在呼叫前就求值,_buff_note 內部的
        # 開發者模式檢查擋不掉 _target_label 的開銷,所以在這裡就先擋掉
        if not self.is_dev_mode:
            return
        # 去重鍵含層數 —— 同一個 key 的重送要擋掉,但層數變化必須印出來
        if not self._buff_first_seen((name, owner, key, stacks)):
            return
        self._buff_note(
            f"[BUFF] {name}{'(已忽略)' if ignored else ''} "
            f"對象:{self._target_label(owner)} "
            f"buffId=0x{buff_id:08X}({format_buff_name(buff_id)}) "
            f"時長={self._buff_duration_text(dur_raw)} "
            f"層數={stacks} 來源:{self._target_label(src)} key={key}")

    def _dmg_feed(self, payload, conn_key, seq):
        """把同一條 TCP 連線的位元組接起來再餵 parse_payload。

        不是完整的 TCP stack,只處理「連續」這一件事:
          * seq 接得上 → 續在上一包的尾巴後面,被切成兩半的事件就補得回來
          * 整包都落在目前緩衝區間內 → 重傳,直接丟掉
          * 部分重疊 → 只把新的那一截接上去
          * 中間缺一段 / 亂序 → 先把還在等的事件放行,再從這包重新開始,
            且這包單獨判 (不再等後續),退化成改版前的逐封包行為

        重複計算靠 stream["reported"] (絕對 seq 高水位) 擋掉,不靠內容比對 ——
        同一輪爆發出現兩筆數值與旗標完全相同的傷害是正常的,內容比對會誤殺。
        代價是亂序時排在高水位之前的那包會被跳過:對 DPS 統計而言,少算一筆
        遠比重複算一筆好,而且亂序本來就罕見 (實測 5557 封包一次都沒發生)。
        """
        st = self._dmg_streams.get(conn_key)
        if st is None:
            st = {"buf": b"", "abs": seq, "reported": seq, "next": seq, "pend": 0.0}
            self._dmg_streams[conn_key] = st
            while len(self._dmg_streams) > DMG_STREAM_MAX_CONNS:
                self._dmg_streams.popitem(last=False)
        else:
            self._dmg_streams.move_to_end(conn_key)

        end = (seq + len(payload)) & 0xFFFFFFFF
        force = False
        if seq == st["next"]:
            st["buf"] += payload
        elif not seq_before(seq, st["abs"]) and not seq_before(st["next"], end):
            return                                  # 整包都在緩衝裡了 → 重傳
        elif seq_before(seq, st["next"]):
            st["buf"] += payload[(st["next"] - seq) & 0xFFFFFFFF:]   # 只接新的那一截
        else:
            # 缺口/亂序:先把還在等後方資料的事件放行,別跟著緩衝一起丟掉
            if st["pend"]:
                self.parse_payload(st["buf"], stream=st, flush=True)
            st["buf"] = payload
            st["abs"] = seq
            st["pend"] = 0.0
            force = True
        # 不變式:abs + len(buf) 永遠等於 next,否則下一包接不上會誤判成缺口
        st["next"] = (st["abs"] + len(st["buf"])) & 0xFFFFFFFF

        # pend = 這一輪「等後方資料」的起始時間。每次重設會讓逾時永遠不成立,
        # 所以沒 flush 就把原本的起點放回去,等夠久才真的放行。
        prev_pend = st["pend"]
        flush = force or (bool(prev_pend)
                          and time.time() - prev_pend >= DMG_PAIR_FLUSH_SEC)
        st["pend"] = 0.0
        self.parse_payload(st["buf"], stream=st, flush=flush)
        if st["pend"] and prev_pend and not flush:
            st["pend"] = prev_pend

        drop = len(st["buf"]) - DMG_STREAM_CARRY
        if drop > 0:
            st["buf"] = st["buf"][drop:]
            st["abs"] = (st["abs"] + drop) & 0xFFFFFFFF

    def parse_payload(self, payload, stream=None, flush=False):
        """掃 payload 裡的 0x5235 傷害事件並累計統計。

        stream=None 走舊的「單一封包」模式 (合成封包 smoke test 仍照這條路徑)。
        由 _dmg_feed 餵進來時 stream 是該連線的接續狀態,多做兩件事:
          * 用絕對 seq 位置記「回報到哪」,重傳/重疊的位元組不會被算第二次
          * 事件後方還沒收滿配對視窗就停下來等下一包,避免把被切斷的事件
            或「0x4FEC 還沒到」的事件判成抓不到技能
        """
        payload_len = len(payload)
        offset = 0
        if stream is not None:
            # 已回報過的區段不必再掃 (reported 是絕對 seq,單調遞增)
            done = (stream["reported"] - stream["abs"]) & 0xFFFFFFFF
            if done < payload_len:
                offset = done

        while offset < payload_len - 4:
            if payload[offset:offset+4] == DMG_EVENT_MAGIC:
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]

                    if stream is not None and size == DMG_EVENT_SIZE:
                        abs_off = (stream["abs"] + offset) & 0xFFFFFFFF
                        if seq_before(abs_off, stream["reported"]):
                            offset += size + 8
                            continue
                        # 配對要雙向掃,所以事件後方也要收滿視窗才判得準;
                        # 沒收滿就原地等下一包 (逾時由 flush 強制放行)
                        need = offset + 9 + size
                        if not flush:
                            need += DMG_SKILL_NEAR_WINDOW
                        if need > payload_len:
                            stream["pend"] = time.time()
                            return
                        stream["reported"] = (abs_off + 1) & 0xFFFFFFFF

                    if offset + 55 <= payload_len:
                        dmg_val = struct.unpack("<I", payload[offset+25:offset+29])[0]
                        # 攻擊對象 ID (protocol: UInt32 targetId @ content+8 = offset+17)
                        # 用於「目標篩選」分桶與日誌歸屬;offset+55 的長度檢查已涵蓋此範圍
                        target_id = struct.unpack("<I", payload[offset+17:offset+21])[0]
                        # 攻擊者 ID (protocol: UInt32 userId @ content+0 = offset+9);
                        # offset+55 的長度守門已涵蓋 offset+9..13
                        attacker_id = struct.unpack("<I", payload[offset+9:offset+13])[0]
                        # anti-decoy (筆記 §3):protocol 規定 ShowDamageFloater 的
                        # 合法條件是 userId != targetId 且兩者皆非 0。attacker == target
                        # 的對齊是誘餌 (改版後的 0x4F40 整族都是這樣),一律跳過不計。
                        if (attacker_id == target_id
                                or attacker_id == 0 or target_id == 0):
                            offset += (size + 8) if size > 0 else 35
                            continue
                        # 統計門檻:沒認出自己的實體 ID 就完全不記錄,認出後也只記
                        # 「攻擊者 == 自己」的傷害 (見 _scan_identity / 身分筆記)。
                        # 勾了「⚡ 強制偵測」就整個旁路,全部收 (見 toggle_force_all)。
                        is_self_hit = self.force_all or (
                            self.ident_self_entity is not None
                            and attacker_id == self.ident_self_entity)

                        # 1. 過濾傷害免疫 (仍歸屬到該目標,切換目標時一起被過濾)
                        if dmg_val == 0xFFFFFFFF:
                            if is_self_hit:
                                msg = "🛡️ [傷害免疫] 數值: 免疫 (0xFFFFFFFF)"
                                self.root.after(0, lambda m=msg, tid=target_id:
                                                self.log_damage(m, (), tid))
                            offset += (size + 8) if size > 0 else 35
                            continue

                        # 2. 讀取標籤旗標
                        #    旗標區為連續 7 bytes (見筆記 §4);flags[0]=b41, flags[1]=b42
                        #    flags[3..4] 的元素/追擊位元尚未驗證,只作診斷用
                        flags = [
                            payload[offset + DMG_FLAG_BASE + i]
                            if offset + DMG_FLAG_BASE + i < payload_len else 0
                            for i in range(DMG_FLAG_LEN)
                        ]
                        b41 = flags[0]
                        b42 = flags[1]
                        b57 = payload[offset+57] if offset+57 < payload_len else 0

                        # 持續傷害 (DoT):已確認,用於在技能名稱後加註 (Dot)
                        is_dot = any(flags[idx] & mask for idx, mask in DMG_DOT_BITS)
                        # 遊戲敘述的「持續傷害」:額外傷害位元全亮但不是 DoT。
                        # 用於技能名加註 (間接) 與覆蓋率分母分流 (見 DMG_SUSTAIN_BITS)
                        is_sustain = (not is_dot) and all(
                            flags[idx] & mask for idx, mask in DMG_SUSTAIN_BITS)

                        # 雙向找伴生的 0x4FEC,拿到技能 ID 與「誰放的」(見 find_dmg_skill)
                        skill_id, caster_id = self.find_dmg_skill(
                            payload, offset, size, target_id, flags)
                        # 連攜:技能是別人放的,傷害卻掛在自己身上 (治癒師 1 技光波等)。
                        # 統計照舊算自己的輸出 —— 遊戲本來就是這樣算的,只在日誌上標記。
                        is_chain = caster_id is not None and caster_id != attacker_id

                        if self.is_dev_mode:
                            # 開發者面板不受統計門檻影響:別人的傷害照印,
                            # 這是驗證身分偵測對不對的唯一依據
                            skill_txt = f"0x{skill_id:08X}" if skill_id is not None else "(未取得)"
                            # 連攜時把真正的施法者印出來 —— 傷害事件本身查不到這個 ID
                            if is_chain:
                                skill_txt += f" 連攜←0x{caster_id:08X}"
                            flags_txt = " ".join(f"{b:02X}" for b in flags)
                            # 候選位元:僅顯示,不影響統計。用來驗證 packet-protocol.md 的推論
                            hits = [name for idx, mask, name in DMG_FLAG_CANDIDATES
                                    if flags[idx] & mask]
                            cand_txt = f" | 候選: {'+'.join(hits)}" if hits else ""
                            # DoT / 額外傷害 各自拆到 bit 層級顯示,方便比對不同來源
                            dot_bits = [lbl for idx, mask, lbl in DMG_DOT_BIT_LABELS
                                        if flags[idx] & mask]
                            extra_bits = [lbl for idx, mask, lbl in DMG_EXTRA_BIT_LABELS
                                          if flags[idx] & mask]
                            dot_txt = f" | DoT({'+'.join(dot_bits)})" if dot_bits else ""
                            if extra_bits:
                                dot_txt += f" | 額外({'+'.join(extra_bits)})"
                            # 本場第一筆傷害仍未綁定 → 把診斷數據印出來,
                            # 用來分辨「沒收到出現訊息」還是「收到但解壓不夠長」
                            if (self.ident_self_entity is None
                                    and not self._ident_scene_warned):
                                self._ident_scene_warned = True
                                # 分三種斷法:連身分都沒有 / 有身分但沒收到出現訊息 /
                                # 收到了卻沒一筆命中 —— 連續進副本偶發失敗靠這行分辨
                                if self.ident_self is None:
                                    why = "連身分都還沒解出 (沒收到或沒解開 0x4FFF)"
                                elif self._ident_scene_full == 0:
                                    why = "沒有任何一筆出現訊息收完整 (串流被打斷)"
                                elif self._ident_scene_hit == 0:
                                    why = "出現訊息收到了但沒一筆命中自己"
                                else:
                                    why = "已命中卻未綁定 (不該發生)"
                                self._ident_log(
                                    f"[ID] ⚠ 本場尚未綁定,傷害不會記錄 — {why} | "
                                    f"已收到 {self._ident_scene_appear} 筆出現訊息 "
                                    f"(完整 {self._ident_scene_full} 筆, "
                                    f"命中 {self._ident_scene_hit} 筆)")
                            dev_msg = (f"[Flag] 數值: {dmg_val} | "
                                       f"攻擊者:0x{attacker_id:08X} → 目標:0x{target_id:08X} | "
                                       f"flags[41-47]: {flags_txt} | b57:{b57:02X} | "
                                       f"技能: {skill_txt}{dot_txt}{cand_txt}")
                            self.root.after(0, lambda m=dev_msg: self.dev_log(m))

                        # 2.4 統計門檻:只記錄自己打出去的傷害。
                        #     還沒認出自己的實體 ID 前一律不記 —— 沒有身分就無從分辨
                        #     哪些是自己的,寧可不記也不要記成別人的 (日誌上會有紅字提示)。
                        if not is_self_hit:
                            if self.ident_self_entity is None:
                                # 真的有傷害被丟掉時才提醒 (本場一次),換場景瞬間不出聲 —
                                # 綁定通常一秒內就補回來,提早報只會變成每次換圖閃一行紅字
                                self._ident_warn_no_id()
                            offset += (size + 8) if size > 0 else 35
                            continue

                        # 2.5 連攜傷害:技能是隊友放的,傷害卻掛在自己身上
                        #     (治癒師 1 技的光波等)。那不是你的輸出,一律不進統計桶。
                        #     「強制偵測」是旁路模式,連自己是誰都還沒認出來,分不出
                        #     誰連攜誰 —— 那裡照常顯示並計入,語意才跟「全部都收」一致。
                        #       選項關閉 → 整筆剔除,日誌也不印
                        #       選項開啟 → 印黃字 + 記進時間序列 (存檔留得住),但不計統計
                        chain_cut = is_chain and not self.force_all
                        if chain_cut and not self.detect_chain:
                            offset += (size + 8) if size > 0 else 35
                            continue

                        # 3. 標籤解析
                        #    b41: bit0=爆擊, bit2=無防備(排除破防), bit3=破防
                        #         bit4+bit5 組合:0x30=延長破防, 0x20=終結
                        #         bit6=首擊(first_hit,非標籤), bit7=普通攻擊旗標(自動攻擊=1)
                        #    b42: bit0=多重打擊, bit1=強擊, bit2=連擊, bit4=迎擊
                        #         bit3+bit7=持續傷害(DoT),不當標籤,改在技能名後加註 (Dot)
                        #    b44: bit3=追擊 (未驗證,見 DMG_ADD_HIT_BIT)
                        #    b57: bit0=破防 (備援旗標)
                        # b41 bit4/bit5 只在「同時亮 bit5」時有已知語意 (0x30 / 0x20);
                        # bit4 單獨亮還沒見過樣本,遮罩不放行,照舊報未知(b41.10)
                        KNOWN_MASK_B41 = 0xCD | ((b41 & 0x30) if (b41 & 0x20) else 0)
                        KNOWN_MASK_B42 = 0x9F   # 原 0x8F;bit4 已確認為迎擊,不再報未知

                        tags = []
                        if b41 & 0x01:
                            tags.append("爆擊")
                        if b42 & 0x02:
                            tags.append("強擊")
                        if (b41 & 0x08) or (b57 & 0x01):
                            tags.append("破防")
                        if (b41 & 0x04) and not (b41 & 0x08):
                            tags.append("無防備")
                        if b42 & 0x04:
                            tags.append("連擊")
                        if b42 & 0x01:
                            tags.append("多重打擊")
                        if b42 & 0x10:
                            tags.append("迎擊")
                        # 延長破防 / 終結:兩者共用 bit5,靠 bit4 區分,互斥
                        if (b41 & 0x30) == 0x30:
                            tags.append("延長破防")
                        elif (b41 & 0x30) == 0x20:
                            tags.append("終結")
                        # 追擊:位置來自 packet-protocol.md,尚未錄到本地樣本驗證
                        if flags[DMG_ADD_HIT_BIT[0]] & DMG_ADD_HIT_BIT[1]:
                            tags.append("追擊")

                        unknown_b41 = b41 & ~KNOWN_MASK_B41 & 0xFF
                        unknown_b42 = b42 & ~KNOWN_MASK_B42 & 0xFF
                        if unknown_b41 or unknown_b42:
                            parts = []
                            if unknown_b41:
                                parts.append(f"b41.{unknown_b41:02X}")
                            if unknown_b42:
                                parts.append(f"b42.{unknown_b42:02X}")
                            tags.append(f"未知({','.join(parts)})")

                        tag_str = f"[{'+'.join(tags)}]" if tags else "[普通]"

                        # 4. 傷害累加:同一筆同時進 TARGET_ALL 與該攻擊對象兩個桶。
                        #    連攜 (chain_cut) 只走下面的時間序列,不碰統計桶。
                        #    目標仍然要註冊 —— 你確實打到它了,不註冊的話存檔裡的
                        #    事件會指向一個不存在於 target_order 的目標。
                        self._register_target(target_id)
                        now = time.time()
                        for _key in () if chain_cut else (TARGET_ALL, target_id):
                            b = self._bucket(_key)
                            b["damage"] += dmg_val
                            if b["first"] is None:
                                b["first"] = now
                            b["last"] = now
                            b["hits"] += 1
                            # DoT 不會觸發爆擊/強擊/連擊/追擊 → 整筆排除在覆蓋率之外
                            # (分子分母都不算),只保留在傷害/命中/DPS 統計裡。
                            # 持續傷害會爆擊,但不會有強擊/連擊/追擊 → 只進爆擊的分子分母。
                            if not is_dot:
                                b["cov_hits"] += 1
                                if not is_sustain:
                                    b["cov_main"] += 1
                                for name in b["tags"]:
                                    if is_sustain and name not in COVERAGE_TAGS_SUSTAIN:
                                        continue
                                    if name in tags:
                                        b["tags"][name] += 1
                            # 累加該技能的傷害/命中/標籤 (skill_id 抓不到就不列入排行)
                            if skill_id is not None:
                                b["skill_damage"][skill_id] = b["skill_damage"].get(skill_id, 0) + dmg_val
                                b["skill_hits"][skill_id] = b["skill_hits"].get(skill_id, 0) + 1
                                # 直傷/間傷各自累計 傷害/次數/最小/最大
                                _sp = b["skill_split"].setdefault(skill_id, {})
                                _e = _sp.get("ind" if is_sustain else "dir")
                                if _e is None:
                                    _sp["ind" if is_sustain else "dir"] = [
                                        dmg_val, 1, dmg_val, dmg_val]
                                else:
                                    _e[0] += dmg_val
                                    _e[1] += 1
                                    if dmg_val < _e[2]:
                                        _e[2] = dmg_val
                                    if dmg_val > _e[3]:
                                        _e[3] = dmg_val
                                per = b["skill_tags"].setdefault(
                                    skill_id, {n: 0 for n in COVERAGE_TAGS})
                                if not is_dot:
                                    b["skill_cov_hits"][skill_id] = b["skill_cov_hits"].get(skill_id, 0) + 1
                                    if not is_sustain:
                                        b["skill_cov_main"][skill_id] = b["skill_cov_main"].get(skill_id, 0) + 1
                                    for _tn in COVERAGE_TAGS:
                                        if is_sustain and _tn not in COVERAGE_TAGS_SUSTAIN:
                                            continue
                                        if _tn in tags:
                                            per[_tn] += 1

                        # 時間序列:桶只留 first/last 兩個時間點,畫不出曲線,
                        # 所以每筆單獨記一列 (日誌上不顯示)。
                        self.damage_events.append(
                            (now, target_id, skill_id, dmg_val,
                             dmg_event_flags(tags, is_dot, is_sustain, is_chain)))

                        # 只有這筆會影響到「目前顯示中的目標」時才重畫
                        # (連攜沒動到任何統計桶,重畫出來會一模一樣)
                        if not chain_cut and self.selected_target in (TARGET_ALL, target_id):
                            self.root.after(0, self._refresh_stats_view)

                        # 技能欄:優先用 skills.ini 對照,skill_id=0 標為符文,否則顯示 hex ID
                        #        DoT 加註 (Dot)、持續傷害加註 (間接) — 兩者旗標都來自
                        #        傷害事件本身,與 skill_id 是否取得無關,抓不到 ID 一樣要加。
                        if skill_id is None:
                            skill_display = "?" * 10
                        else:
                            skill_display = format_skill_name(skill_id)
                        if is_dot:
                            skill_display += DMG_DOT_SUFFIX
                        elif is_sustain:
                            skill_display += DMG_SUSTAIN_SUFFIX
                        # 連攜註記獨立於 (Dot)/(間接):來源是「誰放的」,不是旗標
                        if is_chain:
                            skill_display += DMG_CHAIN_SUFFIX
                        # tab 分隔欄位,tab stop 已在初始化時設定於固定像素位置。
                        # 行首多一個 tab:傷害值靠第一個 (right) 停靠點右對齊,
                        # 不再補空白 — 補空白只在等寬字體下才對得齊。
                        msg = f"\t{dmg_val:,}\t{tag_str}\t{skill_display}"
                        self.root.after(0, lambda m=msg, t=list(tags), tid=target_id,
                                        c="chain" if is_chain else None:
                                        self.log_damage(m, t, tid, color=c))

                    # 事件實際總長為 9 + size,但這裡維持 +8:主迴圈是逐 byte 掃 magic,
                    # 落在前 1 byte 會自動被下一輪修正;落在後 1 byte 則會整個跳過下一筆。
                    offset += (size + 8) if size > 0 else 35
                    continue
                except Exception:
                    offset += 1
                    continue
            offset += 1

    # ================================================
    # 治癒 / 護盾 封包解析 (參考 MM_Scribe_PacketNotes_Heal.md)
    #   0x5029 (32B) = 治癒事件 (每個目標一筆)
    #   0x502A (24B) = 本地玩家被治療旗標 (只用於學習本地 ID,不計入)
    #   0x4EED (32B) = 護盾增量事件
    # Skill ID 提取:對每筆 heal/shield 執行 Near scan (見 HEAL_SHIELD_SKILL_ID.md §4)
    # ================================================
    def parse_heal_shield(self, payload):
        """單次掃描 payload,處理 heal + shield + local ID 學習 + Skill ID 關聯。
        - 未學到 local_player_id 前,heal / shield 都用中性標籤 (黃字「治療?」/「護盾?」)
          並不併入 heal_self / heal_ally 分項統計 (但仍計入 heal_total)。
        - Skill ID 走 HEAL_SHIELD_SKILL_ID.md 規格 (±300B 雙向 Near scan,anti-decoy),
          找不到就顯示無技能名。
        """
        offset = 0
        payload_len = len(payload)

        heals = []        # [(tlv_start, target_id, heal_val)]
        shields = []      # [(tlv_start, target_id, shield_amount)]
        flag_heal = None  # 0x502A 帶的 heal 值 (至多一筆)

        while offset < payload_len - 8:
            tag = payload[offset:offset+4]

            if tag == b'\x29\x50\x00\x00':  # 0x5029 heal event (32B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 24 and offset + 32 <= payload_len:
                        target_id = struct.unpack("<Q", payload[offset+9:offset+17])[0]
                        heal_val = struct.unpack("<I", payload[offset+25:offset+29])[0]
                        heals.append((offset, target_id, heal_val))
                        offset += 32
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            if tag == b'\x2a\x50\x00\x00':  # 0x502A local-heal flag (24B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 16 and offset + 24 <= payload_len:
                        flag_heal = struct.unpack("<I", payload[offset+17:offset+21])[0]
                        offset += 24
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            if tag == b'\xed\x4e\x00\x00':  # 0x4EED shield gain (32B TLV)
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]
                    if size == 24 and offset + 32 <= payload_len:
                        target_id = struct.unpack("<Q", payload[offset+9:offset+17])[0]
                        shield_amount = struct.unpack("<Q", payload[offset+17:offset+25])[0]
                        shields.append((offset, target_id, shield_amount))
                        offset += 32
                        continue
                except Exception:
                    pass
                offset += 1
                continue

            offset += 1

        if not (heals or shields):
            return

        # 本地玩家 ID 學習 (見 §5)
        if self.local_player_id is None and flag_heal is not None and heals:
            candidates = {tid for _s, tid, hv in heals if hv == flag_heal}
            if len(candidates) == 1:
                tid = next(iter(candidates))
                self.local_player_id = tid
                self.root.after(0, lambda t=tid: self.log_heal(
                    f"⭐ 已識別本地玩家 ID: 0x{t:X}"))

        # Shield 事件 (統計只寫日誌,不進 banner)
        for tlv_start, target_id, amount in shields:
            skill_id = self._find_heal_shield_skill_id(payload, tlv_start)
            suffix, tag = self._classify_target(target_id)
            prefix = f"護盾{suffix}"
            skill_part = self._skill_label(skill_id)
            detail = "" if tag == "heal_self" else f"  → 0x{target_id:X}"
            msg = f"[{prefix}] {skill_part}+{amount:,}{detail}"
            self.root.after(0, lambda m=msg, t=tag: self.log_heal(m, tag=t))

        # Heal 事件 (banner 累加)
        for tlv_start, target_id, heal_val in heals:
            skill_id = self._find_heal_shield_skill_id(payload, tlv_start)
            suffix, tag = self._classify_target(target_id)
            self.heal_total += heal_val
            if tag == "heal_self":
                self.heal_self += heal_val
            elif tag == "heal_ally":
                self.heal_ally += heal_val
            # heal_unknown → 只累加 heal_total,不分入 self/ally
            prefix = f"治療{suffix}"
            skill_part = self._skill_label(skill_id)
            detail = "" if tag == "heal_self" else f"  → 0x{target_id:X}"
            msg = f"[{prefix}] {skill_part}+{heal_val:,}{detail}"
            self.root.after(0, lambda m=msg, t=tag: self.log_heal(m, tag=t))

        if heals:
            self.root.after(0, self._update_heal_banner)

    def _classify_target(self, target_id):
        """依 local_player_id 判定 target 的分類。
        回傳 (label_suffix, tag_name):
          - 未學到 → ("?", "heal_unknown")  中性黃字
          - target == local → ("自己", "heal_self")  綠字
          - target != local → ("他人", "heal_ally")  藍字
        """
        if self.local_player_id is None:
            return ("?", "heal_unknown")
        if target_id == self.local_player_id:
            return ("自己", "heal_self")
        return ("他人", "heal_ally")

    def _skill_label(self, skill_id):
        """把 skill_id 包裝成日誌顯示用字串;None → 空字串,否則 '[技能名] '。"""
        if skill_id is None:
            return ""
        return f"[{format_skill_name(skill_id)}] "

    # ---- Skill ID Near scan (見 HEAL_SHIELD_SKILL_ID.md §4) ----
    def _find_heal_shield_skill_id(self, payload, tlv_start):
        """對 heal/shield 事件 (TLV size=24,總長 32) 在 ±300B 雙向視窗內
        搜尋伴生 skill TLV;回傳 skill_id 或 None。
        排名規則:min dist;同距離偏好 after 側 (見 §4.3)。
        """
        payload_len = len(payload)
        tlv_end = min(payload_len, tlv_start + 32)
        W = HEAL_SHIELD_SKILL_NEAR_WINDOW

        best_id = None
        best_dist = None      # 用 None 取代 inf,方便判斷
        best_is_after = False

        def consider(magic_off, is_after):
            nonlocal best_id, best_dist, best_is_after
            got = self._try_read_skill_tlv(payload, magic_off)
            if got is None:
                return
            skill_id, is_alt = got
            if is_alt and not self._alt_skill_follows_shield(payload, magic_off):
                return
            dist = abs(magic_off - tlv_start)
            if best_dist is None or dist < best_dist or (
                dist == best_dist and is_after and not best_is_after
            ):
                best_dist = dist
                best_id = skill_id
                best_is_after = is_after

        # After 窗:[tlv_end, tlv_end+W)
        for off in range(tlv_end, min(payload_len, tlv_end + W)):
            consider(off, is_after=True)

        # Before 窗:[max(0, tlv_start-W), tlv_start)
        for off in range(max(0, tlv_start - W), tlv_start):
            consider(off, is_after=False)

        return best_id

    def _try_read_skill_tlv(self, payload, magic_off):
        """檢查 payload[magic_off] 起是否為合法 skill TLV。
        回傳 (skill_id, is_alt) 或 None;is_alt=True 表示 0x1ADE8 (需再過 anti-decoy)。
        size 不符預期時回 None (呼叫方會繼續掃描下一個 offset,不會提前中止 Near)。
        """
        payload_len = len(payload)
        if magic_off + 8 > payload_len:
            return None
        cmd = payload[magic_off:magic_off+4]
        try:
            size = struct.unpack("<I", payload[magic_off+4:magic_off+8])[0]
        except Exception:
            return None
        # 經典型 0x4FEC size 35 — 無條件接受
        if cmd == SKILL_TLV_MAGIC and size == 35:
            if magic_off + 29 <= payload_len:
                try:
                    return (struct.unpack("<I", payload[magic_off+25:magic_off+29])[0],
                            False)
                except Exception:
                    return None
        # 替代型 0x1ADE8 size 36 — 需 anti-decoy 檢查
        # ⚠ 2026-09-09 改版:這裡的 0x1ADE8 與 anti-decoy 依據的 0x4EED 都還沒對出
        #   新值 (治癒/護盾樣本尚未錄到),因此這條分支目前等同停用。錄到樣本再更新。
        if cmd == b'\xe8\xad\x01\x00' and size == 36:
            if magic_off + 29 <= payload_len:
                try:
                    return (struct.unpack("<I", payload[magic_off+25:magic_off+29])[0],
                            True)
                except Exception:
                    return None
        return None

    def _alt_skill_follows_shield(self, payload, skill_magic_off):
        """anti-decoy:0x1ADE8 只有緊接在某個 0x4EED (size 24) 結束後 0..8 bytes
        才視為真正的 skill TLV,否則為 decoy 要拒絕。
        往前 64 bytes 搜 0x4EED 候選。
        """
        payload_len = len(payload)
        lo = max(0, skill_magic_off - ALT_SKILL_BACKSCAN)
        for o in range(lo, skill_magic_off):
            if o + 8 > payload_len:
                continue
            if payload[o:o+4] != b'\xed\x4e\x00\x00':
                continue
            try:
                size = struct.unpack("<I", payload[o+4:o+8])[0]
            except Exception:
                continue
            if size != 24:
                continue
            shield_end = o + 8 + 24
            gap = skill_magic_off - shield_end
            if 0 <= gap <= ALT_SKILL_MAX_GAP:
                return True
        return False

    def log_heal(self, text, tag=None):
        """寫入治癒日誌。tag 對應 heal_log_area 上定義的 tag 顏色:
          - "heal_self"    → 綠字 (自己)
          - "heal_ally"    → 藍字 (他人)
          - "heal_unknown" → 黃字 (尚未識別本地 ID)
          - None           → 一般白字 (系統/學習訊息)
        """
        self.heal_log_area.configure(state="normal")
        if tag:
            self.heal_log_area._textbox.insert("end", text + "\n", tag)
        else:
            self.heal_log_area.insert("end", text + "\n")
        self.heal_log_area.see("end")
        self.heal_log_area.configure(state="disabled")

    def _update_heal_banner(self):
        self.lbl_heal_total.configure(text=f"{self.heal_total:,}")
        self.lbl_heal_self.configure(text=f"{self.heal_self:,}")
        self.lbl_heal_ally.configure(text=f"{self.heal_ally:,}")

    def packet_callback(self, packet, gen=0):
        # 換網卡時舊執行緒可能還沒退出 — 世代不符就整包丟掉,避免重複處理
        if gen != self._sniff_gen:
            return
        if not (packet.haslayer(TCP) and packet.haslayer(IP)):
            return
        raw_payload = bytes(packet[TCP].payload)
        if not raw_payload:
            return
        # 身分偵測不受「開始/停止」與開發者模式影響:換地圖那一瞬間的
        # 0x4FFF/0x4E4F 只送一次,錯過就要等下次換圖,所以一律掃。
        # 訊息 body 跨封包接續,所以要依連線分流 — 混到別條連線的位元組會把串流解壓弄壞。
        ip_layer, tcp_layer = packet[IP], packet[TCP]
        conn_key = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport)
        self._scan_identity(raw_payload, conn_key)
        # 怪物登場包探針:目標按鈕的名字來源,發布版一樣要跑 (診斷 LOG 只有開發版看得到)。
        # 不受「開始/停止」影響 — 登場包只在進視野那一刻送,錯過就沒有名字了。
        if MONSTER_NAMES:
            self._mob_scan(raw_payload, conn_key)
        # Buff:一律掃進快取,不受「開始/停止」影響 —— ADD 一輩子只送一次,
        # 沒在收就永遠等不到 (同身分偵測的理由)。「按開始前不顯示」是
        # update_buff_list 那邊的事,不是這裡。
        # end 存的是絕對時間,所以按開始時剩餘秒數自然是對的:10 秒前拿到的
        # 30 秒 buff,按下去就顯示 20 秒。
        # 診斷 LOG 那一份輸出才看開發者模式,見 _buff_note
        self._buff_scan(raw_payload)
        if not self.is_monitoring:
            return
        if self.track_damage:
            # 走接續路徑:被切在 TCP segment 邊界的傷害事件才不會整筆漏掉
            self._dmg_feed(raw_payload, conn_key, tcp_layer.seq)
        if self.track_heal:
            self.parse_heal_shield(raw_payload)

    def _ensure_sniffer(self, restart=False):
        """確保攔截執行緒在跑。

        它獨立於「開始/停止」:身分偵測要在沒按開始時也能認出自己 (見
        packet_callback),所以程式一啟動就開始收,直到關閉為止。
        restart=True 用於換網卡 — 世代 +1 讓舊執行緒在下一個封包自行退出。
        """
        if restart:
            self._sniff_gen += 1
            self.sniff_thread = None
        if self.sniff_thread is not None and self.sniff_thread.is_alive():
            return
        gen = self._sniff_gen
        self.sniff_thread = threading.Thread(target=self.sniff_packets,
                                             args=(gen,), daemon=True)
        self.sniff_thread.start()

    def sniff_packets(self, gen=0):
        bpf_filter = self.sniff_filter
        try:
            sniff_kwargs = {
                "filter": bpf_filter,
                "prn": lambda pkt: self.packet_callback(pkt, gen),
                "store": 0,
                "stop_filter": lambda _: gen != self._sniff_gen,
            }
            # 若已由開機自動偵測 or 手動掃描選定網卡,就綁在那張;否則交給 scapy 自選
            if self.chosen_iface:
                sniff_kwargs["iface"] = self.chosen_iface
            # 預設不開混雜模式:我們只要自己這台機器的封包,關掉可避開部分
            # 網卡/驅動不允許 promiscuous 的情況。失敗才退回 scapy 預設。
            try:
                sniff(promisc=False, **sniff_kwargs)
            except Exception as e:
                self.root.after(0, lambda err=e: self.log(
                    f"⚠️ 非 promiscuous 模式擷取失敗 ({err}),改用預設模式重試"))
                sniff(**sniff_kwargs)
        except Exception as e:
            self.root.after(0, lambda err=e: self.log(f"❌ 攔截錯誤: {err}"))

    def start_monitoring(self):
        self.is_monitoring = True
        self.btn_start.configure(state="disabled")
        # 監控中把停止按鈕改成醒目的紅色
        self.btn_stop.configure(state="normal", fg_color="#d63031", hover_color="#b02a2c")

        # 每次按下開始都重新讀取 skills.ini,讓使用者修改後不用重啟程式
        global SKILL_NAMES, MERGE_GROUPS
        SKILL_NAMES, MERGE_GROUPS, conflicts, ini_errors = load_skill_config()
        if ini_errors:
            self.log_error(f"❌ 載入 {SKILL_CFG_NAME} 時發生錯誤:")
            for err in ini_errors:
                self.log_error(f"    • {err}")
        if SKILL_NAMES:
            self.log(f"=== 已載入 {len(SKILL_NAMES)} 個技能名稱 ({SKILL_CFG_NAME}) ===")
        else:
            self.log(f"=== 未載入 {SKILL_CFG_NAME},技能欄將顯示 hex ID ===")
        if MERGE_GROUPS:
            group_count = len(set(MERGE_GROUPS.values()))
            self.log(f"=== 已載入 {group_count} 個合併群組,涵蓋 {len(MERGE_GROUPS)} 個技能名稱 ===")
        for member, first, ignored in conflicts:
            self.log(f"⚠ 群組衝突:「{member}」已屬於「{first}」,忽略「{ignored}」的宣告")
        # effects.ini 同樣每次按開始重讀,讓使用者補了 buffId 不用重啟
        global EFFECT_NAMES, EFFECT_IGNORE
        EFFECT_NAMES, EFFECT_IGNORE, effect_errors = load_effect_names()
        for err in effect_errors:
            self.log_error(f"    • {err}")
        if EFFECT_NAMES:
            self.log(f"=== 已載入 {len(EFFECT_NAMES)} 個效果名稱 ({EFFECT_CFG_NAME})"
                     f",忽略清單 {len(EFFECT_IGNORE)} 筆 ===")
        else:
            self.log(f"=== 未載入 {EFFECT_CFG_NAME},Buff 欄將顯示 hex ID ===")
        # 解除凍結 → 面板改吃背景快取,把「按下去這一刻身上有的 buff」一次列出來。
        # 不清快取:清了就要等每個 buff 重新 ADD 才會再出現,而 ADD 一輩子只送一次
        self._buff_frozen_at = None
        self._buff_frozen_view = None
        # 存檔時的區間起點下界 (見 _buff_intervals)
        self._monitor_start_wall = time.time()

        # 已顯示中的技能排行列即時套用新名稱
        self.update_skill_ranking()

        self.log("=== 已啟動即時監控 ===")
        # 攔截執行緒通常在程式啟動時就跑起來了;這裡只是保險 (例如當初啟動失敗)
        self._ensure_sniffer()
        # 沒有角色 ID 就不會記任何傷害 — 開始的當下一定要讓使用者看到現況
        self._ident_status_line()

    def start_timer(self):
        """讀取分/秒輸入 → 清資料 → 啟動監控 → 開始倒數。
        0:00 或非數字輸入直接忽略;若已有計時進行中,舊計時會被取消再重啟。
        """
        try:
            m = int((self.timer_min_var.get() or "0").strip())
            s = int((self.timer_sec_var.get() or "0").strip())
        except ValueError:
            self.log("⚠ 計時輸入非數字,已忽略")
            return
        if m < 0 or s < 0:
            return
        total = m * 60 + s
        if total <= 0:
            return

        self._cancel_timer()  # 保險起見,先取消可能仍在跑的舊計時
        self.clear_data()
        if not self.is_monitoring:
            self.start_monitoring()

        self.timer_end_time = time.time() + total
        self._set_timer_button_running()
        self.log(f"=== 計時開始:{m:02d}:{s:02d} ===")
        self._tick_timer()

    def _tick_timer(self):
        """每 500ms 更新剩餘時間;歸零時自動停止監控。"""
        if self.timer_end_time is None:
            return
        remaining = self.timer_end_time - time.time()
        if remaining <= 0:
            # 先清狀態,再呼叫 stop_monitoring,避免 stop_monitoring 誤判為手動取消
            self.timer_end_time = None
            self.timer_after_id = None
            self.lbl_timer_remaining.configure(text="已結束", text_color="#ff9944")
            self._set_timer_button_idle()
            if self.is_monitoring:
                self.stop_monitoring()
            self.log("=== 計時結束,已自動停止監控 ===")
            return
        m = int(remaining) // 60
        s = int(remaining) % 60
        self.lbl_timer_remaining.configure(text=f"剩餘 {m:02d}:{s:02d}",
                                            text_color="#88ccff")
        self.timer_after_id = self.root.after(500, self._tick_timer)

    def _cancel_timer(self):
        """取消計時 (清 after callback + 清狀態 + 清顯示 + 按鈕還原閒置樣式)。"""
        if self.timer_after_id is not None:
            try:
                self.root.after_cancel(self.timer_after_id)
            except Exception:
                pass
            self.timer_after_id = None
        self.timer_end_time = None
        self.lbl_timer_remaining.configure(text="")
        self._set_timer_button_idle()

    def _set_timer_button_running(self):
        """切成「計時停止」紅色樣式,command 指向手動停止 handler。"""
        self.btn_timer.configure(text="⏱ 計時停止",
                                 fg_color="#d63031", hover_color="#b02a2c",
                                 command=self._stop_timer_button)

    def _set_timer_button_idle(self):
        """還原為「計時開始」預設綠色樣式。"""
        self.btn_timer.configure(text="⏱ 計時開始",
                                 fg_color=self._btn_timer_idle_fg,
                                 hover_color=self._btn_timer_idle_hover,
                                 command=self.start_timer)

    def _stop_timer_button(self):
        """使用者按下「計時停止」:取消計時並停止監控 (與計時歸零的行為一致)。"""
        was_running = self.timer_end_time is not None
        self._cancel_timer()
        if self.is_monitoring:
            self.stop_monitoring()
        if was_running:
            self.log("=== 計時已手動停止 ===")

    def stop_monitoring(self):
        self.is_monitoring = False
        self.btn_start.configure(state="normal")
        # 停止後把停止按鈕還原為預設樣式
        self.btn_stop.configure(state="disabled",
                                fg_color=self._btn_stop_default_fg,
                                hover_color=self._btn_stop_default_hover)
        # 若在計時中被手動停止,一併取消計時 (計時自然結束時 timer_end_time 已被清 None,
        # 這個分支不會被誤觸)
        if self.timer_end_time is not None:
            self._cancel_timer()
            self.log("=== 計時已隨監控停止取消 ===")
        # 停止 → 面板定格成此刻的快照。逐筆 dict(v) 是必要的:快取在背景還會繼續
        # 更新層數/秒數,共用同一個 dict 的話凍結畫面會被偷偷改掉
        self._buff_frozen_at = time.monotonic()
        self._buff_frozen_view = {k: dict(v) for k, v in self.active_buffs.items()}
        self.log("=== 已停止監控 ===")

    # ================================================
    # 存檔 / 讀取 (當前數據快照)
    #   格式為 JSON:target_stats 本來就是巢狀 dict,直接對應;人可讀,
    #   使用者能開檔比對。不用 pickle —— 讀檔等於執行任意程式碼,
    #   從別人手上拿到的存檔就會是攻擊面。
    #
    #   衍生數字 (DPS / 覆蓋率 / 技能排行 / 佔比) 一律不存:它們都是
    #   update_dps / update_coverage / update_skill_ranking 從桶內原始累積量
    #   現算的,存下去只會多出一份可能對不上的真相。
    # ================================================
    @staticmethod
    def _enc_target_key(key):
        """target_stats 的 key → JSON 字串。JSON 的 object key 只能是字串,
        而這裡是 TARGET_ALL (str) 與 target_id (int) 混用。int 寫成 hex,
        跟 UI / 開發者 log 的 0x + 8 碼慣例一致。
        """
        return key if isinstance(key, str) else f"0x{key:08X}"

    @staticmethod
    def _dec_target_key(key):
        return key if key == TARGET_ALL else int(key, 16)

    def _enc_entity_names(self):
        """有桶且認得出名字的目標 → {"0x........": [名字, 序號或 null]}。"""
        out = {}
        for key in self.target_stats:
            if key == TARGET_ALL:
                continue
            entry = self._entity_names.get(key) or self._loaded_names.get(key)
            if entry is None:
                continue
            name, ordinal = entry
            if key in self._entity_names and self._name_count[name] <= 1:
                ordinal = None
            out[f"0x{key:08X}"] = [name, ordinal]
        return out

    @staticmethod
    def _dec_entity_names(raw):
        """存檔的 entity_names → {target_id(int) → (名字, 序號或 None)}。
        舊存檔沒有這欄,缺了就當空的 (目標欄位退回 hex);單列壞掉只跳過該列 ——
        名字是顯示用的,不值得為它讓整份存檔讀不進來。
        """
        out = {}
        for k, v in (raw or {}).items():
            try:
                name, ordinal = v[0], v[1]
                out[int(k, 16)] = (str(name),
                                   None if ordinal is None else int(ordinal))
            except (ValueError, TypeError, IndexError, KeyError):
                continue
        return out

    @staticmethod
    def _enc_skill_map(mapping):
        """{skill_id(int) → v} → {"0x........" → v};理由同 _enc_target_key。"""
        return {f"0x{sid:08X}": v for sid, v in mapping.items()}

    @staticmethod
    def _dec_skill_map(mapping):
        return {int(k, 16): v for k, v in mapping.items()}

    # 桶內以 skill_id 為 key 的欄位,存/讀兩邊都要走一次 hex 轉換
    _SKILL_KEYED = ("skill_damage", "skill_hits", "skill_cov_hits",
                    "skill_cov_main", "skill_tags", "skill_split")

    def _enc_bucket(self, b):
        d = dict(b)
        for name in self._SKILL_KEYED:
            d[name] = self._enc_skill_map(b[name])
        return d

    def _dec_bucket(self, d):
        """讀回單一統計桶。缺欄位一律沿用 _new_stat_bucket() 的預設值,
        這樣日後往桶裡加欄位時舊存檔仍讀得進來,不必為此升 format 版號。
        """
        b = self._new_stat_bucket()
        for name in ("damage", "hits", "cov_hits", "cov_main"):
            b[name] = int(d.get(name, 0))
        tags = d.get("tags") or {}
        for name in COVERAGE_TAGS:
            b["tags"][name] = int(tags.get(name, 0))
        for name in self._SKILL_KEYED:
            b[name] = self._dec_skill_map(d.get(name) or {})
        # first/last 是 time.time() 的絕對時間戳,照存不動 —— DPS 只用差值,
        # 跨天讀回來仍然正確,而且之後要顯示「這場打了多久」就有現成資料
        b["first"] = d.get("first")
        b["last"] = d.get("last")
        return b

    def _buff_intervals(self):
        """存檔用:自己身上 buff 的 (buffId, 名稱, 起, 迄, 層數) 區間,牆鐘秒。

        起點一律夾到「按下開始」那一刻 —— 開始前就掛在身上的持久型 buff,
        它的 start_wall 可能是幾十分鐘前,原樣寫進存檔會讓圖表算出超過 100%
        的覆蓋率。整段都在開始之前的直接跳過。

        兩個來源合起來 —— 已經 REM 的走 buff_history,還掛在身上的在這裡補一段:
          * 無限持續:沒有排定的結束時間,收在「存檔當下」
          * 有限:收在排定結束時間,但不得超過存檔當下 (還沒到期就是還沒到期)
        沒到期卻已經被 REM 的、以及到期了沒收到 REM 的,兩種都自然落在正確長度。
        """
        now = time.time()
        # 起點下界:按下開始的那一刻。沒按過開始就不夾 (沒有場次可言)
        floor = self._monitor_start_wall
        rows = []
        for bid, nm, st, en, stk in list(self.buff_history):
            if floor is not None:
                if en <= floor:
                    continue          # 整段都在開始之前,與這一場無關
                st = max(st, floor)
            rows.append((bid, nm, st, en, stk))
        me = self.ident_self_entity
        for info in self.active_buffs.values():
            if me is None or info["owner"] != me:
                continue
            end = now if info["infinite"] else min(now, info["end_wall"])
            start = info["start_wall"]
            if floor is not None:
                if end <= floor:
                    continue
                start = max(start, floor)
            # 牆鐘可能被 NTP / 時區調整往回撥,那會撞出「迄早於起」的區間。
            # 夾一下 —— 圖表畫到負寬度的長條會直接消失,查起來只會一頭霧水
            rows.append((info["buff_id"], info["name"], start, max(start, end),
                         info["stacks"]))
        rows.sort(key=lambda r: r[2])
        return rows

    def _snapshot_dict(self):
        """把目前狀態序列化成可寫入 JSON 的 dict。
        不存的東西:local_player_id / 身分綁定 / chosen_iface / settings /
        計時器狀態 —— 那些是「當前執行環境」而非數據,讀檔覆蓋會讓收包行為錯亂。
        """
        return {
            "format": SAVE_FORMAT_VERSION,
            "app_version": VERSION_STR,   # 只做顯示/診斷,相容判斷看 format
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "damage": {
                "target_order": [f"0x{t:08X}" for t in self.target_order],
                "selected_target": self._enc_target_key(self.selected_target),
                "target_stats": {self._enc_target_key(k): self._enc_bucket(v)
                                 for k, v in self.target_stats.items()},
                # 時間序列:一筆一列陣列,欄位順序即 damage_events 的 tuple 順序。
                # ts 只留到毫秒 (float 全精度會讓每筆多出十幾個字元,對曲線無意義)
                "events": [[round(ts, 3), f"0x{tid:08X}",
                            None if sid is None else f"0x{sid:08X}", dmg, flags]
                           for ts, tid, sid, dmg, flags in self.damage_events],
                # 目標名字:只存「這份存檔真的有桶的目標」,整張 _entity_names
                # 大多是路過沒打到的怪。序號在這裡就定死 (null = 存檔當下全場
                # 只有這一隻),讀檔端不重算 —— eid 換一次執行就換了,重算沒有意義。
                "entity_names": self._enc_entity_names(),
            },
            # 治癒只存三個總量:逐行治癒日誌目前沒有結構化緩衝 (直接寫進 widget),
            # 要一起存得先改 parse_heal_shield 的輸出路徑,這版不動
            "heal": {"total": self.heal_total,
                     "self": self.heal_self,
                     "ally": self.heal_ally},
            # Buff 持續軸:圖表程式用它畫甘特條。時間與 damage.events 同一個
            # 牆鐘,所以圖表可以直接拿 events 的 t0 當原點對齊
            "buffs": [[f"0x{bid:08X}", nm, round(st, 3), round(en, 3), stk]
                      for bid, nm, st, en, stk in self._buff_intervals()],
            "log_entries": [
                {"text": e["text"],
                 "target": None if e["target"] is None else f"0x{e['target']:08X}",
                 "tags": list(e["tags"]),
                 "error": bool(e["error"]),
                 "color": e.get("color")}
                for e in self.log_entries],
        }

    def _parse_snapshot(self, raw):
        """驗證並轉換存檔內容。任何欄位有問題就丟例外,由呼叫端統一報錯 ——
        重點是「全部解析成功才回傳」,呼叫端才能保證壞檔不會把現有數據毀掉一半。
        """
        if not isinstance(raw, dict):
            raise ValueError("內容不是 JSON 物件")
        fmt = raw.get("format")
        if fmt != SAVE_FORMAT_VERSION:
            raise ValueError(f"格式版號 {fmt} 不支援 (本程式支援 {SAVE_FORMAT_VERSION})")
        dmg = raw.get("damage") or {}
        stats_raw = dmg.get("target_stats")
        if not isinstance(stats_raw, dict) or TARGET_ALL not in stats_raw:
            raise ValueError("缺少傷害統計資料")
        stats = {self._dec_target_key(k): self._dec_bucket(v)
                 for k, v in stats_raw.items()}
        # target_order 只留 target_stats 真的有桶的 id,否則按鈕列會出現
        # 點下去查無資料的空目標
        order = [t for t in (int(x, 16) for x in (dmg.get("target_order") or []))
                 if t in stats]
        selected = self._dec_target_key(dmg.get("selected_target") or TARGET_ALL)
        if selected != TARGET_ALL and selected not in stats:
            selected = TARGET_ALL
        # 時間序列:V0.53 以前的存檔沒有這欄,缺了就當空的 (讀得進來,只是畫不出曲線)
        events = [(float(ts), int(tid, 16),
                   None if sid is None else int(sid, 16), int(dmgv), int(flags))
                  for ts, tid, sid, dmgv, flags in (dmg.get("events") or [])]
        heal = raw.get("heal") or {}
        entries = []
        for e in (raw.get("log_entries") or []):
            tgt = e.get("target")
            entries.append({"text": str(e.get("text", "")),
                            "target": None if tgt is None else int(tgt, 16),
                            "tags": tuple(e.get("tags") or ()),
                            "error": bool(e.get("error")),
                            "color": e.get("color")})
        return {
            "saved_at": raw.get("saved_at") or "?",
            "target_stats": stats,
            "entity_names": self._dec_entity_names(dmg.get("entity_names")),
            "target_order": order,
            "selected_target": selected,
            "events": events,
            "heal": (int(heal.get("total", 0)), int(heal.get("self", 0)),
                     int(heal.get("ally", 0))),
            "log_entries": entries,
        }

    def save_snapshot(self):
        """把當前所有統計寫成 Save/MMScribe_<日期時間>.json。
        檔名用 %Y%m%d_%H%M%S:字串排序即時間排序,且不含 Windows 禁用的 ':'。
        """
        try:
            data = self._snapshot_dict()
        except Exception as exc:
            self.log_error(f"❌ 建立存檔內容失敗:{exc}")
            return
        save_dir = get_save_dir()
        name = SAVE_FILE_PREFIX + time.strftime("%Y%m%d_%H%M%S")
        try:
            os.makedirs(save_dir, exist_ok=True)
            with open(os.path.join(save_dir, name + SAVE_FILE_EXT),
                      "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except (OSError, TypeError, ValueError) as exc:
            self.log_error(f"❌ 存檔失敗:{exc}")
            return
        self.log(f"=== 已存檔 {name} ===")
        self.refresh_save_list(select=name)

    def refresh_save_list(self, select=None):
        """掃 Save/ 內的檔名填進下拉選單,新的排前面。
        刻意不 parse 檔案內容 —— 檔案一多逐檔 parse 會拖慢啟動,真正的驗證留給
        load_snapshot();壞檔的代價只是一次失敗提示,不是每次開機都變慢。
        """
        names = []
        try:
            for fn in os.listdir(get_save_dir()):
                if fn.startswith(SAVE_FILE_PREFIX) and fn.endswith(SAVE_FILE_EXT):
                    names.append(fn[:-len(SAVE_FILE_EXT)])
        except OSError:
            pass   # 資料夾還沒建立 = 還沒存過檔,不是錯誤
        names.sort(reverse=True)   # 檔名含 %Y%m%d_%H%M%S,字串排序 = 時間排序
        values = names or [SAVE_COMBO_EMPTY]
        self.save_combo.configure(values=values)
        if select and select in names:
            self.save_file_var.set(select)
        elif self.save_file_var.get() not in values:
            # 原本選的檔被刪掉 (或第一次掃描) → 退回最新的一筆
            self.save_file_var.set(values[0])

    def load_snapshot(self):
        """讀取下拉選單選中的存檔:覆蓋當前所有數據,並進入純檢視模式。"""
        name = self.save_file_var.get()
        if not name or name == SAVE_COMBO_EMPTY:
            self.log_error("❌ 尚未選擇存檔")
            return
        path = os.path.join(get_save_dir(), name + SAVE_FILE_EXT)
        # 先完整解析到記憶體,全部通過才動現有狀態
        try:
            with open(path, "r", encoding="utf-8") as f:
                parsed = self._parse_snapshot(json.load(f))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            self.log_error(f"❌ 讀取存檔失敗:{exc}")
            self.refresh_save_list()   # 檔案可能已被手動刪除,順手重掃
            return
        # 覆蓋是不可逆的:當前有數據才攔一道確認,空的就直接讀
        if self.target_stats[TARGET_ALL]["hits"] > 0:
            self._show_load_confirm(name, parsed)
        else:
            self._apply_snapshot(name, parsed)

    def _show_load_confirm(self, name, parsed):
        """覆蓋整個視窗的確認框 (作法同 show_disclaimer)。已顯示時不重複建立。"""
        if getattr(self, "_load_confirm_overlay", None) is not None:
            return
        overlay = ctk.CTkFrame(self.root, fg_color="#0a0a0a", corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._load_confirm_overlay = overlay

        box = ctk.CTkFrame(overlay, fg_color="#1a1a1a", corner_radius=10)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(box, text="⚠ 覆蓋目前數據?",
                     font=(FONT_UI, 15), text_color="#ff9944").pack(padx=24, pady=(18, 6))
        ctk.CTkLabel(box, justify="left", font=(FONT_UI, 12), text_color="#cccccc",
                     text=(f"即將載入:{name}\n"
                           f"存檔時間:{parsed['saved_at']}\n\n"
                           "目前尚未存檔的數據將被覆蓋且無法復原。")
                     ).pack(padx=24, pady=(0, 14))
        btn_row = ctk.CTkFrame(box, fg_color="transparent")
        btn_row.pack(padx=24, pady=(0, 18))

        def confirm():
            self._hide_load_confirm()
            self._apply_snapshot(name, parsed)

        ctk.CTkButton(btn_row, text="取消", width=90, corner_radius=8,
                      fg_color="#4a4a4a", hover_color="#6a6a6a",
                      command=self._hide_load_confirm).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="覆蓋並讀取", width=110, corner_radius=8,
                      fg_color="#c94a4a", hover_color="#e05a5a",
                      command=confirm).pack(side="left", padx=6)

    def _hide_load_confirm(self):
        overlay = getattr(self, "_load_confirm_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self._load_confirm_overlay = None

    def _apply_snapshot(self, name, parsed):
        """停止監控 → 歸零 → 灌入存檔 → 重畫 → 鎖成純檢視模式。"""
        # 攔截執行緒 (_ensure_sniffer) 是常駐的,身分偵測靠它一直收,不能停;
        # is_monitoring=False 就足以讓 parse_payload 停止累加。
        if self.is_monitoring:
            self.stop_monitoring()
        self._reset_stats(clear_dev=False)

        self.target_stats = parsed["target_stats"]
        self._loaded_names = parsed["entity_names"]
        self.target_order[:] = parsed["target_order"]
        self.selected_target = parsed["selected_target"]
        self.heal_total, self.heal_self, self.heal_ally = parsed["heal"]
        self.log_entries.extend(parsed["log_entries"])
        self.damage_events.extend(parsed["events"])

        self._refresh_target_options()
        self._refresh_stats_view()
        self._render_log()
        self._update_heal_banner()
        self._set_view_only(True)
        self.log(f"=== 已讀取存檔 {name} (存於 {parsed['saved_at']}) ===")
        self.log("=== 純檢視模式:按「🧹 清除」可恢復偵測 ===")

    def _set_view_only(self, on):
        """純檢視模式:讀取存檔後鎖住「開始 / 計時」。
        理由:存檔的 first/last 是當時的絕對時間戳,直接續接會讓 DPS 分母變成
        好幾天,數字無聲無息地歸零。與其偷偷重設起點,不如把語意講清楚 ——
        讀檔就是看數據,要重新偵測請先按「清除」。
        """
        self.view_only = on
        # 監控進行中時「開始」本來就該是 disabled,不能被這裡放行
        self.btn_start.configure(
            state="disabled" if (on or self.is_monitoring) else "normal")
        self.btn_timer.configure(state="disabled" if on else "normal")

    def _reset_stats(self, clear_dev=True):
        """把統計 / 日誌 / 治癒總量全部歸零,不寫任何日誌訊息。
        clear_data 與「讀取存檔」共用 —— 後者傳 clear_dev=False,因為診斷 LOG
        記的是「這次執行」的收包狀況,不屬於存檔要覆蓋的數據。
        """
        # === 傷害端 ===
        # 所有目標桶一起丟掉並退回 All,下一場重新累積
        self.target_stats = {TARGET_ALL: self._new_stat_bucket()}
        self.target_order.clear()
        self.selected_target = TARGET_ALL
        self._loaded_names = {}   # 存檔的名字跟著存檔的統計一起走
        self._refresh_target_options()

        self.update_skill_ranking()
        self.lbl_total_dmg.configure(text="0")
        self.lbl_dps.configure(text="0")
        self.lbl_target_hits.configure(text="0 筆")
        self.update_coverage()

        # === 治癒端 ===
        # 注意:local_player_id 不清零 — 一旦學到就整個 session 沿用,
        # 避免使用者手動清資料後又要重新等一次 502A 才能區分自己/隊友
        self.heal_total = 0
        self.heal_self = 0
        self.heal_ally = 0
        self._update_heal_banner()

        # 事件緩衝與畫面一起清 (只清 widget 的話切換目標會把舊事件叫回來)
        self.log_entries.clear()
        self.damage_events.clear()
        # 已結束的 buff 區間與傷害事件同進退 (都是「這一場的記錄」)。
        # active_buffs 不清 —— 那是當下的狀態,見 clear_data 的註解
        self.buff_history.clear()
        # 這一場從現在重新起算,區間起點的下界跟著移過來
        self._monitor_start_wall = time.time()
        self._render_log()

        self.heal_log_area.configure(state="normal")
        self.heal_log_area.delete("1.0", "end")
        self.heal_log_area.configure(state="disabled")

        # 診斷視窗可能沒開;緩衝與底部單行也要一起清,免得重開後舊資料又冒出來
        if clear_dev:
            self._dev_lines.clear()
            try:
                self.dev_strip.configure(text=DEV_STRIP_EMPTY,
                                         text_color=DEV_STRIP_IDLE_COLOR)
            except Exception:
                pass
            if self.dev_log_area is not None:
                self.dev_log_area.configure(state="normal")
                self.dev_log_area.delete("1.0", "end")
                self.dev_log_area.configure(state="disabled")

    def clear_data(self):
        self._reset_stats()
        # 「清除」是離開純檢視模式的唯一出口 (見 _set_view_only)
        self._set_view_only(False)
        self.log("=== 數據已歸零 ===")
        # 注意:身分/綁定不清零 — 清了就得等下次換地圖才會再認出自己,
        # 中間所有傷害都不會被記錄 (同 local_player_id 的處置)。
        # **buff 快取同理,也不清** — 「清除」清的是統計,buff 是當下的狀態不是統計;
        # 而且 ADD 一輩子只送一次,清掉的無限持續 buff 永遠回不來 (實測踩過)。
        # 換場景造成的殘留不必擔心:entityId 會變,update_buff_list 用
        # owner == ident_self_entity 過濾,舊實體的 buff 自然就不顯示了。
        # 只把「本場尚未綁定」的診斷警告重新武裝,並把目前狀態重寫一行到日誌。
        self._ident_scene_warned = False
        self._ident_status_line()


if __name__ == "__main__":
    root = ctk.CTk()
    app = LiveDamageMonitor(root)
    root.mainloop()
