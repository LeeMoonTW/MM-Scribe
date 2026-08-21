"""
瑪奇即時傷害監控 - customtkinter 版
需求: pip install customtkinter scapy
抓封包需要提權:Windows 以系統管理員執行;macOS 需 root 或已放寬 /dev/bpf* 權限。

支援 Windows 10/11 與 macOS (Apple Silicon / Intel)。
macOS 上遊戲為 iOS App on Mac,流量直接走實體網卡,抓法與 Windows 端相同。

打包說明:
  Windows 開發版 (顯示開發者選項):
    python -m PyInstaller --onefile --noconsole --collect-data customtkinter MabinogiMobileScribe_Beta.py

  Windows 發布版 (隱藏開發者選項):
    type nul > RELEASE.marker
    python -m PyInstaller --onefile --noconsole --collect-data customtkinter --add-data "RELEASE.marker;." MabinogiMobileScribe_Beta.py

  macOS (--add-data 分隔符是 ':' 不是 ';'):
    touch RELEASE.marker
    python -m PyInstaller --windowed --collect-data customtkinter --add-data "RELEASE.marker:." MabinogiMobileScribe_Beta.py

  程式啟動時會偵測執行檔內是否包含 RELEASE.marker 檔案,
  存在則隱藏開發者選項按鈕(釋出給他人使用)。
"""
import collections
import configparser
import json
import os
import struct
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
VERSION_STR = "Beta V0.52"
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
# 攻擊日誌保留筆數上限 (切換目標時要依此緩衝重畫整份,故需有上界)
LOG_HISTORY_MAX = 5000
SKILL_CFG_NAME = "skills.ini"
SETTINGS_CFG_NAME = "settings.ini"
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
# 傷害旗標區 (見 MM_Scribe_PacketNotes_Damage.md §4)
# 0x51E9 事件的旗標是連續 7 bytes: payload[offset+41 .. offset+47]
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
IDENT_SELF_TYPE = 0x4FFF
IDENT_APPEAR_TYPE = 0x4E4F
IDENT_SELF_MIN_SIZE = 1024        # A 訊息很大;太小的多半是對錯位撞出來的假標頭
IDENT_SELF_FEED_MAX = 1 << 18     # 餵超過這麼多 bytes 還吐不出 8 bytes 就放棄本則
IDENT_APPEAR_MIN_SIZE = 64        # B 訊息實測 1100~1300 bytes;放寬下限只擋明顯假的
IDENT_APPEAR_HEAD_BYTES = 4096    # B 訊息解壓前幾 bytes,拿來找 characterId
IDENT_APPEAR_CACHE_MAX = 64       # 身分還沒到手前,先留這麼多筆 B 訊息回頭比對
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
MOB_HEAD_SENTINEL = b"\x03\x00\x00\x00"   # 前哨
MOB_TAIL_SENTINEL = b"\x00\x00\x00\x00"   # 後哨
# 掃到這三個一律當沒掃到,繼續往前找 (對照表裡確認過沒有這三個鍵)
MOB_CODE_IGNORE = {"00000000", "01000000", "FFFFFFFF"}
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


def load_monster_names():
    """讀怪物碼 → 名字對照表 (5,743 筆,鍵是 8 字元大寫 hex)。

    只有開發者模式的怪物探針用得到,讀不到就整個功能靜默關閉。
    原始碼佈局下檔案還放在 Note/Ref/,所以多找一層。
    """
    tried = set()
    for path in (get_external_path(MOB_NAME_FILE),
                 get_resource_path(MOB_NAME_FILE),
                 os.path.join(os.path.dirname(os.path.dirname(
                     os.path.abspath(__file__))), "Note", "Ref", MOB_NAME_FILE)):
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


# 發布版沒有診斷 LOG 的 UI 入口,不必花時間 parse 200KB JSON
MONSTER_NAMES = {} if RELEASE_BUILD else load_monster_names()


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


def load_settings():
    """讀取 settings.ini,回傳 dict。缺檔或解析失敗回傳預設值。"""
    defaults = {
        "font_scale": FONT_SCALE_DEFAULT,
        "track_damage": True,
        "track_heal": False,
        "popout_log": False,
        "popout_skill": False,
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
        result["popout_log"] = parser.getboolean("Layout", "popout_log", fallback=False)
    except (ValueError, configparser.Error):
        pass
    try:
        result["popout_skill"] = parser.getboolean("Layout", "popout_skill", fallback=False)
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
    }
    parser["Layout"] = {
        "popout_log": "true" if settings.get("popout_log", False) else "false",
        "popout_skill": "true" if settings.get("popout_skill", False) else "false",
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            parser.write(f)
    except Exception:
        pass


def format_skill_name(skill_id):
    """把 skill_id 轉為顯示名稱。
    - 0x00000000  → 「疑似符文傷害」(依 PacketNotes §5,符文附加傷害的 skill ID 為 0)
    - SKILL_NAMES 有對應 → 使用者命名
    - 其他        → 顯示 hex ID
    """
    if skill_id == 0:
        return "疑似符文傷害"
    return SKILL_NAMES.get(skill_id) or f"0x{skill_id:08X}"


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


IP_FILTER_NET = "43.0.0.0/8"
HIGHLIGHT_OPTIONS = ["無", "爆擊", "強擊", "破防", "無防備", "連擊", "多重打擊", "追擊",
                     "迎擊"]

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
        # 初始高度 780;每個 popout 中的 pane 從初值扣 200,啟動就用正確高度,
        # 不能在 __init__ 尾端做 delta 調整 — 那時 winfo_height() 因視窗尚未 realize
        # 回傳 1,dcalc 後會被 clamp 到 200 → 主視窗變超小、看不到開始按鈕
        # 340 是「dmg_banner + 3 條控制列 + status_bar + padding」的合理下限,
        # 保證兩個都 popout 時也看得到計時器那排
        initial_h = 780
        if self.settings.get("popout_log", False):
            initial_h -= 200
        if self.settings.get("popout_skill", False):
            initial_h -= 200
        initial_h = max(340, initial_h)
        self.root.geometry(f"500x{initial_h}")

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

        # 攻擊事件緩衝:切換目標時要重畫日誌,所以每筆都要留下結構化紀錄。
        # deque(maxlen) 超量會自動丟最舊的,不必手動修剪。
        self.log_entries = collections.deque(maxlen=LOG_HISTORY_MAX)

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

        # 計時器:end_time 為 None 表示無倒數;after_id 用於取消已排程的 tick
        self.timer_end_time = None
        self.timer_after_id = None

        # 追蹤模式旗標 (由 settings 載入,可從設定畫面切換)
        self.track_damage = self.settings["track_damage"]
        self.track_heal = self.settings["track_heal"]
        self.track_damage_var = tk.BooleanVar(value=self.track_damage)
        self.track_heal_var = tk.BooleanVar(value=self.track_heal)

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
        self._dev_lines = collections.deque(maxlen=DEV_LOG_MAX)

        # 提前建立 collapse 狀態與 merge_var,讓 pane 重建 (dock/popout) 時值可延續
        self.log_collapsed = False
        self._prev_height = None
        self.skill_collapsed = False
        self.merge_var = tk.BooleanVar(value=False)

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
        self._build_log_pane(root)
        self._build_skill_pane(root)

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

        # 依 track_damage / track_heal 旗標,把 banner + pane 一次性 pack 到位
        self._apply_tracking_mode()

        # 開啟後自動在背景掃描一次收包網卡,結果會設到 self.chosen_iface
        # 500ms 延遲讓主視窗先完全渲染出來。
        # macOS 會先確認有沒有 BPF 權限 — 沒有的話掃描每張網卡都只會失敗,
        # 不如先把權限問題解決掉再掃。
        self.root.after(500, self._start_capture_access_flow)

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
                                        font=(FONT_LOG, 13), corner_radius=0)
        # 折疊狀態下不 pack log_area,由 toggle_log_collapse 處理
        if not self.log_collapsed:
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_area._textbox.tag_config("highlight", foreground="#ff4d4d")
        # 角色 ID 狀態列:取得後綠字 (未取得走 highlight 紅字)
        self.log_area._textbox.tag_config("ident_ok", foreground="#4dd471")
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
                                                     fg_color="#242424")
        if not self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
        self.skill_pane.bind("<Enter>", self._skill_area_enter)
        self.skill_pane.bind("<Leave>", self._skill_area_leave)
        # 舊 row widgets 已隨舊 pane 銷毀,清空 dict;update_skill_ranking 會依
        # skill_damage 重建列
        self.skill_rows = {}
        return self.skill_pane

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
        self._build_log_pane(self.root)
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
        self._build_skill_pane(self.root)
        self.update_skill_ranking()

    def _build_dev_pane(self, parent):
        """建立診斷 LOG 面板 (只會被 _popout_dev 呼叫,parent 恆為 Toplevel)。"""
        self.dev_pane = ctk.CTkFrame(parent, corner_radius=0)
        ctk.CTkLabel(self.dev_pane, text="🛠 診斷 LOG",
                     font=(FONT_UI, 11)).pack(anchor="w", padx=10, pady=(6, 0))
        # 診斷行很長 (flags 7 bytes + 技能 + DoT + 候選),用 none 不折行,靠橫向捲軸看完整
        self.dev_log_area = ctk.CTkTextbox(self.dev_pane, wrap="none", font=(FONT_MONO, 12),
                                           corner_radius=0)
        self.dev_log_area.pack(fill="both", expand=True, padx=6, pady=6)
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
        if self._dev_lines:
            self.dev_log_area.configure(state="normal")
            self.dev_log_area.insert("1.0", "\n".join(self._dev_lines) + "\n")
            self.dev_log_area.see("end")
            self.dev_log_area.configure(state="disabled")
        # 主視窗如果目前是置頂,新開的 popout 也要一起置頂
        self._apply_topmost_all()

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
        - 中段 pane (log_pane, skill_pane, heal_log_pane) 全部 forget 後
          按順序 pack 於末端 (list 尾端 = 視覺上位於控制列下方)
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
        if not self.popout_log:
            self.log_pane.pack_forget()
        if not self.popout_skill:
            self.skill_pane.pack_forget()
        self.heal_log_pane.pack_forget()

        if self.track_damage:
            # 目標篩選同時作用於看板/技能排行/日誌,只要有追蹤傷害就顯示,
            # 不受 popout_log 影響
            self.target_row.pack(fill="x", padx=10, pady=(0, 3))
            if not self.popout_log:
                self.log_pane.pack(fill="both", expand=True, padx=10, pady=(3, 3))
            if not self.popout_skill:
                self.skill_pane.pack(fill="both", expand=True, padx=10, pady=(0, 3))
        if self.track_heal:
            self.heal_log_pane.pack(fill="both", expand=True, padx=10, pady=(0, 3))
        # 底部診斷區塊不參與這裡的重排 (side="bottom",__init__ 內一次 pack 到底)

        # 依當前佈局重算 minsize,確保 status_bar 不會被 log/skill/heal 這些
        # expand=True 的面板擠掉。用 after(0) 讓 Tk 完成本次 pack 再量高度
        self.root.after(0, self._refresh_minsize)

    def _refresh_minsize(self):
        """依「當前顯示的 banner + 3 條控制列 + status_bar」總高度,
        算出最小視窗高度並套用。
        - winfo_reqheight 回傳實際像素 (含 CTk scaling),要除回 font_scale 變成邏輯像素
        - **必須走 CTk 的 minsize()**,不能用 wm_minsize:CTk 會記住 minsize() 給的值,
          在之後的 scaling / Configure 事件把它重新套一次,直接寫 wm_minsize 會被蓋掉
          (實測:啟動後查到的仍是 __init__ 裡那組 400x180)
        """
        self.root.update_idletasks()
        parts = [self.ctrl_row1, self.ctrl_row2, self.ctrl_row3, self.status_bar]
        # 底部診斷區塊是常駐的 (發布版除外),最小高度要把它算進去
        if self.dev_strip.winfo_manager():
            parts.append(self.dev_strip)
        if self.track_damage:
            parts.append(self.dmg_banner)
            parts.append(self.target_row)
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
                        pkts = _sniff(iface=iface_key,
                                      filter=f"ip net {IP_FILTER_NET} and tcp",
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
        """把掃描結果套用到 self.chosen_iface,之後 sniff() 就會綁這張卡。"""
        prev = self.chosen_iface
        self.chosen_iface = None if iface_dict is None else iface_dict.get("name")
        # 攔截執行緒是常駐的 (見 _ensure_sniffer),換卡要重開一條才會綁到新的
        if self.chosen_iface != prev:
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
            if status in ("ok", "warn"):
                self.log(f"  {title}")

        def on_done(best_iface, hits):
            if best_iface is None:
                self.log("=== 未偵測到目標網段封包,將使用 scapy 預設介面 ===")
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
                    "warn", "掃描結束:所有介面都沒收到目標封包",
                    "可能原因:",
                    "  1. 遊戲未連線 / 未啟動",
                    "  2. 目標伺服器不在監控範圍內",
                    "  3. 沒有以系統管理員身分執行 → sniff 靜默失敗",
                    "  4. 防毒/防火牆阻擋")
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

        ctk.CTkLabel(track_section,
                     text="※ 攻擊數值/治癒數值可同時勾選;至少留一個開啟以免主畫面空白\n"
                          "※ 攻擊數值只統計「攻擊者 = 自己」的傷害,寵物/隊友/敵人不計入;\n"
                          "　 尚未偵測到角色 ID 時一律不記錄,可用控制列的「強制偵測」暫時全收",
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
        折疊時該視窗高度縮到剛好容納其餘元件;展開時還原上次記住的高度。

        target = log_pane 當前所在的 Toplevel (dock 時是 root、popout 時是 Toplevel),
        所有 geometry 都對它操作,避免主視窗被 popout 視窗的動作影響。
        prev height 用 attribute 存在 target 上,讓每個 Toplevel 各自記憶。
        """
        scale = self.font_scale
        target = self.log_pane.winfo_toplevel()
        if self.log_collapsed:
            # === 展開 ===
            self.log_area.pack(fill="both", expand=True, padx=6, pady=6)
            self.log_pane.pack_configure(expand=True, fill="both")
            self.btn_log_toggle.configure(text="▼ 即時攻擊事件日誌")
            self.log_collapsed = False
            prev = getattr(target, "_ldm_log_prev_h", None)
            if prev:
                w = target.winfo_width()
                target.geometry(f"{int(w / scale)}x{int(prev / scale)}")
        else:
            # === 折疊 ===
            target._ldm_log_prev_h = target.winfo_height()  # 記住當前高度
            self.log_area.pack_forget()
            self.log_pane.pack_configure(expand=False, fill="x")
            self.btn_log_toggle.configure(text="▶ 即時攻擊事件日誌 (已折疊)")
            self.log_collapsed = True
            target.update_idletasks()
            w = target.winfo_width()
            h = target.winfo_reqheight()
            target.geometry(f"{int(w / scale)}x{int(h / scale)}")

    def toggle_skill_collapse(self):
        """折疊/展開技能傷害排行區塊。折疊時 skill_scroll 隱藏但 target_stats 持續累計。"""
        if self.skill_collapsed:
            self.skill_scroll.pack(fill="both", expand=True, padx=6, pady=6)
            self.skill_pane.pack_configure(expand=True, fill="both")
            self.btn_skill_toggle.configure(text="▼ 技能傷害排行")
            self.skill_collapsed = False
        else:
            self.skill_scroll.pack_forget()
            self.skill_pane.pack_configure(expand=False, fill="x")
            self.btn_skill_toggle.configure(text="▶ 技能傷害排行 (已折疊)")
            self.skill_collapsed = True

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
        for row in self.skill_rows.values():
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
            self.dev_log("[ID] 尚未取得自己的身分 — 等 0x4FFF「我的角色資料」出現"
                         "(換地圖時會送)")
        else:
            acc, idx = self.ident_self
            bound = ("0x%08X" % self.ident_self_entity
                     if self.ident_self_entity is not None else "未綁定")
            self.dev_log(f"[ID] 目前身分: 帳號碼={acc} 角色索引={idx} | 自己 = {bound}")
        if MONSTER_NAMES:
            self.dev_log(f"[MOB] 怪物名對照表已載入 {len(MONSTER_NAMES):,} 筆 — "
                         f"0x{MOB_APPEAR_TYPE:04X} 登場包探針啟用 (純觀測,不進統計)")
        elif not RELEASE_BUILD:
            self.dev_log(f"[MOB] 找不到 {MOB_NAME_FILE},怪物名探針關閉")

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

    def log_damage(self, text, tags, target_id):
        """攻擊事件:記下受擊目標,供切換目標時過濾。"""
        self._append_log(text, target=target_id, tags=tags)


    def dev_log(self, text):
        """診斷訊息:進緩衝 → 更新底部單行 → 展開視窗開著就一併寫入。"""
        self._dev_lines.append(text)
        # 底部只有一行,換行字元會把 button 撐高,長行也要截斷
        line = text.replace("\n", " ")
        if len(line) > DEV_STRIP_MAX_CHARS:
            line = line[:DEV_STRIP_MAX_CHARS - 1] + "…"
        try:
            self.dev_strip.configure(text=line)
        except Exception:
            pass
        # 視窗關閉時 widget 不存在 (寫入是 after() 排程,可能晚於關窗)
        if self.dev_log_area is None:
            return
        self.dev_log_area.configure(state="normal")
        self.dev_log_area.insert("end", text + "\n")
        self.dev_log_area.see("end")
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

    def _refresh_target_options(self):
        """依 target_order 重建目標按鈕列;維持目前選取不變。
        按鈕文字刻意只放 Entity ID (不含傷害數字),這樣只有「出現新對象」時才需要
        重建,不必每筆傷害都動 widget。
        ID 用 hex 呈現,與技能欄/開發者 log 的 0x + 8 碼慣例一致。
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
            add(tid, f"0x{tid:08X}", 96)

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
    def find_skill_id_after(self, payload, start):
        """在 start offset 後方(200 bytes 內)尋找 0x4fc5 TLV, 回傳其 skill_id。
        參考 MM_Scribe_PacketNotes.md §5: skill_id 位於該 block payload offset 17..20。
        """
        payload_len = len(payload)
        limit = min(start + 200, payload_len - 8)
        scan = start
        while scan < limit:
            if payload[scan:scan+4] == b'\xc5\x4f\x00\x00':
                try:
                    sz = struct.unpack("<I", payload[scan+4:scan+8])[0]
                    if sz == 35 and scan + 8 + 21 <= payload_len:
                        return struct.unpack("<I", payload[scan+25:scan+29])[0]
                except Exception:
                    pass
                return None
            scan += 1
        return None

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
                self._ident_log("[ID] 未安裝 brotli,無法解出自己的身分 (pip install brotli)")
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
                    self._ident_log(f"[ID] 我的角色資料解壓中斷 ({exc.__class__.__name__}),"
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
                    self._ident_log(f"[ID] 已收 {st['got']}B 仍吐不出前 8 bytes,放棄本則")
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
            self._ident_log(f"[ID] 解出 reserved={reserved} ≠ 0 → 判為假陽性,丟棄")
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
        off = None
        if eid is not None:
            if self.ident_self is None:
                # 身分還沒到手 → 先留著,等 A 訊息來了回頭掃 (兩個方向都要做)
                self._ident_appear_cache.pop(eid, None)
                self._ident_appear_cache[eid] = plain
                while len(self._ident_appear_cache) > IDENT_APPEAR_CACHE_MAX:
                    self._ident_appear_cache.popitem(last=False)
            else:
                off = self._ident_match_offset(plain)
        # 別人的出現訊息不寫 LOG (一次換圖十幾筆,只會洗版) — 只累計數字,
        # 供「本場尚未綁定」那行診斷用
        if off is not None:
            self._ident_scene_hit += 1
            self._ident_bind(eid, off)

    def _ident_match_offset(self, plain):
        """在解壓內容裡找 u64 characterId == 我的身分,回傳位移;沒有則 None。

        比對鍵是帳號碼與角色索引「兩個都要相等」— 拆開比會綁到同帳號的別隻角色,
        或撞到別的帳號 (角色索引 4、5 這種小數字滿地都是)。
        """
        if self.ident_self is None:
            return None
        account, index = self.ident_self
        off = plain.find(struct.pack("<Q", account << 16 | index))
        return None if off < 0 else off

    def _ident_bind(self, eid, off):
        if self.ident_self_entity == eid:
            return
        prev = self.ident_self_entity
        self.ident_self_entity = eid
        note = (f" (原 0x{prev:08X} → 重新綁定)" if prev is not None else " (本場首次綁定)")
        self._ident_log(f"[ID] ★ 自己 = 實體 0x{eid:08X}{note} | "
                        f"characterId 位於解壓後位移 +{off}")
        self._ident_notify_ok()
        # 治癒端的 0x502A 學習是唯一獨立於本規則的自身 ID 來源 (見 parse_heal_shield §5),
        # 學到的話拿來當第二個佐證 —— 只有一個來源就分不出對錯
        lp = self.local_player_id
        if lp is not None:
            same = "一致" if (lp & 0xFFFFFFFF) == eid else "不一致"
            self._ident_log(f"[ID] 對照治癒端學到的本地 ID 0x{lp:X}: {same}")

    def _ident_rescan_cache(self):
        """A 訊息晚到:回頭掃已快取的 B 訊息。"""
        if not self._ident_appear_cache:
            return
        hits = 0
        for eid, plain in list(self._ident_appear_cache.items()):
            off = self._ident_match_offset(plain)
            if off is not None:
                hits += 1
                self._ident_bind(eid, off)
        self._ident_log(f"[ID] 回掃 {len(self._ident_appear_cache)} 筆已快取的玩家出現訊息,"
                        f"命中 {hits} 筆")
        self._ident_appear_cache.clear()

    # ================================================
    # 怪物登場包探針 (0x4E4C) — 只寫診斷 LOG,不進統計
    # ================================================

    def _mob_reset(self):
        """清空探針狀態。與身分偵測分開,免得互相干擾。"""
        self._mob_streams = collections.OrderedDict()   # 連線 key → 進行中的訊息
        self._mob_seen = collections.OrderedDict()      # entityId → 已印過的怪物碼
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
        else:
            self._mob_n_unknown += 1
        # 同一隻 (eid + 同一個碼) 只印一次 — 登場包會重送
        if self._mob_seen.get(eid) == code:
            return
        self._mob_seen[eid] = code
        while len(self._mob_seen) > MOB_SEEN_MAX:
            self._mob_seen.popitem(last=False)
        if name:
            self._mob_note(f"[MOB] eid={eid} code={code} → {name} ({eid & 0xFF})")
        else:
            self._mob_note(f"[MOB] eid={eid} code={code} → 查表無此碼 "
                           f"(Monster {eid})")

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

    def parse_payload(self, payload):
        offset = 0
        payload_len = len(payload)

        while offset < payload_len - 4:
            if payload[offset:offset+4] == b'\xe9\x51\x00\x00':
                try:
                    size = struct.unpack("<I", payload[offset+4:offset+8])[0]

                    if offset + 55 <= payload_len:
                        dmg_val = struct.unpack("<I", payload[offset+25:offset+29])[0]
                        # 攻擊對象 ID (protocol: UInt32 targetId @ content+8 = offset+17)
                        # 用於「目標篩選」分桶與日誌歸屬;offset+55 的長度檢查已涵蓋此範圍
                        target_id = struct.unpack("<I", payload[offset+17:offset+21])[0]
                        # 攻擊者 ID (protocol: UInt32 userId @ content+0 = offset+9);
                        # offset+55 的長度守門已涵蓋 offset+9..13
                        attacker_id = struct.unpack("<I", payload[offset+9:offset+13])[0]
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

                        # 嘗試從後續的 0x4fc5 TLV 抽出 skill_id (可能為 None)
                        # 事件實際總長為 9 + size (標頭含 encodingType),這裡刻意用 +8 起掃:
                        # 起點早 1 byte 只是多掃一輪,起點晚 1 byte 會直接跳過 magic。
                        skill_id = self.find_skill_id_after(payload, offset + 8 + size)

                        if self.is_dev_mode:
                            # 開發者面板不受統計門檻影響:別人的傷害照印,
                            # 這是驗證身分偵測對不對的唯一依據
                            skill_txt = f"0x{skill_id:08X}" if skill_id is not None else "(未取得)"
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
                                self._ident_log(
                                    f"[ID] ⚠ 本場尚未綁定 — 已收到 "
                                    f"{self._ident_scene_appear} 筆出現訊息 "
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

                        # 3. 標籤解析
                        #    b41: bit0=爆擊, bit2=無防備(排除破防), bit3=破防
                        #         bit6=首擊(first_hit,非標籤), bit7=普通攻擊旗標(自動攻擊=1)
                        #    b42: bit0=多重打擊, bit1=強擊, bit2=連擊, bit4=迎擊
                        #         bit3+bit7=持續傷害(DoT),不當標籤,改在技能名後加註 (Dot)
                        #    b44: bit3=追擊 (未驗證,見 DMG_ADD_HIT_BIT)
                        #    b57: bit0=破防 (備援旗標)
                        KNOWN_MASK_B41 = 0xCD
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

                        # 4. 傷害累加:同一筆同時進 TARGET_ALL 與該攻擊對象兩個桶
                        self._register_target(target_id)
                        now = time.time()
                        for _key in (TARGET_ALL, target_id):
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

                        # 只有這筆會影響到「目前顯示中的目標」時才重畫
                        if self.selected_target in (TARGET_ALL, target_id):
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
                        # tab 分隔欄位,tab stop 已在初始化時設定於固定像素位置。
                        # 行首多一個 tab:傷害值靠第一個 (right) 停靠點右對齊,
                        # 不再補空白 — 補空白只在等寬字體下才對得齊。
                        msg = f"\t{dmg_val:,}\t{tag_str}\t{skill_display}"
                        self.root.after(0, lambda m=msg, t=list(tags), tid=target_id:
                                        self.log_damage(m, t, tid))

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
        # 經典型 0x4FC5 size 35 — 無條件接受
        if cmd == b'\xc5\x4f\x00\x00' and size == 35:
            if magic_off + 29 <= payload_len:
                try:
                    return (struct.unpack("<I", payload[magic_off+25:magic_off+29])[0],
                            False)
                except Exception:
                    return None
        # 替代型 0x1ADE8 size 36 — 需 anti-decoy 檢查
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
        # 怪物登場包探針:純觀測,只在開發版且對照表讀得到時才跑
        if self.is_dev_mode and MONSTER_NAMES:
            self._mob_scan(raw_payload, conn_key)
        if not self.is_monitoring:
            return
        if self.track_damage:
            self.parse_payload(raw_payload)
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
        bpf_filter = f"ip net {IP_FILTER_NET} and tcp"
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
        self.log("=== 已停止監控 ===")

    def clear_data(self):
        # === 傷害端 ===
        # 所有目標桶一起丟掉並退回 All,下一場重新累積
        self.target_stats = {TARGET_ALL: self._new_stat_bucket()}
        self.target_order.clear()
        self.selected_target = TARGET_ALL
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
        self._render_log()

        self.heal_log_area.configure(state="normal")
        self.heal_log_area.delete("1.0", "end")
        self.heal_log_area.configure(state="disabled")

        # 診斷視窗可能沒開;緩衝與底部單行也要一起清,免得重開後舊資料又冒出來
        self._dev_lines.clear()
        try:
            self.dev_strip.configure(text=DEV_STRIP_EMPTY)
        except Exception:
            pass
        if self.dev_log_area is not None:
            self.dev_log_area.configure(state="normal")
            self.dev_log_area.delete("1.0", "end")
            self.dev_log_area.configure(state="disabled")

        self.log("=== 數據已歸零 ===")
        # 注意:身分/綁定不清零 — 清了就得等下次換地圖才會再認出自己,
        # 中間所有傷害都不會被記錄 (同 local_player_id 的處置)。
        # 只把「本場尚未綁定」的診斷警告重新武裝,並把目前狀態重寫一行到日誌。
        self._ident_scene_warned = False
        self._ident_status_line()


if __name__ == "__main__":
    root = ctk.CTk()
    app = LiveDamageMonitor(root)
    root.mainloop()
