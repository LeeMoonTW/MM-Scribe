"""
瑪奇即時傷害監控 — 傷害時間軸圖表閱覽器 (customtkinter 版)
需求: pip install customtkinter

本程式與 MabinogiMobileScribe_Beta.py 完全獨立:不抓封包、不需提權,
只讀 Save/ 內既有的存檔 JSON。刻意不 import 主程式 —— 那會連帶拉進
scapy / brotli 與一堆模組層級初始化,對一個純檢視工具是不必要的相依。
代價是下面重複了主程式的幾個小工具 (路徑、skills.ini 載入、技能命名),
兩邊都要改時請一起改;判斷相容性的錨點是 SAVE_FORMAT_VERSION。

資料一律從 damage.events 現算,不讀 target_stats:
  events 每列 = (ts, target_id, skill_id, damage, flags)
  flags 內含所有標籤位元 + DoT / 間接兩個高位元,足以重建覆蓋率統計。
好處是統計與圖表出自同一份原始資料,日後要加「拖曳選區間重算」是免費的
(統計桶只有總量,做不到區間篩選)。

打包說明 (與主程式相同的參數,少了 scapy 相依):
  python -m PyInstaller --onefile --noconsole --collect-data customtkinter MabinogiMobileScribeGraph_Beta.py
"""
import configparser
import json
import math
import os
import sys
import tkinter as tk
import tkinter.font as tkfont   # buff 名稱塞不塞得進左側欄位要實際量
import customtkinter as ctk

# 版號的唯一來源是主程式的 VERSION_STR (見 RELEASING.md),這裡不自己維護一份。
# 取法見 read_version():原始碼佈局下直接讀隔壁的主程式,打包後讀建置時
# 寫進來的 VERSION.txt (由 BuildTool 產生)。
MAIN_SCRIPT_NAME = "MabinogiMobileScribe_Beta.py"
VERSION_FILE = "VERSION.txt"

# ----------------------------------------------------
# 平台差異 (與主程式同步)
# ----------------------------------------------------
IS_MACOS = sys.platform == "darwin"
FONT_UI = "PingFang TC" if IS_MACOS else "Microsoft JhengHei"

# ----------------------------------------------------
# 存檔格式 (與主程式同步 —— 改主程式的存檔欄位語意時這裡要跟著升版)
# ----------------------------------------------------
SAVE_DIR_NAME = "Save"
SAVE_FILE_PREFIX = "MMScribe_"
SAVE_FILE_EXT = ".json"
SAVE_FORMAT_VERSION = 1
SAVE_COMBO_EMPTY = "(無存檔)"
SKILL_CFG_NAME = "skills.ini"
MERGE_GROUP_SECTION = "合併群組"

# 傷害事件旗標:位元順序即主程式的 DMG_EVENT_TAG_BITS,不可任意調換
DMG_EVENT_TAG_BITS = ("爆擊", "強擊", "破防", "無防備",
                      "連擊", "多重打擊", "迎擊", "追擊",
                      "延長破防", "終結")
DMG_EVENT_DOT_BIT = 1 << 16
DMG_EVENT_SUSTAIN_BIT = 1 << 17
# 覆蓋率:DoT 整筆不計;持續傷害 (間接) 只計爆擊 —— 與主程式同一套分母規則
COVERAGE_TAGS = ("爆擊", "強擊", "連擊", "追擊")
COVERAGE_TAGS_SUSTAIN = ("爆擊",)

UNKNOWN_SKILL_LABEL = "(未知技能)"   # events 裡 skill_id 為 null 的那些傷害
# 目標篩選 (與主程式同名同色):TARGET_ALL 是「全部對象」
TARGET_ALL = "__ALL__"
TARGET_ALL_LABEL = "All"
TARGET_BTN_SELECTED = "#3a6a9a"
TARGET_BTN_IDLE = "#2a2a2a"
# 按鈕寬度用「顯示單位」估算 (CJK 算 2 單位),不量實際字型 —— 量測值是螢幕
# 像素,而 width= 吃的是 CTk 縮放後的單位,HiDPI 下會對不上。與主程式同一組值。
TARGET_BTN_UNIT_W = 9              # 每單位估算寬度 (0x + 8 碼 = 10 單位 ≈ 舊的 96)
TARGET_BTN_MIN_W = 60
TARGET_BTN_MAX_W = 200
TARGET_NAME_MAX_UNITS = 20         # 超過就截斷加省略號

# ----------------------------------------------------
# 配色
# ----------------------------------------------------
BG_CHART = "#1b1b1b"
COL_GRID = "#333333"
COL_AXIS_TXT = "#8a8a8a"
COL_DPS_LINE = "#d5ac57"      # 累積平均 DPS (右軸)
COL_DPS5_LINE = "#3778b0"     # 5 秒移動平均 DPS (右軸,與黃線共用刻度)
DPS_WINDOW_SEC = 5            # 5 秒 DPS 的窗長
COL_ROW_ALT = "#242424"
COL_ROW_SEL = "#33475c"   # 選取中的技能列
# 技能配色:依該場總傷害排名依序配發,超出色盤的技能一律灰色。
# 刻意壓低彩度 —— 一張圖上十幾個高彩度色塊互相搶眼,反而看不出誰是主力。
# 相鄰名次的技能在圖上是上下疊在一起的,所以色相之外再交錯明暗,免得疊起來糊成一片。
# 亮度留了餘裕:日後 hover 要提亮某個技能時,才有往上打的空間。
SKILL_PALETTE = ("#6b8ca6", "#8f5f5c", "#6f9c7c", "#9c8352", "#7a6b96",
                 "#7fb3a8", "#96688a", "#8a9b63", "#7a4f3c", "#5f6b96",
                 "#b09a8c", "#5c8a80")
SKILL_COLOR_REST = "#5e5e5e"

# 圖表版面
PAD_L, PAD_R, PAD_T, PAD_B = 62, 62, 14, 24
MIN_SLOT_PX = 1.0   # 每格最小像素;不足時自動把 N 秒併成一格 (見 _slot_seconds)
# 縮放:視窗最少顯示幾秒。再小下去每格會寬到看不出「時間軸」的形狀
MIN_VIEW_SEC = 5
ZOOM_STEP = 1.25    # 滾輪一格的縮放倍率
AXIS_MAX_INTERVALS = 5      # 縱軸最多幾格 (見 nice_axis)
HOVER_LIGHTEN = 0.42        # hover 時色塊往白色推的比例
TOOLTIP_MAX_SKILLS = 8      # tooltip 最多列幾個技能,其餘併成一行
TOOLTIP_MAX_HITS = 15       # 按住 Shift 時最多列幾筆傷害明細,其餘只報筆數
TOOLTIP_COL_GAP = 12        # 逐筆明細:傷害欄與後面欄位的間距 (px)
# ---- Buff 持續軸 ----
BUFF_ROW_H = 20            # 每列高度 (含間距)
BUFF_BAR_H = 10            # 長條本身的高度
BUFF_NAME_PT = 8           # 名稱字級
BUFF_STACK_PT = 8          # 方塊開頭的層數標註字級
BUFF_SEG_GAP = 2           # 相鄰方塊之間留的空隙 (px);不留的話連著的兩段會黏成一條
BUFF_STACK_MIN_W = 18      # 方塊窄於這個寬度就不標層數 (字會溢出到隔壁)
# 名稱欄:與傷害圖左側刻度同一個位置 (x0 - 6, 靠右),寬度就是 PAD_L 扣掉那 6px。
# 塞不下的名字截斷加省略號 —— 不截的話會直接畫出 canvas 左緣,看起來像壞掉
BUFF_NAME_GAP = 6
BUFF_AXIS_PAD = 6
# 長條綠色與主程式面板同一個色系。面板那邊是 #347747 (綠 #30A050 以 60% alpha
# 疊在 #3A3A3A 上的預混結果);這裡底色更暗 (#1B1B1B),直接用未混色的原綠才不會糊掉。
# 平常畫暗的那支,hover 傷害長條時把同時段的 buff 換成亮的 —— 兩者要一眼分得出來,
# 又不能暗到看不見長條在哪
COL_BUFF_BAR = "#1A582C"        # 平常
COL_BUFF_BAR_HI = "#30A050"     # 被 hover 的時段
# 層數文字要在暗綠與亮綠上都讀得到,所以用淺色 (原本的深色字在暗綠上會糊掉)
COL_BUFF_STACK_TXT = "#e6f2ea"
COL_BUFF_NAME = "#ffffff"
COL_BUFF_BG = "#1b1b1b"

COL_TIP_BG = "#101010"
COL_TIP_BORDER = "#4a4a4a"
COL_TIP_TXT = "#d8d8d8"


# ====================================================
# 路徑 / 設定檔 (以下四段與主程式同源)
# ====================================================
def get_resource_path(filename):
    """PyInstaller bundled 資源路徑 (未打包時即原始碼資料夾)。"""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def get_external_path(filename):
    """EXE 旁邊 (或原始碼所在資料夾) 的外部檔路徑 —— 使用者可編輯的位置。"""
    if not getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    if IS_MACOS:
        # 與主程式一致:.app 內部唯讀,使用者檔案落在 Application Support
        base = os.path.expanduser("~/Library/Application Support/MM Scribe")
        return os.path.join(base, filename)
    return os.path.join(os.path.dirname(sys.executable), filename)


def get_save_dir():
    return get_external_path(SAVE_DIR_NAME)


def read_version():
    """回傳主程式的 VERSION_STR。兩條來源,都指向同一個真相:
      1. 打包時 BuildTool 從主程式抄進來的 VERSION.txt (EXE / .app 內)
      2. 原始碼佈局下,直接讀隔壁的主程式
    兩條都撈不到就回 "?" —— 版號顯示不出來不值得讓程式開不起來。
    """
    try:
        with open(get_resource_path(VERSION_FILE), encoding="utf-8") as f:
            v = f.read().strip()
        if v:
            return v
    except OSError:
        pass
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), MAIN_SCRIPT_NAME)
    try:
        with open(src, encoding="utf-8") as f:
            for line in f:
                # 只認行首的定義,才不會撈到字串內嵌的 f"...{VERSION_STR}"
                if line.startswith("VERSION_STR"):
                    parts = line.split('"')
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        pass
    return "?"


VERSION_STR = read_version()


def load_skill_config():
    """讀 skills.ini,回傳 (skill_names, merge_groups)。
    只取主程式的成功路徑:這裡是檢視工具,ini 有問題最多就是顯示 hex ID,
    不值得把主程式那套逐行錯誤回報也搬過來。
    """
    path = get_external_path(SKILL_CFG_NAME)
    if not os.path.exists(path):
        # macOS 打包版的外部路徑在 Application Support,主程式還沒跑過就不存在;
        # 退回 bundle 內附的那份 (唯讀,但技能名對照本來就只讀不寫)
        path = get_resource_path(SKILL_CFG_NAME)
    if not os.path.exists(path):
        return {}, {}
    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return {}, {}

    def _is_merge_section(name):
        if name == MERGE_GROUP_SECTION:
            return True
        if name.startswith(MERGE_GROUP_SECTION):
            return name[len(MERGE_GROUP_SECTION):len(MERGE_GROUP_SECTION) + 1] \
                in ("-", ":", ".", "_", " ")
        return False

    names, groups = {}, {}
    for section in parser.sections():
        if _is_merge_section(section):
            for group_name, members_str in parser.items(section):
                group_name = group_name.strip()
                if not group_name:
                    continue
                for member in members_str.split(","):
                    member = member.strip()
                    if member and member not in groups:
                        groups[member] = group_name
            continue
        for key, value in parser.items(section):
            try:
                skill_id = int(key.strip(), 16)
            except ValueError:
                continue
            name = value.strip()
            if name:
                names[skill_id] = name
    return names, groups


SKILL_NAMES, MERGE_GROUPS = load_skill_config()


def format_skill_name(skill_id):
    """skill_id → 顯示名稱 (規則與主程式相同)。None = 抓不到 ID 的傷害。"""
    if skill_id is None:
        return UNKNOWN_SKILL_LABEL
    if skill_id == 0:
        return "疑似符文傷害"
    return SKILL_NAMES.get(skill_id) or f"0x{skill_id:08X}"


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


def format_target_name(tid, entity_names):
    """目標按鈕文字:存檔有記到名字就用名字,否則退回 0x + 8 碼 hex。

    序號是主程式存檔當下就定死的 (None = 當時全場只有這一隻),這裡不重算 ——
    eid 換一次執行就換了,拿本檔的目標數量去推同名幾隻會推錯。
    """
    entry = entity_names.get(tid)
    if entry is None:
        return f"0x{tid:08X}"
    name, ordinal = entry
    label = clip_units(name, TARGET_NAME_MAX_UNITS)
    return f"{label} #{ordinal}" if ordinal else label


# ====================================================
# 存檔讀取
# ====================================================
def load_events(path):
    """讀存檔並取出時間序列。回傳 dict;任何問題丟 ValueError 由呼叫端報錯。

    只驗證圖表需要的欄位 —— target_stats / log_entries 一概不看,
    本程式的每一個數字都從 events 現算 (見檔頭)。
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("內容不是 JSON 物件")
    fmt = raw.get("format")
    if fmt != SAVE_FORMAT_VERSION:
        raise ValueError(f"格式版號 {fmt} 不支援 (本程式支援 {SAVE_FORMAT_VERSION})")
    dmg = raw.get("damage")
    if not isinstance(dmg, dict):
        raise ValueError("缺少 damage 區段")
    rows = dmg.get("events")
    if rows is None:
        # V0.53 之前的存檔沒有這一欄:讀得進來但畫不出東西,講清楚原因
        raise ValueError("此存檔沒有時間序列 (events),無法繪製圖表 —— "
                         "需要 Beta V0.53 以後版本所存的檔")
    events = []
    for ts, tid, sid, dmg_val, flags in rows:
        events.append((float(ts), int(tid, 16),
                       None if sid is None else int(sid, 16),
                       int(dmg_val), int(flags)))
    events.sort(key=lambda e: e[0])
    # Buff 持續軸:V0.5x 之前的存檔沒有這欄,缺了就當沒有 (圖表照畫,只是沒有下半段)
    buffs = []
    for row in (raw.get("buffs") or []):
        try:
            # 層數是後來才加的第 5 欄;更早的存檔只有 4 欄,當作 1 層
            bid, nm, st, en = row[:4]
            stacks = int(row[4]) if len(row) > 4 else 1
            buffs.append((int(bid, 16), str(nm), float(st), float(en), stacks))
        except (ValueError, TypeError, IndexError):
            continue   # 壞掉的單列跳過就好,不值得為它讓整份存檔讀不進來
    buffs.sort(key=lambda b: b[2])
    # 目標名字:主程式 V0.5x 之後才存,缺了就當空的 (目標按鈕退回 hex)。
    # 單列壞掉只跳過該列 —— 名字是顯示用的,不值得為它讓整份存檔讀不進來。
    names = {}
    for k, v in ((raw.get("damage") or {}).get("entity_names") or {}).items():
        try:
            names[int(k, 16)] = (str(v[0]),
                                 None if v[1] is None else int(v[1]))
        except (ValueError, TypeError, IndexError, KeyError):
            continue
    return {
        "saved_at": raw.get("saved_at") or "?",
        "app_version": raw.get("app_version") or "?",
        "events": events,
        "buffs": buffs,
        "entity_names": names,
    }


def list_saves():
    """掃 Save/ 內的存檔檔名,新的排前面 (檔名含時間戳,字串排序即時間排序)。"""
    names = []
    try:
        for fn in os.listdir(get_save_dir()):
            if fn.startswith(SAVE_FILE_PREFIX) and fn.endswith(SAVE_FILE_EXT):
                names.append(fn[:-len(SAVE_FILE_EXT)])
    except OSError:
        pass   # 資料夾不存在 = 還沒存過檔,不是錯誤
    names.sort(reverse=True)
    return names


# ====================================================
# 統計聚合
# ====================================================
def decode_tags(flags):
    """flags → (tag 名稱 set, is_dot, is_sustain)。"""
    tags = {name for i, name in enumerate(DMG_EVENT_TAG_BITS) if flags & (1 << i)}
    return tags, bool(flags & DMG_EVENT_DOT_BIT), bool(flags & DMG_EVENT_SUSTAIN_BIT)


def tags_text(flags):
    """單筆傷害的標籤字串,順序照 DMG_EVENT_TAG_BITS;沒有標籤回空字串。"""
    tags, is_dot, is_sustain = decode_tags(flags)
    parts = [t for t in DMG_EVENT_TAG_BITS if t in tags]
    if is_dot:
        parts.append("DoT")
    if is_sustain:
        parts.append("間接")
    return "+".join(parts)


def display_name_for(skill_id, merge):
    name = format_skill_name(skill_id)
    return MERGE_GROUPS.get(name, name) if merge else name


class Aggregate:
    """一份存檔 (全部對象) 的聚合結果:每秒桶 + 技能統計。

    每秒桶固定以 1 秒為單位建立;畫面塞不下時才在繪圖階段把 N 秒併成一格,
    這樣視窗放大後不必重算資料。
    """

    def __init__(self, events, merge, base_t0=None, base_n_sec=None):
        self.events = events
        self.t0 = events[0][0] if base_t0 is None else base_t0
        self.t1 = events[-1][0]
        # 時間軸的原點與長度可由外部指定 (目標篩選時沿用整場的軸),
        # 這樣切換目標不會讓 x 軸整條位移,才比得出「哪個目標是什麼時候打的」
        self.n_sec = (int(self.t1 - self.t0) + 1 if base_n_sec is None
                      else base_n_sec)
        # first_sec / duration 講的是「這批事件自己」:交手起點與跨度。
        # DPS 的分母用它 —— 中途才出現的目標不該被它出現前的空白稀釋
        self.first_sec = int(events[0][0] - self.t0)
        self.duration = max(1.0, events[-1][0] - events[0][0])

        self.sec_total = [0] * self.n_sec              # 每秒總傷害
        # 每秒 {技能名: [傷害, 命中次數]} —— 次數是給 hover tooltip 用的
        self.sec_skill = [dict() for _ in range(self.n_sec)]
        self.skills = {}   # 技能名 → 統計 dict
        self.total = 0
        # 每秒對應到 events 的索引區間 [lo, hi)。events 依時間排序,同一秒必然
        # 是連續的一段,所以逐筆明細不必另外複製一份出來存
        self.sec_range = [None] * self.n_sec

        for ev_i, (ts, _tid, sid, dmg, flags) in enumerate(events):
            idx = int(ts - self.t0)
            if idx >= self.n_sec:      # 浮點邊界保護
                idx = self.n_sec - 1
            rng = self.sec_range[idx]
            self.sec_range[idx] = (ev_i, ev_i + 1) if rng is None else (rng[0], ev_i + 1)
            name = display_name_for(sid, merge)
            self.total += dmg
            self.sec_total[idx] += dmg
            cell = self.sec_skill[idx].get(name)
            if cell is None:
                self.sec_skill[idx][name] = [dmg, 1]
            else:
                cell[0] += dmg
                cell[1] += 1

            s = self.skills.get(name)
            if s is None:
                s = self.skills[name] = {
                    "damage": 0, "hits": 0,
                    "cov_hits": 0, "cov_main": 0,   # 爆擊 / 其餘標籤的分母
                    "tags": {t: 0 for t in COVERAGE_TAGS},
                    "min": dmg, "max": dmg,
                }
            s["damage"] += dmg
            s["hits"] += 1
            if dmg < s["min"]:
                s["min"] = dmg
            if dmg > s["max"]:
                s["max"] = dmg
            tags, is_dot, is_sustain = decode_tags(flags)
            # 覆蓋率規則與主程式 parse_payload 相同:
            #   DoT 整筆不計;持續傷害只進爆擊的分子分母
            if not is_dot:
                s["cov_hits"] += 1
                if not is_sustain:
                    s["cov_main"] += 1
                for t in COVERAGE_TAGS:
                    if is_sustain and t not in COVERAGE_TAGS_SUSTAIN:
                        continue
                    if t in tags:
                        s["tags"][t] += 1

        # 累積傷害前綴和:cum[k] = 前 k 秒的總傷害。
        # 黃線是「從開場到當下」的累積平均 DPS,縮放到中段時仍要看得到開場以來的
        # 累積量,所以不能只加可視範圍內的桶。
        self.cum = [0] * (self.n_sec + 1)
        for i, v in enumerate(self.sec_total):
            self.cum[i + 1] = self.cum[i] + v

        # 排名 (總傷害由大到小) → 決定表格順序、堆疊順序與配色
        self.order = sorted(self.skills, key=lambda n: self.skills[n]["damage"],
                            reverse=True)
        self.colors = {n: (SKILL_PALETTE[i] if i < len(SKILL_PALETTE)
                           else SKILL_COLOR_REST)
                       for i, n in enumerate(self.order)}

    def rate(self, name, tag):
        """標籤覆蓋率;分母為 0 (例如整支技能都是持續傷) 回傳 None → 顯示「—」。"""
        s = self.skills[name]
        den = s["cov_hits"] if tag in COVERAGE_TAGS_SUSTAIN else s["cov_main"]
        if den == 0:
            return None
        return s["tags"][tag] * 100.0 / den


# ====================================================
# 數字 / 時間格式
# ====================================================
def lighten(color, factor=HOVER_LIGHTEN):
    """把顏色往白色推 factor 比例。色盤刻意壓低亮度,就是為了留出這段提亮空間。"""
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    mix = lambda v: min(255, int(round(v + (255 - v) * factor)))
    return f"#{mix(r):02x}{mix(g):02x}{mix(b):02x}"


def fmt_compact(v):
    """座標軸用的短格式 (參考圖同樣用萬/億,長數字會把軸標擠爆)。
    尾巴的 .0 去掉 —— 刻度落在整數級距上時「20萬」比「20.0萬」乾淨。
    """
    if v >= 1e8:
        s = f"{v / 1e8:.2f}億"
    elif v >= 1e4:
        s = f"{v / 1e4:.1f}萬"
    else:
        return f"{v:.0f}"
    whole, _, tail = s[:-1].partition(".")
    tail = tail.rstrip("0")
    return whole + ("." + tail if tail else "") + s[-1]


def nice_axis(value, max_lines=AXIS_MAX_INTERVALS):
    """把軸頂湊到 1/2/5 × 10ⁿ 的整數級距上,回傳 (級距, 軸頂, 格數)。

    不直接拿資料最大值當軸頂 —— 那會讓刻度變成 6.35萬 / 12.7萬 這種讀不出來的數字。
    改成在 …5萬 → 10萬 → 20萬 → 50萬 → 100萬… 這條階梯上找第一個能讓格數
    不超過 max_lines 的級距;級距是資料決定的,不必為不同規模的場次寫死門檻。
    """
    if value <= 0:
        return 1, 1, 1
    mag = 10 ** math.floor(math.log10(value / max_lines)) if value > max_lines else 1
    for mult in (1, 2, 5, 10):
        step = max(1, int(round(mult * mag)))   # 傷害是整數,級距不取小數
        if math.ceil(value / step) <= max_lines:
            n = max(1, math.ceil(value / step))
            return step, step * n, n
    step = max(1, int(round(10 * mag)))
    return step, step * max_lines, max_lines


def fmt_mmss(sec):
    sec = int(sec)
    if sec >= 3600:
        return f"{sec // 3600}:{sec % 3600 // 60:02d}:{sec % 60:02d}"
    return f"{sec // 60:02d}:{sec % 60:02d}"



# ====================================================
# 主視窗
# ====================================================
class GraphViewer:
    def __init__(self, root):
        self.root = root
        self.root.title(f"MM Scribe Graph {VERSION_STR}")
        self.root.geometry("1280x1000")
        self.root.minsize(900, 600)
        # 視窗標題列 icon:與主程式同一顆圖 (BuildTool 會把它一起打包進來)。
        # macOS 的 Tk 不吃 .ico,改用 iconphoto 讀 PNG;載不到不影響功能
        icon_path = get_resource_path("icon.png" if IS_MACOS else "icon.ico")
        if os.path.exists(icon_path):
            try:
                if IS_MACOS:
                    self._app_icon = tk.PhotoImage(file=icon_path)
                    self.root.iconphoto(True, self._app_icon)
                else:
                    self.root.iconbitmap(icon_path)
            except Exception:
                pass

        self.agg = None          # 當前 Aggregate (未讀檔時 None)
        self.meta = None         # 當前存檔的 saved_at / app_version
        self.raw_events = None   # 供切換「合併同技能」時重算,不必重讀檔
        self._resize_job = None
        # 可視區間 (秒,相對於第一筆傷害)。一律用整數秒 —— 每秒桶是整數秒對齊的,
        # 起點若帶小數,併格時會把同一秒的傷害切給兩格。
        self.view_start = 0
        self.view_span = 0       # 0 = 尚未讀檔
        self._pan = None         # 右鍵拖曳中: (起始滑鼠 x, 起始 view_start)
        self._bar_items = {}     # 格 index → [(canvas item, 原色), ...]
        self._hover_slot = None  # 目前提亮中的格
        self._hover_xy = None    # 最後一次 hover 的游標位置 (Shift 切換時要原地重畫)
        self._shift = False      # 是否按著 Shift (逐筆明細模式)
        self._geom = None        # 上次繪圖的座標資訊 (hover 命中判定用)
        self.selected_target = TARGET_ALL   # 目標過濾 (單選,與主程式一致)
        self.target_buttons = {}
        self.entity_names = {}   # target_id → (怪物名, 序號或 None),來自存檔
        self.selected_skills = set()   # 圖表過濾:空集合 = 不過濾
        self.row_widgets = {}          # 技能名 → ([該列 widgets], 原底色)
        self.f_sec_total = None        # 套用過濾後的每秒總傷害
        self.f_cum = None              # 同上的前綴和 (兩條 DPS 線用)
        self.buffs = []                # [(buffId, 名稱, 起, 迄)] 牆鐘秒
        self.buff_rows = []            # 全部的列: [(名稱, [(起秒, 迄秒, 層數), ...])]
        self.buff_stats = []           # 表格用: [(名稱, 覆蓋秒數, 覆蓋率)] 依覆蓋排序
        # 持續軸要畫哪幾個 —— 預設空的 (什麼都不畫),由 BUFF 統計表點選加入。
        # 用 list 不用 set:出現順序要照使用者點擊的順序
        self.selected_buffs = []
        self.buff_row_widgets = {}     # 名稱 → ([該列 widgets], 原底色)
        # 持續軸上每個方塊的 (canvas item, 起秒, 迄秒) —— hover 傷害長條時
        # 用來找出同時段生效中的 buff 並提亮
        self._buff_seg_items = []
        self._buff_hl_items = []       # 目前被提亮的那幾個,移開時要還原
        self._buff_head = {}           # 欄名 → 表頭 label (點了要換 ▲▼)
        # BUFF 表排序: (欄 index, 是否遞減)。預設名稱升冪 —— 名字的位置固定,
        # 換了存檔也還在同一列,找起來比「覆蓋率排序」穩定
        self._buff_sort = (0, False)
        self._buff_name_font = None    # 量名稱寬度用,第一次要畫時才建
        # 被截斷的名稱要能 hover 看全名: [(y上, y下, 全名), ...] 與名稱欄右界 x
        self._buff_name_hits = []
        self._buff_name_x = 0

        self.save_var = tk.StringVar(value=SAVE_COMBO_EMPTY)
        self.merge_var = tk.BooleanVar(value=False)
        # 兩條曲線預設關掉:一開圖先看每秒傷害的分佈,要看趨勢再自己開
        self.show_dps_var = tk.BooleanVar(value=False)   # 累積平均 DPS 曲線
        self.show_dps5_var = tk.BooleanVar(value=False)  # 5 秒 DPS 曲線

        self._build_ui()
        self.refresh_save_list()

    # ---------- 版面 ----------
    def _build_ui(self):
        top = ctk.CTkFrame(self.root, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(top, text="存檔:", font=(FONT_UI, 13)).pack(side="left")
        self.save_combo = ctk.CTkComboBox(top, width=240, values=[SAVE_COMBO_EMPTY],
                                          variable=self.save_var, state="readonly",
                                          font=(FONT_UI, 12), dropdown_font=(FONT_UI, 12))
        self.save_combo.pack(side="left", padx=(6, 6))
        ctk.CTkButton(top, text="讀取", width=70, font=(FONT_UI, 13),
                      command=self.load_selected).pack(side="left")
        ctk.CTkButton(top, text="重新整理", width=80, font=(FONT_UI, 13),
                      fg_color="#3a3a3a", hover_color="#4a4a4a",
                      command=self.refresh_save_list).pack(side="left", padx=6)
        ctk.CTkCheckBox(top, text="合併同技能", variable=self.merge_var,
                        font=(FONT_UI, 13), command=self._on_merge_toggle
                        ).pack(side="left", padx=(14, 0))
        # 曲線開關:只影響繪圖,不動聚合結果,所以直接重畫就好
        for text, var, color in (("累積平均 DPS", self.show_dps_var, COL_DPS_LINE),
                                 (f"{DPS_WINDOW_SEC}秒 DPS", self.show_dps5_var,
                                  COL_DPS5_LINE)):
            ctk.CTkCheckBox(top, text=text, variable=var, font=(FONT_UI, 13),
                            text_color=color, fg_color=color,
                            hover_color=color, command=self._draw_chart
                            ).pack(side="left", padx=(14, 0))

        self.status = ctk.CTkLabel(self.root, text="尚未讀取存檔",
                                   font=(FONT_UI, 12), text_color="#9a9a9a",
                                   anchor="w")
        self.status.pack(fill="x", padx=12)

        # 圖表
        chart_box = ctk.CTkFrame(self.root, fg_color="#202020")
        chart_box.pack(fill="both", expand=True, padx=10, pady=(4, 6))
        head = ctk.CTkFrame(chart_box, fg_color="transparent")
        head.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(head, text="傷害時間軸", font=(FONT_UI, 13, "bold"),
                     text_color="#5aa9e6").pack(side="left")
        self.chart_hint = ctk.CTkLabel(head, text="", font=(FONT_UI, 11),
                                       text_color="#8a8a8a")
        self.chart_hint.pack(side="right")
        # 目標列:目標多的時候會塞不下,用水平捲動框而不是硬擠或截斷
        self.target_bar = ctk.CTkScrollableFrame(
            chart_box, orientation="horizontal", height=44,
            fg_color="transparent")
        self.target_bar.pack(fill="x", padx=8, pady=(4, 0))
        self.chart = tk.Canvas(chart_box, bg=BG_CHART, highlightthickness=0)
        self.chart.pack(fill="both", expand=True, padx=8, pady=(4, 0))
        # Buff 持續軸:獨立 canvas,但左右內距與 chart 完全相同 (padx=8 + PAD_L/PAD_R),
        # x 座標才會跟上面的傷害長條對得起來。縮放/橫移由 _draw_chart 末尾一併重畫
        self.buffbar = tk.Canvas(chart_box, bg=COL_BUFF_BG, highlightthickness=0,
                                  height=BUFF_ROW_H + BUFF_AXIS_PAD * 2)
        self.buffbar.pack(fill="x", padx=8, pady=(0, 8))
        # 名稱欄太窄,長一點的 buff 名會被截成「岩石巨人…」;滑上去顯示全名
        self.buffbar.bind("<Motion>", self._on_buff_motion)
        self.buffbar.bind("<Leave>", lambda _e: self.buffbar.delete("bufftip"))
        self.chart.bind("<Configure>", self._on_chart_resize)
        # 滾輪縮放:Windows / macOS 走 <MouseWheel> (delta 正負即方向),
        # X11 的滾輪是 Button-4/5,順手一起綁
        self.chart.bind("<MouseWheel>", self._on_wheel)
        self.chart.bind("<Button-4>", self._on_wheel)
        self.chart.bind("<Button-5>", self._on_wheel)
        # 右鍵拖曳橫移。macOS 的 Tk 把右鍵送成 Button-2 (Button-3 是中鍵),
        # 兩個都綁才能兩邊都用右鍵拖
        for btn in (("3", "2") if IS_MACOS else ("3",)):
            self.chart.bind(f"<ButtonPress-{btn}>", self._on_pan_start)
            self.chart.bind(f"<B{btn}-Motion>", self._on_pan_move)
            self.chart.bind(f"<ButtonRelease-{btn}>", self._on_pan_end)
        # Hover:滑過長條顯示明細。右鍵拖曳期間 Tk 會挑更精確的 <B3-Motion>,
        # 所以橫移時不會同時觸發這裡
        self.chart.bind("<Motion>", self._on_motion)
        self.chart.bind("<Leave>", lambda _e: self._clear_hover())
        # Shift 切換逐筆明細。綁在 root:tk.Canvas 沒有鍵盤焦點,綁在它身上收不到。
        # 滑鼠停著不動時,只有這裡能讓 tooltip 立刻換模式
        for key in ("Shift_L", "Shift_R"):
            self.root.bind(f"<KeyPress-{key}>", lambda _e: self._set_shift(True))
            self.root.bind(f"<KeyRelease-{key}>", lambda _e: self._set_shift(False))

        # 技能統計 / BUFF 統計:共用一個 grid 容器。用 pack 的話兩塊會依各自的
        # 需求高度分配剩餘空間 (技能列多就吃掉大半),grid + 相同 weight + uniform
        # 才是真的對半分
        tables_box = ctk.CTkFrame(self.root, fg_color="transparent")
        tables_box.pack(fill="both", expand=True)
        tables_box.grid_columnconfigure(0, weight=1)
        for r in (0, 1):
            tables_box.grid_rowconfigure(r, weight=1, uniform="stats")

        # 技能統計
        table_box = ctk.CTkFrame(tables_box, fg_color="#202020")
        table_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=(0, 10))
        thead = ctk.CTkFrame(table_box, fg_color="transparent")
        thead.pack(fill="x", padx=8, pady=(6, 2))
        ctk.CTkLabel(thead, text="技能統計", font=(FONT_UI, 13, "bold"),
                     text_color="#5aa9e6").pack(side="left")
        ctk.CTkLabel(thead, text="(點技能列可只看該技能的圖表,可複選)",
                     font=(FONT_UI, 11), text_color="#7a7a7a").pack(side="left",
                                                                    padx=(8, 0))
        self.clear_filter_btn = ctk.CTkButton(
            thead, text="清除過濾", width=80, font=(FONT_UI, 12),
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            state="disabled", command=self.clear_filter)
        self.clear_filter_btn.pack(side="right")
        self.filter_label = ctk.CTkLabel(thead, text="", font=(FONT_UI, 12),
                                         text_color="#c8a04e")
        self.filter_label.pack(side="right", padx=(0, 10))
        self.table = ctk.CTkScrollableFrame(table_box, fg_color="transparent")
        self.table.pack(fill="both", expand=True, padx=4, pady=(0, 6))

        # BUFF 統計
        buff_box = ctk.CTkFrame(tables_box, fg_color="#202020")
        buff_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        bhead = ctk.CTkFrame(buff_box, fg_color="transparent")
        bhead.pack(fill="x", padx=8, pady=(6, 2))
        ctk.CTkLabel(bhead, text="BUFF統計", font=(FONT_UI, 13, "bold"),
                     text_color="#5aa9e6").pack(side="left")
        ctk.CTkLabel(bhead, text="(點BUFF列可在時間軸上顯示覆蓋圖表,可複選)",
                     font=(FONT_UI, 11), text_color="#7a7a7a").pack(side="left",
                                                                    padx=(8, 0))
        self.clear_buff_btn = ctk.CTkButton(
            bhead, text="清除過濾", width=80, font=(FONT_UI, 12),
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            state="disabled", command=self.clear_buff_filter)
        self.clear_buff_btn.pack(side="right")
        self.buff_table = ctk.CTkScrollableFrame(buff_box, fg_color="transparent")
        self.buff_table.pack(fill="both", expand=True, padx=4, pady=(0, 6))

    # ---------- 存檔 ----------
    def refresh_save_list(self):
        """只讀檔名不 parse 內容 (與主程式相同的取捨:檔案一多才不會拖慢啟動)。"""
        names = list_saves()
        values = names or [SAVE_COMBO_EMPTY]
        self.save_combo.configure(values=values)
        if self.save_var.get() not in values:
            self.save_var.set(values[0])

    def load_selected(self):
        name = self.save_var.get()
        if not name or name == SAVE_COMBO_EMPTY:
            self._set_status("❌ 尚未選擇存檔", error=True)
            return
        path = os.path.join(get_save_dir(), name + SAVE_FILE_EXT)
        try:
            data = load_events(path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self._set_status(f"❌ 讀取失敗:{exc}", error=True)
            self.refresh_save_list()   # 檔案可能已被手動刪掉,順手重掃
            return
        if not data["events"]:
            self._set_status("❌ 此存檔的時間序列是空的 (沒有記到任何傷害)", error=True)
            return
        self.meta = data
        self.raw_events = data["events"]
        self.buffs = data["buffs"]
        self.entity_names = data["entity_names"]
        self.selected_target = TARGET_ALL
        self._build_target_bar()
        self._rebuild()

    def _build_target_bar(self):
        """依總傷害由大到小列出目標按鈕 (All 固定第一個)。
        文字用存檔記下的怪物名,沒記到才退回 0x + 8 碼 hex (與主程式一致)。
        """
        for btn in self.target_buttons.values():
            btn.destroy()
        self.target_buttons.clear()
        totals = {}
        for _ts, tid, _sid, dmg, _fl in self.raw_events:
            totals[tid] = totals.get(tid, 0) + dmg

        def add(key, text, width):
            btn = ctk.CTkButton(self.target_bar, text=text, width=width, height=26,
                                corner_radius=6, font=(FONT_UI, 12),
                                fg_color=TARGET_BTN_IDLE, hover_color="#4a4a4a",
                                command=lambda k=key: self._on_target_change(k))
            btn.pack(side="left", padx=(0, 4))
            self.target_buttons[key] = btn

        add(TARGET_ALL, TARGET_ALL_LABEL, 46)
        for tid in sorted(totals, key=lambda t: -totals[t]):
            text = format_target_name(tid, self.entity_names)
            add(tid, text, target_btn_width(text))
        self._update_target_style()

    def _update_target_style(self):
        for key, btn in self.target_buttons.items():
            btn.configure(fg_color=(TARGET_BTN_SELECTED
                                    if key == self.selected_target
                                    else TARGET_BTN_IDLE))

    def _on_target_change(self, key):
        if key == self.selected_target:
            return
        self.selected_target = key
        self._update_target_style()
        self._rebuild(reset_view=False)   # 時間軸不變 → 保留目前縮放

    def _on_merge_toggle(self):
        if self.raw_events:
            self._rebuild()

    def _rebuild(self, reset_view=True):
        """重新聚合 → 重畫圖表與表格 (讀檔、切合併模式、切目標共用)。

        目標篩選在這一層做:只把該目標的事件餵進 Aggregate,表格與圖表就都是
        該目標的數字 (與主程式點目標按鈕的行為一致)。時間軸基準仍用整場的,
        切目標不會讓 x 軸位移。
        """
        # 時間軸基準一律取自整場 (raw_events 讀檔時已依時間排序),
        # 當場算比另外存一份狀態少一個要同步的東西
        base_t0 = self.raw_events[0][0]
        base_n_sec = int(self.raw_events[-1][0] - base_t0) + 1
        events = self.raw_events
        if self.selected_target != TARGET_ALL:
            events = [e for e in events if e[1] == self.selected_target]
        self.agg = Aggregate(events, self.merge_var.get(), base_t0, base_n_sec)
        a = self.agg
        # 換檔或切換合併模式 → 縮放歸零,回到整場視野。切目標則保留目前視野,
        # 因為時間軸沒變,同一個時間窗才好在不同目標之間對照
        if reset_view:
            self.view_start, self.view_span = 0, a.n_sec
        self._pan = None
        # 過濾一起清掉:合併群組會讓技能名整組換掉,換目標則技能清單本來就不同,
        # 留著舊名的選取只會選到空氣
        self.selected_skills.clear()
        self._set_status(
            f"存檔時間 {self.meta['saved_at']} ({self.meta['app_version']})    "
            f"場次長度 {fmt_mmss(a.duration)}    "
            f"總傷害 {a.total:,}    "
            f"平均 DPS {a.total / a.duration:,.0f}    "
            f"傷害事件 {len(a.events):,} 筆")
        # 覆蓋率的分母用「實際交手長度」而不是 base_n_sec —— 後者是每秒桶的個數
        # (尾端會多算一秒),全程掛著的 buff 會算出 99% 這種看起來像有破口的數字
        self._prepare_buff_rows(base_t0,
                                self.raw_events[-1][0] - self.raw_events[0][0])
        self._build_table()
        self._build_buff_table()
        self.clear_buff_btn.configure(
            state="normal" if self.selected_buffs else "disabled")
        self._apply_filter()   # 內含 _draw_chart

    def _prepare_buff_rows(self, base_t0, base_span):
        """把存檔裡的 buff 區間換算成「相對開場的秒數」並依名稱歸成列。

        同名的多次施放共用一列 (參考圖的 BUFF1/2/3 就是這樣),列的排序看
        總持續時間 —— 掛最久的排最上面,一眼看得出主要的增益覆蓋。
        軸的原點與傷害圖共用 base_t0,兩張圖才對得起來。
        """
        # 區間一律夾進 [0, 場次長度]。主程式那邊已經把起點夾到「按下開始」,
        # 但圖表的原點是**第一筆傷害**,不是按開始那一刻 —— 中間隔了多久就會多出
        # 多少,不在這裡再夾一次仍會算出超過 100% 的覆蓋率
        span = max(1.0, base_span)
        by_name = {}
        for _bid, nm, st, en, stacks in self.buffs:
            st = min(max(st - base_t0, 0.0), span)
            en = min(max(en - base_t0, 0.0), span)
            if en <= st:
                continue   # 整段都落在場次之外
            by_name.setdefault(nm, []).append((st, en, stacks))
        self.buff_rows = [(nm, sorted(segs)) for nm, segs in by_name.items()]
        # 覆蓋秒數要先把區間**聯集**再算 —— 同名的不同實體 (例如兩個「情緒調節」)
        # 可能時間重疊,直接把每段長度加總會算出超過 100% 的覆蓋率
        stats = []
        for nm, segs in self.buff_rows:
            covered, cur_s, cur_e = 0.0, None, None
            for st, en, _k in segs:
                if cur_e is None or st > cur_e:
                    if cur_e is not None:
                        covered += cur_e - cur_s
                    cur_s, cur_e = st, en
                else:
                    cur_e = max(cur_e, en)
            if cur_e is not None:
                covered += cur_e - cur_s
            stats.append((nm, covered, covered * 100.0 / span))
        self.buff_stats = stats
        self._apply_buff_sort()
        # 這份存檔裡已經沒有的名稱要從選取中丟掉,否則持續軸少一列卻還算在
        # 「已選 N 個」裡
        have = {nm for nm, _ in self.buff_rows}
        self.selected_buffs = [n for n in self.selected_buffs if n in have]
        self._sync_buffbar_height()

    def _sync_buffbar_height(self):
        """canvas 高度跟著「已選取的列數」走 —— 沒選就收成一條細線,不佔版面。"""
        n = len(self.selected_buffs)
        self.buffbar.configure(
            height=(n * BUFF_ROW_H + BUFF_AXIS_PAD * 2) if n else 18)

    def _fit_buff_name(self, name, avail):
        """名稱塞不進左側欄位就從尾端截斷加省略號。

        字寬要實際量 —— 中文/英文/數字混排時按字數估會差很多。
        Font 物件建一次就快取,每列每次重畫都 new 一個會拖慢橫移。
        """
        f = self._buff_name_font
        if f is None:
            f = self._buff_name_font = tkfont.Font(
                family=FONT_UI, size=BUFF_NAME_PT, weight="bold")
        if avail <= 0 or f.measure(name) <= avail:
            return name
        for i in range(len(name) - 1, 0, -1):
            clipped = name[:i] + "…"
            if f.measure(clipped) <= avail:
                return clipped
        return "…"

    def _draw_buffs(self, x0, plot_w, vs, g, n_slots):
        """畫 buff 持續軸。座標換算與傷害圖同一套:
        第 i 格的左緣是 x0 + i*slot_w,而 slot_w = plot_w / n_slots,
        所以「時間 t 秒」對應到 x0 + (t - vs) / (n_slots * g) * plot_w。
        """
        c = self.buffbar
        c.delete("all")
        self._buff_name_hits = []
        self._buff_seg_items = []
        self._buff_hl_items = []
        if self.agg is None:
            return
        # 沒有 buff 記錄 (舊版存檔) 一樣整片留白 —— 這件事在「BUFF統計」表裡
        # 已經寫得很清楚了,時間軸這邊不重複
        if not self.buff_rows:
            return
        # 依使用者點擊的順序取列 —— 不照覆蓋率排,照他自己排的
        segs_of = dict(self.buff_rows)
        rows = [(nm, segs_of[nm]) for nm in self.selected_buffs if nm in segs_of]
        if not rows:
            return   # 沒選就整片留白 (提示字放在 BUFF 統計的標題列,這裡不重複)
        span = n_slots * g          # 可視區間的實際秒數 (併格後可能略大於 view_span)
        if span <= 0 or plot_w <= 0:
            return
        # 只有被截斷的名稱才需要 hover 看全名,沒截斷的不記 —— 滑過完整的名字
        # 還跳一個一模一樣的 tooltip 只是干擾
        self._buff_name_x = x0

        def t2x(t):
            return x0 + (t - vs) / span * plot_w

        for i, (nm, segs) in enumerate(rows):
            y = BUFF_AXIS_PAD + i * BUFF_ROW_H + (BUFF_ROW_H - BUFF_BAR_H) / 2
            # 底線:沒有長條的時段也看得出這一列存在,不然列與列會對不上名字
            c.create_line(x0, y + BUFF_BAR_H / 2, x0 + plot_w,
                          y + BUFF_BAR_H / 2, fill="#2a2a2a")
            for st, en, stacks in segs:
                # 可視範圍外的整段跳過;跨出邊界的裁掉超出的部分。
                # en < st 是壞資料 (存檔時牆鐘被往回撥),跳過而不是畫成負寬度
                if en < st or en < vs or st > vs + span:
                    continue
                bx0, bx1 = t2x(max(st, vs)), t2x(min(en, vs + span))
                # 右緣讓出 BUFF_SEG_GAP —— 層數一變就切一段,相鄰兩段的時間是
                # 連續的,不留空隙會黏成一條看不出切在哪
                bx1 -= BUFF_SEG_GAP
                # 極短的 buff 在縮小視野時會塌成 0 寬,補到至少 1px 才看得見
                if bx1 - bx0 < 1:
                    bx1 = bx0 + 1
                self._buff_seg_items.append(
                    (c.create_rectangle(bx0, y, bx1, y + BUFF_BAR_H,
                                        fill=COL_BUFF_BAR, width=0), st, en))
                # 層數標在方塊開頭。1 層不標 (與主程式面板同一個規則:大部分
                # buff 一輩子都是 1 層,每塊都掛個 ×1 只是雜訊);
                # 被視野左緣裁掉的那段也不標 —— 標在裁切點上會讓人以為那裡是起點
                if stacks > 1 and st >= vs and bx1 - bx0 >= BUFF_STACK_MIN_W:
                    c.create_text(bx0 + 2, y + BUFF_BAR_H / 2, text=f"×{stacks}",
                                  anchor="w", fill=COL_BUFF_STACK_TXT,
                                  font=(FONT_UI, BUFF_STACK_PT, "bold"))
            # 名稱放左側欄位、靠右對齊 —— 與傷害圖的縱軸刻度 (x0 - 6, anchor="e")
            # 同一個位置,兩張圖的左緣才連成一條線
            shown = self._fit_buff_name(nm, x0 - BUFF_NAME_GAP)
            c.create_text(x0 - BUFF_NAME_GAP, y + BUFF_BAR_H / 2, text=shown,
                          anchor="e", fill=COL_BUFF_NAME,
                          font=(FONT_UI, BUFF_NAME_PT, "bold"))
            if shown != nm:
                # 命中範圍取整列高,不是只有文字那幾 px —— 8pt 的字高不到 11px,
                # 逼使用者精準壓在字上等於這功能不能用
                row_top = BUFF_AXIS_PAD + i * BUFF_ROW_H
                self._buff_name_hits.append((row_top, row_top + BUFF_ROW_H, nm))

    def _on_buff_motion(self, e):
        """滑過被截斷的 buff 名稱時,在旁邊顯示全名。"""
        c = self.buffbar
        c.delete("bufftip")
        if e.x >= self._buff_name_x:      # 只有左側名稱欄有作用,長條區不理
            return
        for top, bottom, full in self._buff_name_hits:
            if top <= e.y < bottom:
                break
        else:
            return
        f = self._buff_name_font
        pad, tw = 5, (f.measure(full) if f else len(full) * 12)
        th = BUFF_ROW_H
        # 預設放在游標右下;貼到右緣就翻到左邊,貼到下緣就翻到上面 ——
        # canvas 只有幾十 px 高,不翻的話 tooltip 會有一半在外面看不到
        x = e.x + 12
        if x + tw + pad * 2 > c.winfo_width():
            x = max(0, e.x - 12 - tw - pad * 2)
        y = e.y + 6
        if y + th > c.winfo_height():
            y = max(0, e.y - 6 - th)
        c.create_rectangle(x, y, x + tw + pad * 2, y + th,
                           fill=COL_TIP_BG, outline=COL_TIP_BORDER,
                           tags="bufftip")
        c.create_text(x + pad, y + th / 2, text=full, anchor="w",
                      fill=COL_TIP_TXT, font=(FONT_UI, BUFF_NAME_PT),
                      tags="bufftip")

    def _set_status(self, text, error=False):
        self.status.configure(text=text,
                              text_color="#e06c6c" if error else "#9a9a9a")

    # ---------- 圖表 ----------
    def _on_chart_resize(self, _evt=None):
        # 拖曳視窗時 Configure 會連發,debounce 一下避免重畫打結
        if self._resize_job is not None:
            self.root.after_cancel(self._resize_job)
        self._resize_job = self.root.after(60, self._draw_chart)

    def _slot_seconds(self, plot_w):
        """一格代表幾秒。預設 1 秒;可視區間塞不下時 (每格 < MIN_SLOT_PX) 才併格。
        依「可視秒數」而非整場長度計算 —— 放大後格子變寬,自然會回到每格 1 秒。
        """
        if plot_w <= 0:
            return 1
        return max(1, math.ceil(self.view_span / (plot_w / MIN_SLOT_PX)))

    def _plot_geom(self):
        """回傳 (x0, plot_w);尺寸還沒成形或沒資料時回 None。滑鼠事件與繪圖共用。"""
        if self.agg is None:
            return None
        W = self.chart.winfo_width()
        plot_w = W - PAD_L - PAD_R
        if W < 80 or plot_w < 20:
            return None
        return PAD_L, plot_w

    def _clamp_view(self):
        """把可視區間夾回合法範圍。縮放/橫移/換檔後一律走這裡,避免各處各夾一次。"""
        n = self.agg.n_sec
        self.view_span = max(min(MIN_VIEW_SEC, n), min(self.view_span, n))
        self.view_start = max(0, min(self.view_start, n - self.view_span))

    # ---------- 滑鼠:滾輪縮放 / 右鍵橫移 ----------
    def _on_wheel(self, e):
        geom = self._plot_geom()
        if geom is None:
            return
        x0, plot_w = geom
        # Windows 的 delta 是 ±120、macOS 是小整數、X11 則靠 num 4/5 —— 只取方向
        if getattr(e, "num", 0) in (4, 5):
            zoom_in = (e.num == 4)
        else:
            zoom_in = getattr(e, "delta", 0) > 0
        # 以游標所在時間為錨點:放大時游標下的那一秒留在原位,才不會越縮越偏
        frac = min(1.0, max(0.0, (e.x - x0) / plot_w))
        anchor = self.view_start + frac * self.view_span
        span = self.view_span / ZOOM_STEP if zoom_in else self.view_span * ZOOM_STEP
        self.view_span = max(1, int(round(span)))
        self.view_start = int(round(anchor - frac * self.view_span))
        self._clamp_view()
        self._draw_chart()
        # 重畫已把 hover 清掉,但游標還停在原處 —— 立刻依新版面重算,
        # 否則縮放後 tooltip 會消失到使用者再動一下滑鼠為止
        self._on_motion(e)

    def _on_pan_start(self, e):
        if self._plot_geom() is not None:
            self._pan = (e.x, self.view_start)

    def _on_pan_move(self, e):
        geom = self._plot_geom()
        if self._pan is None or geom is None:
            return
        _x0, plot_w = geom
        # 往左拖 = 看更晚的時間,所以位移取負號
        sec_per_px = self.view_span / plot_w
        self.view_start = int(round(self._pan[1] - (e.x - self._pan[0]) * sec_per_px))
        self._clamp_view()
        self._draw_chart()

    def _on_pan_end(self, _e):
        self._pan = None

    # ---------- 滑鼠:hover 提亮 + tooltip ----------
    def _slot_at(self, x, y):
        """游標位置 → 格 index;不在繪圖區內或該格沒傷害則回 None。
        y 只要求落在繪圖區內,不要求真的壓在色塊上 —— 長條細到 1px 時,
        逼使用者精準命中色塊等於這功能不能用。
        """
        gm = self._geom
        if gm is None or not (gm["y_top"] <= y <= gm["y_bottom"]):
            return None
        if not (gm["x0"] <= x < gm["x0"] + gm["plot_w"]):
            return None
        i = int((x - gm["x0"]) / gm["slot_w"])
        if not (0 <= i < gm["n_slots"]) or not gm["slot_total"][i]:
            return None
        return i

    def _on_motion(self, e):
        self._shift = bool(getattr(e, "state", 0) & 0x0001)
        slot = self._slot_at(e.x, e.y)
        if slot is None:
            self._clear_hover()
            return
        if slot != self._hover_slot:
            self._clear_hover()
            for item, color in self._bar_items.get(slot, ()):
                self.chart.itemconfigure(item, fill=lighten(color))
            self._highlight_buffs(slot)
            self._hover_slot = slot
        # 位置要記在 _clear_hover 之後 —— 那支會把它歸零,先寫會被洗掉,
        # Shift 原地切換模式就會失效
        self._hover_xy = (e.x, e.y)
        # tooltip 要跟著游標走,所以每次移動都重畫 (只有幾個 item,很便宜)
        self.chart.delete("tooltip")
        self._draw_tooltip(slot, e.x, e.y)

    def _highlight_buffs(self, slot):
        """把「這一格的時間範圍內生效中」的 buff 方塊換成亮色。

        只作用在持續軸上真的畫出來的方塊 —— 沒被選進時間軸的 buff 本來就沒有
        item,自然不會被提亮。
        併格時 (g > 1) 一格代表好幾秒,只要方塊與這段時間有交集就算生效。
        """
        gm = self._geom
        if gm is None or not self._buff_seg_items:
            return
        lo = gm["vs"] + slot * gm["g"]
        hi = lo + gm["g"]
        for item, st, en in self._buff_seg_items:
            if st < hi and en > lo:
                self.buffbar.itemconfigure(item, fill=COL_BUFF_BAR_HI)
                self._buff_hl_items.append(item)

    def _set_shift(self, on):
        """Shift 狀態改變 → 若正 hover 著,原地把 tooltip 換成另一種模式。"""
        if on == self._shift:
            return
        self._shift = on
        if self._hover_slot is not None and self._hover_xy:
            self.chart.delete("tooltip")
            self._draw_tooltip(self._hover_slot, *self._hover_xy)

    def _clear_hover(self):
        """還原提亮的色塊並收掉 tooltip。整張重畫時 item 已失效,交給 _draw_chart 歸零。"""
        if self._hover_slot is not None:
            for item, color in self._bar_items.get(self._hover_slot, ()):
                self.chart.itemconfigure(item, fill=color)
            self._hover_slot = None
        # 提亮的 buff 方塊一併還原。整張重畫時 item 已失效,_draw_buffs 會清空這份
        for item in self._buff_hl_items:
            self.buffbar.itemconfigure(item, fill=COL_BUFF_BAR)
        self._buff_hl_items = []
        self._hover_xy = None
        self.chart.delete("tooltip")

    def _hit_rows(self, t_start, t_end, hits):
        """Shift 模式:列出這格內的每一筆傷害。

        高頻技能一秒打十幾下、併格時更多,全列出來 tooltip 會長到蓋住整張圖,
        所以硬性只列 TOOLTIP_MAX_HITS 筆,其餘收成一行報筆數 —— 逐筆看完整清單
        本來就不是 tooltip 該扛的事。
        """
        a = self.agg
        sel = self.selected_skills
        rows = []
        shown = 0
        rest_dmg = 0
        for sec in range(t_start, t_end):
            rng = a.sec_range[sec]
            if rng is None:
                continue
            for _ts, _tid, sid, dmg, flags in a.events[rng[0]:rng[1]]:
                name = display_name_for(sid, self.merge_var.get())
                if sel and name not in sel:
                    continue
                if shown >= TOOLTIP_MAX_HITS:
                    rest_dmg += dmg
                    continue
                tag = tags_text(flags)
                rows.append(((f"{dmg:,}", f"{tag}  {name}" if tag else name),
                             a.colors.get(name, SKILL_COLOR_REST)))
                shown += 1
        if shown < hits:
            rows.append(((f"…另有 {hits - shown} 筆未列出 (合計 {rest_dmg:,})",),
                         COL_AXIS_TXT))
        return rows

    def _draw_tooltip(self, slot, mx, my):
        """在 Canvas 上直接畫 tooltip (不開 Toplevel:免視窗管理、不搶焦點)。
        每個技能一行、用該技能的顏色 —— 顏色就是圖上色塊與表格色標的同一套。
        """
        c = self.chart
        gm = self._geom
        a = self.agg
        g, vs = gm["g"], gm["vs"]
        t_start = vs + slot * g
        t_end = min(t_start + g, a.n_sec)
        total = gm["slot_total"][slot]
        per = gm["slot_skill"][slot]
        hits = sum(cell[1] for cell in per.values())

        head = fmt_mmss(t_start) if g == 1 else f"{fmt_mmss(t_start)}~{fmt_mmss(t_end)}"
        rows = [((f"{head}    {total:,}  ({hits} 次命中)",), COL_TIP_TXT)]
        if self._shift:
            rows.extend(self._hit_rows(t_start, t_end, hits))
        else:
            ranked = sorted(per.items(), key=lambda kv: kv[1][0], reverse=True)
            for name, (dmg, n) in ranked[:TOOLTIP_MAX_SKILLS]:
                rows.append(((f"{name}    {dmg:,} ({dmg * 100.0 / total:.1f}%)  {n} 次",),
                             a.colors.get(name, SKILL_COLOR_REST)))
            if len(ranked) > TOOLTIP_MAX_SKILLS:
                rest = sum(cell[0] for _n, cell in ranked[TOOLTIP_MAX_SKILLS:])
                rows.append(((f"…其他 {len(ranked) - TOOLTIP_MAX_SKILLS} 項    {rest:,}",),
                             COL_AXIS_TXT))
            rows.append((("按住 Shift 顯示每筆傷害",), COL_AXIS_TXT))

        # 先全部畫在原點量尺寸,再依量到的寬度排版、整組搬到定位 ——
        # Canvas 沒有事前量文字的 API,也沒有 Text widget 那種 tab stop,
        # 所以「傷害靠右」只能自己算欄寬把每個 item 推到定位 (空白補齊在
        # 比例字體下對不齊:空白的寬度不等於數字的寬度)
        items = []          # (item, 第幾列, 第幾欄)
        line_h = 0
        for i, (cells, color) in enumerate(rows):
            for col, text in enumerate(cells):
                it = c.create_text(0, 0, text=text, anchor="nw", fill=color,
                                   font=(FONT_UI, 10), tags="tooltip")
                if not line_h:      # 用第一行的實際高度當行距
                    bb = c.bbox(it)
                    line_h = (bb[3] - bb[1]) + 3
                items.append((it, i, col))
        # 第 0 欄 (傷害) 的欄寬 = 該欄最寬的一筆
        col0_w = max((c.bbox(it)[2] - c.bbox(it)[0]
                      for it, _r, col in items if col == 0 and len(rows[_r][0]) > 1),
                     default=0)
        for it, row_i, col in items:
            bb = c.bbox(it)
            if len(rows[row_i][0]) == 1:      # 單欄列 (標題 / 摘要 / 省略行) 靠左
                x = 0
            elif col == 0:                    # 傷害:右緣對齊欄寬
                x = col0_w - (bb[2] - bb[0])
            else:
                x = col0_w + TOOLTIP_COL_GAP
            c.coords(it, x, row_i * line_h)
        items = [it for it, _r, _c in items]
        bb = c.bbox("tooltip")
        w, h = bb[2] - bb[0], bb[3] - bb[1]
        W, H = c.winfo_width(), c.winfo_height()
        # 預設放右下;貼到邊界就翻到另一側,免得被裁掉
        px = mx + 16 if mx + 16 + w + 8 <= W else mx - 16 - w
        py = my + 14 if my + 14 + h + 8 <= H else my - 14 - h
        px = max(6, min(px, W - w - 6))
        py = max(6, min(py, H - h - 6))
        c.move("tooltip", px - bb[0], py - bb[1])
        # 背板最後畫 = 蓋在文字上,所以再把文字抬回最上層
        c.create_rectangle(px - 6, py - 4, px + w + 6, py + h + 4,
                           fill=COL_TIP_BG, outline=COL_TIP_BORDER,
                           tags="tooltip")
        for it in items:
            c.tag_raise(it)

    def _draw_chart(self):
        self._resize_job = None
        c = self.chart
        c.delete("all")
        # 整張重畫 = 舊的 item id 全失效,hover 狀態一起歸零
        self._bar_items, self._hover_slot, self._geom = {}, None, None
        W, H = c.winfo_width(), c.winfo_height()
        if W < 80 or H < 60:
            return
        if self.agg is None:
            c.create_text(W // 2, H // 2, text="讀取存檔後在此顯示傷害時間軸",
                          fill="#666666", font=(FONT_UI, 13))
            self.buffbar.delete("all")
            return

        a = self.agg
        plot_w = W - PAD_L - PAD_R
        plot_h = H - PAD_T - PAD_B
        if plot_w < 20 or plot_h < 20:
            return
        x0, y0 = PAD_L, PAD_T          # 繪圖區左上
        y_bottom = PAD_T + plot_h

        self._clamp_view()
        vs, vspan = self.view_start, self.view_span
        g = self._slot_seconds(plot_w)
        n_slots = math.ceil(vspan / g)
        slot_w = plot_w / n_slots

        # 併格:把 g 秒的每秒桶加總成一格 (資料仍是 1 秒解析度,只有畫面在併)
        sel = self.selected_skills
        slot_total, slot_skill, slot_end = [], [], []
        for i in range(n_slots):
            lo = vs + i * g
            hi = min(lo + g, vs + vspan, a.n_sec)
            tot = 0
            per = {}
            for s in range(lo, hi):
                tot += self.f_sec_total[s]
                for name, (dmg, hits) in a.sec_skill[s].items():
                    if sel and name not in sel:
                        continue
                    cell = per.get(name)
                    if cell is None:
                        per[name] = [dmg, hits]
                    else:
                        cell[0] += dmg
                        cell[1] += hits
            slot_total.append(tot)
            slot_skill.append(per)
            slot_end.append(hi)

        # 兩條曲線各自可關。關掉的不算進右軸上限 —— 否則關掉高聳的 5 秒線後,
        # 剩下那條仍被壓在圖表底部,看起來像沒關到。
        series = []
        if self.show_dps_var.get():
            # 累積平均 DPS = 從開場到該格結束的總傷害 ÷ 已過秒數。
            # 用前綴和而非可視範圍內的累加 —— 放大到中段時仍是「整場累積」的
            # 那條線,不會因為視野變了就換一個意思。
            series.append(([self.f_cum[end] / max(1.0, min(end - a.first_sec, a.duration))
                            for end in slot_end],
                           COL_DPS_LINE, "累積平均 DPS"))
        if self.show_dps5_var.get():
            # 最近 DPS_WINDOW_SEC 秒的 DPS。分母用「實際窗長」而非固定 5 —— 開場
            # 前四秒的窗還沒滿,除以 5 會把起手的爆發壓成看起來很低。
            # 併格時 (g>1) 只在每格結束取樣,但窗長 5 秒 > 併格秒數的常見值,
            # 相鄰取樣點的窗互相重疊,爆發不會整段漏掉。
            vals = []
            for end in slot_end:
                lo = max(0, end - DPS_WINDOW_SEC)
                vals.append((self.f_cum[end] - self.f_cum[lo]) / (end - lo))
            series.append((vals, COL_DPS5_LINE, f"{DPS_WINDOW_SEC}秒 DPS"))

        # 縱軸湊到整數級距 (見 nice_axis);右軸沿用左軸的格數,兩邊的刻度才會
        # 落在同一條格線上 —— 各自取格數的話右邊的數字會浮在格線之間
        bar_step, bar_top, n_lines = nice_axis(max(slot_total) or 1)
        # 開著的線共用右軸:同樣是 DPS,分開縮放會讓「藍線比黃線高」變成假象
        dps_peak = max((max(v) for v, _c, _t in series), default=0) or 1
        dps_step, dps_top, _n = nice_axis(dps_peak, n_lines)
        dps_top = dps_step * n_lines

        # 格線 + 左右軸刻度 (左=每格傷害,右=DPS)
        for k in range(n_lines + 1):
            y = y_bottom - plot_h * k / n_lines
            c.create_line(x0, y, x0 + plot_w, y, fill=COL_GRID)
            c.create_text(x0 - 6, y, text=fmt_compact(bar_step * k),
                          anchor="e", fill=COL_AXIS_TXT, font=(FONT_UI, 10))
            # 右軸刻度用中性色:兩條線共用這條軸,染成任一條線的顏色都會誤導。
            # 兩條都關掉時右軸沒有東西在用,連刻度一起收掉
            if series:
                c.create_text(x0 + plot_w + 6, y,
                              text=fmt_compact(dps_step * k),
                              anchor="w", fill=COL_AXIS_TXT, font=(FONT_UI, 10))

        # 堆疊長條:同一格內依總傷害排名由下往上疊,顏色與表格一致
        bar_w = max(1.0, slot_w - 1.0)
        for i, per in enumerate(slot_skill):
            if not per:
                continue
            bx = x0 + i * slot_w
            acc = 0
            items = self._bar_items[i] = []
            for name in a.order:
                cell = per.get(name)
                if not cell or not cell[0]:
                    continue
                dmg = cell[0]
                top = y_bottom - plot_h * (acc + dmg) / bar_top
                bottom = y_bottom - plot_h * acc / bar_top
                # 極細的長條 (< 1px) 會被 Canvas 畫成空的,補到至少 1px
                if bottom - top < 1:
                    top = bottom - 1
                color = a.colors[name]
                # 記下 (item, 原色) 供 hover 提亮後還原 —— 移開時只改回這幾個色塊,
                # 不必為了取消高亮整張圖重畫
                items.append((c.create_rectangle(bx, top, bx + bar_w, bottom,
                                                 fill=color, width=0), color))
                acc += dmg

        def draw_series(values, color):
            pts = []
            for i, v in enumerate(values):
                pts.extend((x0 + i * slot_w + slot_w / 2,
                            y_bottom - plot_h * v / dps_top))
            if len(pts) >= 4:
                c.create_line(*pts, fill=color, width=2, smooth=False)
            elif len(pts) == 2:
                # 只有一格 (放到最大或只有一秒資料) 時折線畫不出來,補一個點
                c.create_oval(pts[0] - 2, pts[1] - 2, pts[0] + 2, pts[1] + 2,
                              fill=color, width=0)

        # 依 series 順序畫,5 秒線在後 = 疊在上面:爆發的起伏是這張圖要看的重點
        for values, color, _text in series:
            draw_series(values, color)

        c.create_line(x0, y_bottom, x0 + plot_w, y_bottom, fill="#555555")

        # 時間軸:約 6 個刻度,取整格邊界避免標籤與長條錯位
        ticks = min(6, n_slots)
        step = max(1, n_slots // ticks)
        for i in range(0, n_slots, step):
            x = x0 + i * slot_w
            c.create_text(x, y_bottom + 12, text=fmt_mmss(vs + i * g),
                          anchor="n", fill=COL_AXIS_TXT, font=(FONT_UI, 10))
        c.create_text(x0, y0 - 2, text=f"每格傷害 (每格 {g} 秒)" if g > 1
                      else "每秒傷害", anchor="nw", fill=COL_AXIS_TXT,
                      font=(FONT_UI, 10))
        # 右上角圖例:只列出開著的線,由右往左排。每個標籤用前一個的 bbox 定位 ——
        # 固定像素偏移會在不同字體/縮放下疊在一起
        right = x0 + plot_w
        for _values, color, text in reversed(series):
            lbl = c.create_text(right, y0 - 2, text=text, anchor="ne",
                                fill=color, font=(FONT_UI, 10))
            bx = c.bbox(lbl)
            if bx:
                right = bx[0] - 10
        span_txt = f"顯示 {fmt_mmss(vs)}~{fmt_mmss(min(vs + vspan, a.n_sec))}"
        if vspan >= a.n_sec:
            span_txt += " (整場)"
        self.chart_hint.configure(
            text=f"每格 {g} 秒{' (已自動併格)' if g > 1 else ''}    {span_txt}"
                 "    滾輪縮放,右鍵拖曳橫移")
        # hover 命中判定要的座標與資料,畫完才定案 (併格數、slot 寬都在上面才算出來)
        self._geom = {"x0": x0, "plot_w": plot_w, "y_top": y0,
                      "y_bottom": y_bottom, "slot_w": slot_w,
                      "n_slots": n_slots, "g": g, "vs": vs,
                      "slot_total": slot_total, "slot_skill": slot_skill}
        # Buff 軸跟著同一組座標重畫 —— 縮放、橫移、resize 都會走到這裡
        self._draw_buffs(x0, plot_w, vs, g, n_slots)

    # ---------- 技能統計表 ----------
    # (欄名, 寬度, 對齊)  —— 欄位與參考圖一致,數值語意與主程式相同
    COLUMNS = (("技能", 200, "w"), ("貢獻度", 70, "e"), ("總傷害", 105, "e"),
               ("DPS", 90, "e"), ("命中次數", 75, "e"), ("爆擊", 62, "e"),
               ("強擊", 62, "e"), ("連擊", 62, "e"), ("追擊", 62, "e"),
               ("最低", 90, "e"), ("最高", 90, "e"), ("平均", 90, "e"))

    def _build_table(self):
        for w in self.table.winfo_children():
            w.destroy()
        a = self.agg
        if a is None or not a.order:
            return

        # 表頭與資料列共用同一個 grid,欄寬用 minsize 固定;技能名那欄可伸縮
        for i, (_n, wd, _anchor) in enumerate(self.COLUMNS):
            self.table.grid_columnconfigure(i + 1, minsize=wd,
                                            weight=1 if i == 0 else 0)
        self.table.grid_columnconfigure(0, minsize=18)   # 顏色標記 (即圖表圖例)

        for i, (name, _wd, anchor) in enumerate(self.COLUMNS):
            ctk.CTkLabel(self.table, text=name, font=(FONT_UI, 12, "bold"),
                         text_color="#bfbfbf", anchor=anchor
                         ).grid(row=0, column=i + 1, sticky="ew", padx=4, pady=(2, 4))

        self.row_widgets = {}
        for r, name in enumerate(a.order, start=1):
            s = a.skills[name]
            bg = COL_ROW_ALT if r % 2 else "transparent"
            widgets = [ctk.CTkLabel(self.table, text="■", text_color=a.colors[name],
                                    font=(FONT_UI, 12), fg_color=bg, width=18)]
            widgets[0].grid(row=r, column=0, sticky="nsew")
            cells = (
                name,
                f"{s['damage'] * 100.0 / a.total:.1f}%",
                f"{s['damage']:,}",
                f"{s['damage'] / a.duration:,.0f}",
                f"{s['hits']:,}",
                self._fmt_rate(name, "爆擊"),
                self._fmt_rate(name, "強擊"),
                self._fmt_rate(name, "連擊"),
                self._fmt_rate(name, "追擊"),
                f"{s['min']:,}",
                f"{s['max']:,}",
                f"{s['damage'] / s['hits']:,.0f}",
            )
            for i, ((_n, _wd, anchor), text) in enumerate(zip(self.COLUMNS, cells)):
                lbl = ctk.CTkLabel(self.table, text=text, font=(FONT_UI, 12),
                                   anchor=anchor, fg_color=bg,
                                   text_color="#e0e0e0" if i == 0 else "#c8c8c8")
                lbl.grid(row=r, column=i + 1, sticky="nsew", padx=4, pady=1)
                widgets.append(lbl)
            # 整列都可點:只綁技能名那格的話,點右半邊的數字沒反應會像壞掉
            for w in widgets:
                w.configure(cursor="hand2")
                w.bind("<Button-1>", lambda _e, n=name: self._toggle_skill(n))
            self.row_widgets[name] = (widgets, bg)
        self._restyle_rows()

    # (欄名, 寬度, 對齊) —— BUFF 統計只有三欄,名稱那欄伸縮
    # 寬度與對齊沿用技能表的第一欄 (COLUMNS[0]),兩張表的名稱欄才等寬
    BUFF_COLUMNS = (("BUFF名稱", COLUMNS[0][1], "w"), ("覆蓋率", 90, "e"),
                    ("生效時間", 110, "e"))

    def _build_buff_table(self):
        for w in self.buff_table.winfo_children():
            w.destroy()
        self.buff_row_widgets = {}
        if not self.buff_stats:
            ctk.CTkLabel(self.buff_table, text="此存檔沒有 BUFF 記錄",
                         font=(FONT_UI, 12), text_color="#7a7a7a",
                         anchor="w").grid(row=0, column=0, sticky="w", padx=6, pady=4)
            return
        # 第 0 欄留白,寬度與技能表的顏色標記欄相同 —— 沒有它的話兩張表的
        # 名稱雖然等寬,起點還是會差 18px,看起來仍舊沒對齊
        self.buff_table.grid_columnconfigure(0, minsize=18)
        for i, (_n, wd, _a) in enumerate(self.BUFF_COLUMNS):
            self.buff_table.grid_columnconfigure(i + 1, minsize=wd,
                                                 weight=1 if i == 0 else 0)
        # 尾端補一根固定寬度的空欄,讓兩張表的「非伸縮欄總寬」相等。
        # 名稱欄是唯一 weight=1 的欄,會把剩餘空間全吃下去 —— BUFF 表只有三欄,
        # 不補的話它拿到的剩餘空間遠多於技能表,實際寬度就差了三倍
        # (實測 1400px 視窗下:技能名 345px vs BUFF 名 1003px)
        pad = (sum(w for _n, w, _a in self.COLUMNS[1:])
               - sum(w for _n, w, _a in self.BUFF_COLUMNS[1:]))
        self.buff_table.grid_columnconfigure(len(self.BUFF_COLUMNS) + 1,
                                             minsize=max(0, pad), weight=0)
        sort_col, sort_desc = self._buff_sort
        for i, (name, _wd, anchor) in enumerate(self.BUFF_COLUMNS):
            head = name + (" ▼" if sort_desc else " ▲") if i == sort_col else name
            self._buff_head[name] = lbl = ctk.CTkLabel(
                self.buff_table, text=head, font=(FONT_UI, 12, "bold"),
                text_color="#ffffff" if i == sort_col else "#bfbfbf",
                anchor=anchor, cursor="hand2")
            lbl.grid(row=0, column=i + 1, sticky="ew", padx=4, pady=(2, 4))
            lbl.bind("<Button-1>", lambda _e, k=i: self._sort_buff_table(k))
        for r, (nm, secs, pct) in enumerate(self.buff_stats, start=1):
            bg = COL_ROW_ALT if r % 2 else "transparent"
            cells = (nm, f"{pct:.1f}%", fmt_mmss(secs))
            widgets = []
            for i, ((_n, _wd, anchor), text) in enumerate(zip(self.BUFF_COLUMNS, cells)):
                lbl = ctk.CTkLabel(self.buff_table, text=text, font=(FONT_UI, 12),
                                   anchor=anchor, fg_color=bg, cursor="hand2",
                                   text_color="#e0e0e0" if i == 0 else "#c8c8c8")
                lbl.grid(row=r, column=i + 1, sticky="nsew", padx=4, pady=1)
                # 整列都可點 (同技能表:只綁名稱那格的話點右半邊沒反應會像壞掉)
                lbl.bind("<Button-1>", lambda _e, n=nm: self._toggle_buff(n))
                widgets.append(lbl)
            self.buff_row_widgets[nm] = (widgets, bg)
        self._restyle_buff_rows()

    # 各欄的排序鍵。名稱用字串,其餘用數值 —— 全部丟給 sorted 的 key
    _BUFF_SORT_KEYS = (lambda r: r[0], lambda r: r[1], lambda r: r[1])

    def _sort_buff_table(self, col):
        """點表頭切換排序。同一欄再點一次換升冪/降冪。

        「覆蓋率」與「生效時間」是同一個量的兩種寫法 (覆蓋秒數 ÷ 場長),
        排序鍵共用一個,不必分開。
        """
        cur_col, desc = self._buff_sort
        self._buff_sort = (col, not desc if col == cur_col else (col != 0))
        self._apply_buff_sort()
        self._build_buff_table()

    def _apply_buff_sort(self):
        col, desc = self._buff_sort
        self.buff_stats.sort(key=self._BUFF_SORT_KEYS[col], reverse=desc)

    def _toggle_buff(self, name):
        """點一下加入持續軸,再點一下移除。**加在尾端** —— 持續軸的列序就是
        使用者點選的順序,不重排。"""
        if name in self.selected_buffs:
            self.selected_buffs.remove(name)
        else:
            self.selected_buffs.append(name)
        self._apply_buff_filter()

    def clear_buff_filter(self):
        if not self.selected_buffs:
            return
        self.selected_buffs.clear()
        self._apply_buff_filter()

    def _apply_buff_filter(self):
        self._restyle_buff_rows()
        n = len(self.selected_buffs)
        self.clear_buff_btn.configure(state="normal" if n else "disabled")
        # 高度變了要先讓 Tk 套用,_draw_buffs 才量得到新的 winfo_height
        self._sync_buffbar_height()
        self.root.update_idletasks()
        self._draw_chart()

    def _restyle_buff_rows(self):
        """選取中的列改底色 + 名稱轉白,並在名稱前標上它在持續軸的第幾列。"""
        for nm, (widgets, bg) in self.buff_row_widgets.items():
            on = nm in self.selected_buffs
            for i, w in enumerate(widgets):
                w.configure(fg_color=COL_ROW_SEL if on else bg)
            widgets[0].configure(
                text=f"{self.selected_buffs.index(nm) + 1}. {nm}" if on else nm,
                text_color="#ffffff" if on else "#e0e0e0")

    def _fmt_rate(self, name, tag):
        v = self.agg.rate(name, tag)
        return "—" if v is None else f"{v:.0f}%"

    # ---------- 技能過濾 (只影響圖表,表格數字仍是整場的) ----------
    def _toggle_skill(self, name):
        if name in self.selected_skills:
            self.selected_skills.discard(name)
        else:
            self.selected_skills.add(name)
        self._apply_filter()

    def clear_filter(self):
        if not self.selected_skills:
            return
        self.selected_skills.clear()
        self._apply_filter()

    def _apply_filter(self):
        """依目前選取的技能算出圖表要用的每秒總量與前綴和,然後重畫。

        表格不跟著篩 —— 那些數字是整場的,選了技能 A 之後 B 的爆擊率並不會改變,
        把 B 藏起來只會讓人以為資料不見了。要看的是「A 在時間軸上的樣子」。
        """
        a = self.agg
        if a is not None:
            sel = self.selected_skills
            if not sel:
                self.f_sec_total, self.f_cum = a.sec_total, a.cum
            else:
                self.f_sec_total = [
                    sum(cell[0] for n, cell in per.items() if n in sel)
                    for per in a.sec_skill]
                cum = [0] * (a.n_sec + 1)
                for i, v in enumerate(self.f_sec_total):
                    cum[i + 1] = cum[i] + v
                self.f_cum = cum
            self._restyle_rows()
        n = len(self.selected_skills)
        self.filter_label.configure(text=f"已過濾 {n} 個技能" if n else "")
        self.clear_filter_btn.configure(state="normal" if n else "disabled")
        self._draw_chart()

    def _restyle_rows(self):
        """選取中的列改底色 + 技能名轉白;未選取的回到原本的斑馬紋。"""
        for name, (widgets, bg) in self.row_widgets.items():
            on = name in self.selected_skills
            for i, w in enumerate(widgets):
                w.configure(fg_color=COL_ROW_SEL if on else bg)
                if i == 1:   # 技能名那格
                    w.configure(text_color="#ffffff" if on else "#e0e0e0")


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    GraphViewer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
