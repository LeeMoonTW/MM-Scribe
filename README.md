# MM-Scribe

《瑪奇Mobile》個人傷害統計工具
僅適用於台港澳版本

---

## 免責聲明

【 MM Scribe 使用免責聲明 】

一、本工具由社群個人開發，與任何遊戲廠商、發行商並無合作、
    授權或關聯關係，亦非任何官方認可之工具。

二、本工具僅供個人學習研究與傷害分析用途，
    請勿用於任何商業行為或不當競技目的。

三、透過網路封包擷取遊戲資訊，可能違反相關遊戲之服務條款。
    使用者需自行評估風險與後果，包含但不限於
    帳號警告、停權或永久封鎖。

四、本工具僅在本機端解析封包內容，
    不會蒐集、儲存或傳送任何個人資料至外部伺服器。

五、開發者不對使用本工具所產生之任何直接或間接損失
    負任何法律或道義責任。

六、使用本工具即視為您已閱讀並同意上述所有條款。
    若不同意，請立即停止使用並刪除本程式。

---

## 主要功能

- **即時傷害統計**：累積傷害、DPS、爆擊 / 強擊 / 連擊覆蓋率

---

## 系統需求

### Windows

- Windows 10 / 11
- [Npcap](https://npcap.com/) 驅動
- 系統管理員權限（scapy 抓包需要）
- 原始碼版另需 Python 3.x 與相依套件：`customtkinter`、`scapy`、`Brotli`

### macOS

- macOS 13 以上，**Apple Silicon**（遊戲本身是 iOS App on Mac，無法在 Intel Mac 上執行）
- libpcap 為系統內建，**不需要**安裝 Npcap 之類的驅動
- 抓包需要 BPF 裝置權限（見下方使用說明）
- 原始碼版另需 Python 3.12 與相依套件：`customtkinter`、`scapy`、`Brotli`

遊戲在 macOS 上是透過 App Store 安裝的 **iOS App on Mac**，
封包直接走實體網卡，不需要模擬器、網路共享或任何轉送設定。
封包格式與 Windows 端相同，解析邏輯共用。

---

## macOS 使用說明

### 1. 解除 Apple 的安全性阻擋

首次開啟 `MM Scribe.app` 時，macOS 會跳出：

> **Apple 無法驗證「MM Scribe」是否為惡意軟體，它可能會損害你的 Mac 或危害你的隱私權。**

這是因為本工具沒有經過 Apple 公證（notarization）—— 那需要付費的 Apple Developer 帳號。
這個提示不代表程式有問題，但也請自行判斷來源是否可信。

**方法 A：終端機一行解決（推薦，所有 macOS 版本通用）**

```bash
xattr -dr com.apple.quarantine "/Applications/MM Scribe.app"
```

`com.apple.quarantine` 是檔案從網路下載時被貼上的標記，移除後就不會再被攔。
路徑請換成 `.app` 實際存放的位置。

**方法 B：從系統設定允許**

1. 在警告對話框點「**完成**」（不要點「移到垃圾桶」）
2. 開啟「**系統設定**」→「**隱私權與安全性**」
3. 捲到最下方的「**安全性**」區段，會看到「已阻擋使用『MM Scribe』…」
4. 點「**仍要打開**」，再確認一次並輸入密碼

> macOS 15 Sequoia 起，Apple 已移除舊版「按住 Control 點按 →『打開』」的繞過方式，
> 必須改走上述系統設定的流程。

### 2. 授予抓包權限

抓封包需要以讀寫模式開啟 `/dev/bpf*`，它預設只有 root 能存取。四選一：

**方法 A：直接在程式裡設定（最簡單，推薦）**

打開 MM Scribe 即可 —— 偵測到沒有權限時會自動跳出說明視窗，
點「設定」並輸入一次密碼就完成，之後每次都能直接點開使用。

**方法 B：用內附腳本設定（與方法 A 等效，但可以先看清楚會改什麼）**

```bash
./macos-bpf-access.sh status     # 先看目前狀態,不需 sudo
./macos-bpf-access.sh install    # 設定免 sudo 抓包
./macos-bpf-access.sh uninstall  # 隨時可還原
```

方法 A 與 B 的原理都與 Wireshark 的 ChmodBPF 相同，也沿用同一個 `access_bpf`
群組，兩者可並存：建立群組並把你的帳號加入，再安裝一個開機執行的 LaunchDaemon，
把 `/dev/bpf*` 交給該群組。

> ⚠ **安全性取捨**：設定完成後，`access_bpf` 群組的成員不需要密碼就能監聽
> 這台電腦上的所有網路流量。這正是 Wireshark 的做法，但請確認你接受這個取捨；
> 不想長期開著就用 `uninstall` 還原。

**方法 C：安裝 Wireshark 的 ChmodBPF**

若你本來就會用 [Wireshark](https://www.wireshark.org/)，安裝它 dmg 內附的
ChmodBPF 即可，效果相同，不需要再跑方法 A 或 B（程式偵測到它已安裝時也不會再提示）。

**方法 D：每次以 sudo 啟動**

不想更動系統權限的話就維持用 sudo。`.app` 沒有「以管理員身分執行」這種選項，
需從終端機啟動：

```bash
sudo "/Applications/MM Scribe.app/Contents/MacOS/MM Scribe"
```

### 3. 開始使用

1. 先開好遊戲並登入
2. 啟動 MM Scribe，程式會自動偵測收包網卡（通常兩秒內完成並選到 Wi-Fi 那張）
3. 按「開始」，然後進遊戲打怪，傷害統計就會即時跳動

若一直沒有數據，點「設定」→「網路檢測」可以逐項確認權限、驅動與網卡狀態。

### 從原始碼執行

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python scapy==2.7.0 customtkinter==5.2.2 Brotli==1.1.0
./run-macos.sh
```

`run-macos.sh` 會自動判斷是否需要提權，並處理 uv 版 Python 的 Tcl/Tk 路徑問題。
直接跑原始碼不會遇到上面第 1 點的 Gatekeeper 問題。

---

## 設定檔說明

設定檔須放在 `MM Scribe.exe` 同一資料夾（或原始碼版的 [Source/](Source/) 資料夾內），修改後重啟程式生效。

macOS 打包成 `.app` 之後，設定檔改放在 `~/Library/Application Support/MM Scribe/`
（`.app` 內部不可寫，首次啟動會自動把預設檔複製過去）；直接跑原始碼時仍然是讀 [Source/](Source/)。

### [skills.ini](Source/skills.ini) — 技能 ID 對照與合併群組

```ini
[職業名稱]
0x技能ID = 顯示名稱

[合併群組-職業名稱]
合併名稱 = 顯示名稱1, 顯示名稱2, 顯示名稱3
```

- 技能 ID 支援 `0x64d5b11d` 或 `64d5b11d` 兩種寫法，大小寫皆可
- 以 `;` 或 `#` 開頭的行為註解
- 找不到對應 ID 的技能會顯示原始 hex ID

### [settings.ini](Source/settings.ini) — 顯示 / 追蹤 / 排版

```ini
[Display]
font_scale = 1.00              ; 字體縮放 1.0 ~ 2.0

[Tracking]
track_damage = true            ; 攻擊數值追蹤
track_heal = false             ; 治癒數值追蹤（Beta）

[Layout]
popout_log = false             ; 攻擊事件日誌獨立視窗
popout_skill = false           ; 技能傷害排行獨立視窗
```

---

## 打包方式

### Windows

**開發版**（顯示開發者選項）：

```bash
python -m PyInstaller --onefile --noconsole --collect-data customtkinter MabinogiMobileScribe_Beta.py
```

**發布版**（隱藏開發者選項）：

```bash
type nul > RELEASE.marker
python -m PyInstaller --onefile --noconsole --collect-data customtkinter --add-data "RELEASE.marker;." MabinogiMobileScribe_Beta.py
```

### macOS

`--add-data` 的分隔符是 `:` 而非 `;`，且要用 `--windowed` 產生 `.app`：

```bash
touch RELEASE.marker
python -m PyInstaller --windowed --collect-data customtkinter --add-data "RELEASE.marker:." MabinogiMobileScribe_Beta.py
```

PyInstaller 只會做 ad-hoc 簽章（沒有 Team ID），因此 `.app` 一定會被 Gatekeeper 攔下，
使用者需依「[macOS 使用說明](#macos-使用說明)」第 1 點解除。要根治得有付費的 Apple
Developer 帳號做簽章與公證。

另外 `.app` 沒有「以系統管理員身分執行」這種選項，所以程式在首次啟動偵測到沒有
BPF 權限時，會引導使用者做一次性設定（見使用說明第 2 點）。`macos-bpf-access.sh`
必須跟著打包進 bundle，建置腳本已處理。

程式啟動時會偵測 EXE 內是否包含 `RELEASE.marker` 檔案，存在則隱藏開發者選項按鈕（釋出給他人使用）。

---

## 發版

版號寫在 [Source/MabinogiMobileScribe_Beta.py](Source/MabinogiMobileScribe_Beta.py) 的
`VERSION_STR`，原始碼檔名不帶版號。發版用根目錄的 [release.sh](release.sh)：

```bash
./release.sh 0.53            # 更新版號 → commit → 打 tag → 推送 → 開 draft release
./release.sh 0.53 --dry-run  # 先看它打算做什麼
```

流程細節與檔名調整的原因見 [RELEASING.md](RELEASING.md)。

---

## 社群 / 回報問題

- Discord：<https://discord.gg/NaddqvBVvb>
- GitHub Issues：歡迎回報缺漏的技能 ID、封包格式異常或功能建議
