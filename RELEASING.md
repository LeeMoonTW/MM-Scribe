# MM Scribe — 發版流程

這份文件講兩件事：原始碼檔名為什麼不再帶版號，以及 `release.sh` 怎麼用。

---

## 1. 為什麼原始碼檔名不再帶版號

```
舊：Source/MabinogiMobileScribe_Beta_V0.52.py
新：Source/MabinogiMobileScribe_Beta.py
```

版號寫在檔名裡，代表**每次改版都是一次改名**。改名帶來三個具體代價：

### 代價一：git 看不到「同一個檔案」

改名在 git 眼中是「刪掉一個檔 + 新增一個檔」。`git blame` 會自動跟著改名走，
但 `git log` 不加 `--follow` 就只剩改名後那一筆；GitHub 網頁上的 history 與 blame
也得在每個交界處手動點一次「View blame prior to this change」。主程式有四千多行，
檔名一路從 `V0.43`、`V0.50` 改到 `V0.52`，一共三次改名，等於要點三次才看得完。

### 代價二：每次改版要手動同步 8 處引用

檔名被寫死在這些地方，漏改一處就是一行跑不動的指令：

| 檔案 | 處數 | 內容 |
|---|---|---|
| `README.md` | 3 | 三段 PyInstaller 打包指令 |
| `Source/MabinogiMobileScribe_Beta.py` | 3 | 開頭 docstring 裡的打包說明 |
| `run-macos.sh` | 1 | `SCRIPT=` 指到的原始碼路徑 |
| `Note/MM_Scribe_PacketNotes_Identity.md` | 1 | 程式實作對照的章節標題 |

### 代價三：建置腳本只能靠猜

`MabinogiMobileScribe_BuildTool.bat` / `.sh` 原本是這樣找原始碼的：

```bash
SCRIPT="$(ls -t MabinogiMobileScribe_*.py | head -1)"   # 挑最新修改的那個
```

為的就是「換版號不用改這支腳本」。固定檔名之後這個理由消失了，
而它反而變成風險：工作目錄裡若還留著舊的 `MabinogiMobileScribe_Beta_V0.52.py`，
只要它的修改時間比較新，就會打包到舊程式。所以兩支腳本都改成直接指名，
**找不到才**退回原本的掃描方式（相容還留著舊檔名的工作目錄）。

---

## 2. 版號現在只有一個來源

改名之後，版號唯一的落腳處是主程式裡的這一行：

```python
VERSION_STR = "Beta V0.52"
```

讀它的地方：

| 誰 | 用途 |
|---|---|
| 程式本身 | 視窗標題顯示的版本（`MM Scribe Beta V0.52`） |
| `.github/workflows/build-macos.yml` | 決定發布 zip 的檔名 |
| `release.sh` | 比對／更新版號，並據此打 tag |

發布檔名的格式沒有變，仍然是 `MMScribe.Beta.V0.52.macOS.zip` —— 只是來源從
「解析檔名」換成「讀 VERSION_STR」。

CI 在打 tag 發版時會額外核對 tag 版號與 `VERSION_STR` 是否一致，不一致時發一則
warning 但**不中斷建置**：這時候 zip 還是做得出來，只是檔名版號會對不上 release，
值得提醒，但不值得讓整輪建置白跑。用 `release.sh` 發版的話兩者必然一致，不會踩到。

---

## 3. `release.sh` 用法

放在專案根目錄，跟 `run-macos.sh`、`macos-bpf-access.sh` 同一層。

### 最短路徑

```bash
./release.sh 0.53
```

這一行會依序做完：更新 `VERSION_STR` → commit → 打 tag `v0.53-beta-mac` →
推分支與 tag → 建立 draft release。推送前會問一次 `[y/N]`。

### 參數

| 寫法 | 結果 |
|---|---|
| `./release.sh 0.53` | tag 補成 `v0.53-beta-mac`，`VERSION_STR` 改成 `Beta V0.53` |
| `./release.sh v0.53-beta-mac` | tag 原樣使用，版號一樣取 `0.53` |
| `./release.sh v1.0` | tag 就叫 `v1.0`，`VERSION_STR` 改成 `Beta V1.0` |

`VERSION_STR` 只置換裡面的數字，`Beta`、`V` 這些前後綴原樣保留。
哪天想改成 `V1.0`（拿掉 Beta），手動改一次 `VERSION_STR`，之後腳本就會沿用新格式。

### 選項

| 選項 | 說明 |
|---|---|
| `--dry-run` | 只印出將要執行的指令，不做任何實際變更 |
| `--no-push` | 做完本機 commit 與 tag 就停，最後會印出推送指令讓你自己下 |
| `--no-release` | 推 tag，但不建立 GitHub draft release |
| `--release` | 強制建立 draft release（沒有 `gh` 或未登入時直接失敗） |
| `--remote <名稱>` | 推送目標，預設 `origin` |
| `--branch <名稱>` | 允許發版的分支，預設 `main` |
| `-y`, `--yes` | 跳過互動確認 |
| `-h`, `--help` | 顯示說明 |

沒裝 [`gh`](https://cli.github.com/)（或沒 `gh auth login`）時會自動略過 release
那一步，其餘照跑，不會失敗。

### 它會先擋掉什麼

動手之前會逐項檢查，任何一項不過就停下來，什麼都不改：

| 檢查 | 不過的原因 |
|---|---|
| tag 名稱合法 | 不合法的話要到最後 `git tag` 才失敗，那時版號已經 commit 下去了 |
| 在分支上，且是 `main` | detached HEAD 或功能分支發版，做出來的版本會少東西 |
| 工作區乾淨 | 待會要 commit `VERSION_STR`，夾帶到別的改動就洗不掉了 |
| 與遠端沒有落後或分歧 | tag 會打在少東西的 commit 上，而且 `git push` 也會被拒 |
| tag 尚未存在（本機與遠端都查） | 覆蓋既有 tag 會讓已經下載過的人拿到對不上的版本 |

tag 已存在時腳本**不會代為刪除**，只印出手動刪除的指令 —— 重打 tag 該由人明確決定。

第一次用建議先跑一次 `--dry-run` 看看它打算做什麼：

```bash
./release.sh 0.53 --dry-run
```

`--dry-run` 唯一會實際執行的是 `git fetch`（只更新遠端追蹤 ref，不動工作區也不動分支）。
這是刻意的：不 fetch 的話，落後／分歧檢查會拿過期的資料算，正好在最需要它的時候給出
全綠的假答案。

---

## 4. 完整發版流程

1. 把要發的內容都合進 `main`，`git push` 完
2. `./release.sh 0.53`
3. 到 Actions 看 macOS 建置（約數分鐘），完成後 zip 會自動掛到 draft release
4. Windows 版 exe 要在 Windows 上跑 `Source/MabinogiMobileScribe_BuildTool.bat`，
   再手動附到同一個 release
5. 回到 draft release 寫發版說明，按 Publish

第 4 步是目前唯一沒自動化的環節 —— CI 只有 macOS runner，Windows 版仍是手動建置。

---

## 5. 出狀況時

**tag 打錯了、還沒公開 release**

```bash
git tag -d v0.53-beta-mac                        # 刪本機
git push origin :refs/tags/v0.53-beta-mac        # 刪遠端
```

`VERSION_STR` 的 commit 要不要一起 revert 看情況；只是版號打錯的話，
直接用正確版號再跑一次 `release.sh` 即可，它會把 `VERSION_STR` 蓋成新的。

**CI 說 `tag 是 v0.53-beta-mac，但 VERSION_STR 是「Beta V0.52」`**

代表 tag 是手動打的、沒經過 `release.sh`。建置照樣會完成，但 zip 會叫
`MMScribe.Beta.V0.52.macOS.zip`。修法是刪掉 tag（上面那兩行）後改用 `release.sh` 重發。

**release 還沒建立，但 tag 已經推出去了**

Workflow 找不到 release 時只會留下 artifact 並印一則 notice，不會失敗。
之後手動建立 release，再從那次 workflow run 的 artifact 下載 zip 附上去即可。

**`gh release create` 失敗**

腳本會印 `[略過]` 然後正常結束 —— tag 已經推出去了，少的只是一個草稿，
到 GitHub 網頁上手動建立同名 release 就好。
