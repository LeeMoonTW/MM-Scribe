# MM Scribe — 封包偵測技術筆記

> 給未來的自己 / 未來的 Claude 對話用：快速掌握目前封包解析邏輯與已鎖定的旗標位置。

**最後更新：2026-08-16** — 與第三方整理的 `packet-protocol.md`（版本 2026-08-15）對照後補全。
標示 ★ 或「待驗證」的內容來自該份文件的推導，**尚未用本地封包樣本逐一確認**；標示「100% 確認」「實測」的仍以本地樣本為準。
差異總表見 **§12**。

---

## 1. 資料來源

- **來源**：透過 `scapy.sniff()` 攔截 TCP 封包（BPF 過濾器 `ip net 43.0.0.0/8 and tcp`）
- **需求**：Windows 需安裝 [Npcap](https://npcap.com/) 驅動；程式啟動時會偵測並在底部狀態列顯示
- **權限**：抓封包需要系統管理員身分執行

---

## 2. 封包整體結構

每個 TCP payload 內含多個訊息段落。**標頭是 9 bytes，不是 8**（2026-08-16 與 `packet-protocol.md` 對照後修正）：

```
[packetType 4 bytes LE] [contentLength 4 bytes LE] [encodingType 1 byte] [content ... contentLength bytes]
[packetType 4 bytes LE] [contentLength 4 bytes LE] [encodingType 1 byte] [content ... contentLength bytes]
...
```

程式一段一段掃過去，找 `packetType == 0xE9 0x51 0x00 0x00`（即 **0x51E9 傷害事件**）時展開解析。

### ⚠ 與 `packet-protocol.md` 對照後的三點修正

1. **原本筆記寫的「offset 8 = 未知 byte」其實是 `encodingType`**。
   - `0` = 原始位元組；`1` = **Brotli 壓縮**。目前程式沒有解壓，若某筆傷害封包 `enc==1` 會整段看不到（實測樣本目前都是 `0`，所以沒踩到）。
2. **事件實際總長為 `9 + size`，但程式刻意維持 `offset += 8 + size`**（2026-08-16 評估後決定不改）。
   - 主迴圈是逐 byte 掃 magic：落點**早 1 byte** 只是多掃一輪就會命中；落點**晚 1 byte** 會直接越過下一筆的 magic 開頭，**整筆事件被吃掉**。
   - 9-byte 標頭這個前提來自第三方文件，本地沒有獨立證據（所有 offset 都是實測校準的，整體平移 1 byte 也會自洽）。
   - 因此保留 `+8` 這個「寧可早一格」的保守值，`find_skill_id_after()` 的掃描起點同理。
3. **`packetType` 的數值來自伺服器下發的遠端目錄（`packet_type_config*.enc`），會隨區服／改版變動**。
   - `0x51E9` / `0x4FC5` 是台服當前版本的實測值，**不是協定常數**。改版後若統計歸零，第一個要懷疑的就是這兩個值變了。

### 訊息外層還有 Frame（目前未使用）

完整協定中訊息包在 `FrameStart` … `FrameEnd` 之間（後援值 `934E00000000000000` / `3D4F00000000000000`）。本工具走「直接在 TCP payload 掃 magic」的簡化路徑，不切框；代價是可能掃到框外的偶然對齊（實測未發生）。

### 已知漏包來源：TCP 未重組

協定要求依 `tcp_seq` 重組後再切包。目前 `scapy` 是**逐封包**餵 `parse_payload()`，因此：

- 傷害事件若剛好被切在兩個 TCP segment 之間 → **整筆漏掉**（總傷害與 DPS 會低估）
- 目前 61 bytes 的事件相對 MTU 很小，被切中的機率低，但長時間統計仍會累積誤差

---

## 3. 0x51E9 傷害事件內部佈局

> **身分確認**：`0x51E9` = protocol 的 **`CHANNEL_ShowDamageFloater_NTF`**（傷害數字飄字）。
> 判定依據：傷害在 content+16、旗標在 content+32，完全命中 protocol §6.2 SelfDamage 的第一組候選佈局 `(baseOffset=0, flagsOffset=32)`，且旗標 6 個 bit 的語意與實測標籤 100% 吻合。

從事件 header 起算的相對 offset（`content offset = 本表 offset − 9`）：

| Offset | content | 長度 | 內容 |
|--------|---------|------|------|
| 0..3 | — | 4 | packetType = `e9 51 00 00` |
| 4..7 | — | 4 | contentLength (通常 = `35 00 00 00` = 53) |
| 8 | — | 1 | **`encodingType`**（原筆記誤標為未知 byte）；實測恆為 `0` |
| 9..16 | 0..7 | 8 | **攻擊者 ID**；protocol 定義為 `UInt32 userId@0` + 4 bytes 保留，取 uint64 LE 低 32 位等價 |
| 17..24 | 8..15 | 8 | **目標 ID**（同上，`UInt32 targetId@8`）★ 2026-08-16 起用於「目標篩選」分桶統計 |
| 25..28 | 16..19 | 4 | **傷害數值** (uint32 LE) |
| 29..40 | 20..31 | 12 | 未解（protocol 亦未鎖定） |
| **41..47** | **32..38** | **7** | **旗標區（7 bytes，見 §4）** ← 原本只讀了前 2 bytes |
| 48..49 | 39..40 | 2 | 未解 |
| 50..57 | 41..48 | 8 | protocol 稱 `specialMeta`（8 bytes hex）；`b57` 落在其尾端 |
| 58..60 | 49..52 | 3 | 未解 |

整個事件總長 = 4 + 4 + 1 + 53 = **62 bytes**（原筆記寫 61，少算 enc byte）

### 特殊值
- `dmg_val == 0xFFFFFFFF` → 傷害免疫（不計入統計，只印訊息）★ **本工具獨有發現，protocol 未記載**

### protocol 提到但本工具未處理的防呆
- ShowDamageFloater 的合法條件是 **`userId != targetId` 且兩者皆 ≠ 0**；`userId == targetId` 的對齊是 **decoy（誘餌），必須跳過**。
  目前 `parse_payload()` 沒做這個檢查，理論上可能把誘餌算成一筆傷害。（實測未觀察到，但值得加。）
- protocol 另列 3 組備援佈局 `(16,48)`、`(0,24)`、`(16,40)`，本工具寫死 `(0,32)`。只要 `contentLength == 53` 就是 `(0,32)`，可用 size 當守門條件。

---

## 4. 標籤旗標位置 ★ 2026-08-16 大幅擴充 ★

**旗標是一個連續 7 bytes 的區塊**（`offset+41` .. `offset+47`），原本筆記只鎖定了前 2 bytes。

| 變數名 | 絕對 offset | flags[] index | 狀態 |
|--------|------------|---------------|------|
| `b41` | `offset+41` | flags[0] | 已實作 |
| `b42` | `offset+42` | flags[1] | 已實作 |
| **`b43`** | **`offset+43`** | **flags[2]** | **★ 未實作** |
| **`b44`** | **`offset+44`** | **flags[3]** | **★ 未實作（追擊在這裡）** |
| **`b45`** | **`offset+45`** | **flags[4]** | **★ 未實作（元素屬性在這裡）** |
| `b46` `b47` | `offset+46/47` | flags[5..6] | 未實作，protocol 亦無已知位元 |
| `b57` | `offset+57` | （不在旗標區） | 已實作，本工具獨有 |

> 下表中標「protocol」的位元名稱來自 `packet-protocol.md` §6.2 攻擊旗標表，**尚未用本地封包樣本逐一驗證**。
> 已實測的 6 個標籤與 protocol 命名完全對應（6/6），因此其餘位元的可信度很高，但仍建議錄樣本確認再上正式 tag。

### `b41` = flags[0]（建議新已知遮罩 `0xCD`，未變）

| bit | mask | 標籤 | protocol 名 | 備註 |
|-----|------|------|-------------|------|
| 0 | `0x01` | **爆擊** | `crit_flag` | 100% 確認 |
| 1 | `0x02` | — | `what1` | protocol 也標為未知 |
| 2 | `0x04` | **無防備** | `unguarded_flag` | 需**額外檢查 bit 3=0**，否則會被誤判為破防（兩者共用此 bit） |
| 3 | `0x08` | **破防** | `break_flag` | 100% 確認 |
| 4 | `0x10` | *（見下）* | `what05` | 只在與 bit5 同亮時有已知語意；單獨亮尚無樣本 |
| 5 | `0x20` | *（見下）* | `what06` | — |

> **bit4 + bit5 組合**（2026-08-29 由實測日誌回報，尚未錄封包樣本逐一驗證）：
> `b41 & 0x30 == 0x30` → **延長破防**；`== 0x20` → **終結**。兩者互斥，已上正式 tag。
> `== 0x10`（bit4 單獨亮）語意不明，仍走 `未知(b41.10)`。
| 6 | `0x40` | *（非標籤）* | **`first_hit_flag`** | ★ **原本標為「用途不明」，protocol 命名為「首擊」**。普攻與部分技能會亮，符合「一次施放的第一段命中」語意 |
| 7 | `0x80` | *（非標籤）* | `default_attack_flag` | **普通攻擊指示**：玩家自動攻擊=1；玩家技能 or 寵物攻擊=0。僅用於分類 |

### `b42` = flags[1]（建議新已知遮罩 `0x8F`，原 `0x07`）

| bit | mask | 標籤 | protocol 名 | 備註 |
|-----|------|------|-------------|------|
| 0 | `0x01` | **多重打擊** | `multi_attack_flag` | 寵物多段攻擊測試確認 |
| 1 | `0x02` | **強擊** | `power_flag` | 100% 確認 |
| 2 | `0x04` | **連擊** | `fast_flag` | 100% 確認 |
| 3 | `0x08` | **額外傷害**（非 DoT） | `dot_flag` | ⚠ protocol 命名有誤導性，見 §4.2 |
| 7 | `0x80` | **額外傷害**（非 DoT） | `dot_flag2` | ⚠ 同上。`b42 = 0x88` 在 DoT／追加傷害／地面傷害上都會出現 |

### `b43` = flags[2]

| bit | mask | protocol 名 | 備註 |
|-----|------|-------------|------|
| 0 | `0x01` | `dot_flag3` | **額外傷害**標記的一部分，非 DoT 判據（見 §4.2） |

### `b44` = flags[3] ★ 新增 — **「追擊」在這裡**

| bit | mask | 標籤 | protocol 名 |
|-----|------|------|-------------|
| 3 | `0x08` | **★ 追擊 ★**（仍未驗證） | `add_hit_flag` |
| 4 | `0x10` | **出血／創傷**（✅ 已驗證，見 §4.3） | `bleed_flag` |
| 5 | `0x20` | 暗屬性 | `dark_flag` |
| 6 | `0x40` | 火屬性 | `fire_flag` |
| 7 | `0x80` | 聖屬性 | `holy_flag` |

> 「追擊」原本在 §6 列為「測試資料完全沒出現過，bit 位置未知」。protocol 指出它是 flags[3] bit3，也就是 **`payload[offset+44] & 0x08`**。
>
> **2026-08-16 已接進主程式**：正式標籤 + 上方面板覆蓋率 + 高亮下拉 + 技能排行展開明細。
> 常數在 `DMG_ADD_HIT_BIT`，若實測發現誤判改那一行即可。
> **仍屬未驗證**：本地沒有確定含追擊的樣本。已知的反面證據只有一項 —— 出血 tick 的 `b44 = 0x10`（不含 `0x08`），所以至少不會被出血誤觸發。
> 佐證：登場封包 ActorParameter 的 6 個強化欄位為 `smash / combo / rapid / aoe / extra_hit / ultimate`，`extra_hit` 即追擊，確實是獨立機制。

### `b45` = flags[4] ★ 新增 — 元素屬性

| bit | mask | 標籤 | protocol 名 |
|-----|------|------|-------------|
| 0 | `0x01` | 冰屬性 | `ice_flag` |
| 1 | `0x02` | 雷屬性 | `electric_flag` |
| 2 | `0x04` | 毒屬性 | `poison_flag` |
| 3 | `0x08` | 心／精神屬性 | `mind_flag` |
| 4 | `0x10` | **★ 持續傷害（唯一 DoT 判據，✅ 已驗證）** | `dot_flag4` |

> **這解掉了 §5 的符文謎題**：原本靠 `0x00005096` TLV 內的 UTF-16 字串（`Elemental_Common_Hit_Lightning`）猜元素種類，
> 其實 `b45 & 0x02`（`electric_flag`）就直接是雷屬性。雷符文樣本應該同時有 `b45=0x02` 與 `b42=0x88`。
> **待驗證**：回頭檢查那 3 筆雷符文樣本的 `b45` 是否為 `0x02`。若成立，符文／元素傷害可完全靠旗標分類，不必解字串。

### 4.1 持續傷害（DoT）驗證紀錄 ✅ 2026-08-16（**已修正初版的錯誤結論**）

> ⚠ 初版只有 1 筆出血樣本，誤把 `b42` bit3/bit7 + `b43` bit0 也當成 DoT 旗標。
> 後續 5 組對照樣本證明那三個位元在**追加傷害、地面傷害**上同樣會亮，**不是 DoT 判據**。

實測對照組：

| # | 來源 | b41 | b42 | b43 | b44 | b45 | 是否 DoT |
|---|------|-----|-----|-----|-----|-----|---------|
| 1 | 被動技 毒 DOT | `00` | 88 | 01 | 00 | **14** | ✅ |
| 2 | 2技 **追加傷害** | `05` | 88 | 01 | 00 | **00** | ❌ |
| 3 | 3技 創傷 DOT | `00` | 88 | 01 | 10 | **10** | ✅ |
| 4 | 4技 毒 DOT | `00` | 88 | 01 | 00 | **14** | ✅ |
| 5 | 4技 **地面傷害**（技能本身的毒屬性範圍傷害，非中毒 debuff） | `01` | 88 | 01 | 00 | **04** | ❌ |

**結論：DoT 判據只有 `b45 & 0x10`（flags[4] bit4，protocol 的 `dot_flag4`）一個位元。**

```python
DMG_DOT_BITS = ((4, 0x10),)
is_dot = any(flags[idx] & mask for idx, mask in DMG_DOT_BITS)
```

兩個獨立佐證：

| 證據 | 說明 |
|------|------|
| `b41` | 真 DoT tick 三組恆為 `00`（**不會爆擊**）；追加傷害 `05`（爆擊+無防備）、地面傷害 `01`（爆擊）皆非 0 |
| 傷害數值 | DoT 每跳固定（506/506/506、906×3）；追加傷害與地面傷害會浮動（2227/2247、1099/1149/1105） |

### 4.2 `b42` bit3/bit7 + `b43` bit0 = 「額外傷害」通用標記

這三個位元在上述 **5 組全部亮起**，普攻則不亮（普攻 `b42 = 0x02`）。

推定語意：**「這一筆不是玩家直接命中的主傷害」** —— DoT、追加傷害、地面傷害都算。
protocol 把它們命名為 `dot_flag` / `dot_flag2` / `dot_flag3`，**該命名有誤導性**，本工具改稱「額外傷害」。

目前只在開發者面板顯示（`| 額外(42.08+42.80+43.01)`），不影響統計。

### 4.2.1 「持續傷害」= 額外傷害且非 DoT ★ 2026-08-19 接進統計 ★

遊戲內敘述為「持續傷害」的技能效果（樣本：`0x6E202640` = 5技 高潮(終章)），封包上**不是 DoT**：

| b41 | 含義 | 數值 | 均值 | 倍率 |
|---|---|---|---|---|
| `00` | 無 | 2723 / 3009 / 2960 | 2897 | 1.00× |
| `01` | 爆擊 | 5359 / 5839 | 5599 | 1.93× |
| `05` | 爆擊+無防備 | 7594 / 7680 / 7334 | 7536 | 2.60× |

flags 全部是 `xx 88 01 00 00 00 00` —— 額外傷害三位元全亮、`b45 = 00`（無 DoT、無元素）。
倍率乾淨（爆擊約 2×，無防備再 +35%）代表走正常傷害計算，與真 DoT（`b41` 恆 `00`、每跳定值）明顯不同。

判定式（`DMG_SUSTAIN_BITS`，實作於主程式）：

```python
is_sustain = (not is_dot) and all(flags[idx] & mask for idx, mask in DMG_EXTRA_BITS)
```

程式行為：
- 技能名後加註 `(間接)`（`DMG_SUSTAIN_SUFFIX`），與 DoT 的 `(Dot)` 互斥。
- 覆蓋率分母**分流**：爆擊用 `cov_hits`（只排除 DoT），強擊/連擊/追擊用 `cov_main`（再排除持續傷）。
  常數 `COVERAGE_TAGS_SUSTAIN = ("爆擊",)` 控制哪些標籤照算。持續傷若帶強擊位元，分子也一併排除。

**未驗證的限制**：§4.1 樣本 #5「4技 地面傷害」同樣符合這個判定式（`01 88 01 00 04`），
旗標層面無法區分「持續傷害」與「地面傷害」。目前兩者都會被標成 `(間接)`，
要再細分只能靠 skill ID 或 `b45` 元素位元。

### 4.3 元素旗標 ✅ 已驗證兩個

| 旗標 | 位置 | 佐證 |
|------|------|------|
| **毒** | `b45 & 0x04` | 樣本 #1（被動技）、#4（4技 DOT）、#5（4技 地面傷害）三個不同技能各自出現 |
| **出血/創傷** | `b44 & 0x10` | 樣本 #3「創傷 DOT」，對上 protocol 的 `bleed_flag` |

其餘元素（暗/火/聖/冰/雷/心）仍未錄到樣本，開發者面板保留 `?` 後綴。

注意 #5：`b45` 從 `14` 變 `04` —— 少了 DoT 位元、保留毒屬性。這證明**元素位元與 DoT 位元互相獨立**，可分別判定。

### 4.4 仍未確認

- **追擊**（`b44 & 0x08`）：上述 5 組**全部沒亮**。已確認遊戲中的「追加攻擊」**不是** `add_hit_flag`（兩者是不同機制），追擊本身仍無樣本。
- 樣本 #3 的 skill ID `0x17F764D2` 對照 `skills.ini` 為 `[未分類] 3技 奇襲`，偏向支持「該 ID 是**引發創傷的來源技能**」而非效果本身。
  但在 §5.1 的配對驗證補上之前不能定案。
- 樣本 #5 與 #4 共用同一個 skill ID（`0x166C5CA0`）卻是不同性質的傷害 → **skill ID 無法區分 DoT 與直接傷害，只能靠旗標**。

### `b57` bit 對應（已知遮罩 `0x01`）— 本工具獨有

| bit | mask | 標籤 | 備註 |
|-----|------|------|------|
| 0 | `0x01` | **破防** | 與 `b41` bit 3 完全同步的**備援旗標**（兩者只要一個亮就算破防） |

> `b57` = content offset 48，落在 protocol 的 `specialMeta`（content 41..48）尾端，**protocol 沒有對這個 byte 定義位元**。
> 這是本地樣本歸納出來的，protocol 未涵蓋 → **保留，不要因為對照文件沒寫就拿掉**。
> 另注意：protocol 有獨立的 `REPLICATION_ActorBreak_BreakOccurred_REPL`（真正的破防事件封包，帶 breakType 與持續秒數），與此旗標是兩回事。

---

## 5. 技能識別（Skill ID）★ 2026-08 新發現 ★

**每筆傷害的來源技能可以識別**。0x51E9 事件本身不含技能 ID（tail 32 byte 除了旗標位以外全為 0），但**緊接在 0x51E9 後面**的另一個 TLV `0x00004fc5` 內含 skill ID。

### `0x00004fc5` TLV 結構（contentLength 35 bytes）

> **身分確認**：`0x4FC5` = protocol 的 **`CHANNEL_HitPresentation_NTF`**（命中表現／攻擊旗標包）。
> 判定依據：protocol 定義 `userId@0`、`targetId@8`、`key1@16`、`key2@20`、旗標 7 bytes@24 —— 逐欄對上本地實測。
> 也就是說 **本工具所謂的「Skill ID」＝ protocol 的 `key1`**。

```
[packetType 4B: c5 4f 00 00] [contentLength 4B: 23 00 00 00 = 35] [encodingType 1B] [content 35B]
```

下表沿用舊筆記的「payload offset」（＝從 `size` 欄之後起算，含 encodingType byte），並補上 content 座標：

| Offset (payload) | content | 長度 | 內容 |
|-----------------|---------|------|------|
| 0 | — | 1 | 原記為 tag `0x00`，實為 **`encodingType`** |
| 1..8 | 0..7 | 8 | 攻擊者 ID（protocol：`UInt32 userId@0` + 保留） |
| 9..16 | 8..15 | 8 | 目標 ID（protocol：`UInt32 targetId@8` + 保留） |
| **17..20** | **16..19** | **4** | **★ Skill ID (uint32 LE) ★** = protocol `key1` |
| 21..24 | 20..23 | 4 | protocol `key2`（實測恆為 `00 00 00 00`） |
| 25 | 24 | 1 | **旗標 byte0**（b41 echo） |
| 26 | 25 | 1 | **旗標 byte1**（b42 echo） |
| **27..31** | **26..30** | **5** | **★ 旗標 byte2..byte6 —— 即 b43/b44/b45 的等價位置，尚未讀取** |
| 32 | 31 | 1 | 保留 |
| 33 | 32 | 1 | b57 echo（protocol 未定義此 byte） |
| 34 | 33 | 1 | 通常 `0x01` |

> 注意：protocol 說當 `key1 == 0` 且 `len ≥ 32` 時，content+24 起的 8 bytes 應解讀為 `specialMeta` 而非旗標。
> 本工具的「skill ID = 0 → 符文傷害」正好落在這個條件上 —— 也就是**符文傷害那幾筆的 b41/b42 echo 可能其實是 specialMeta，不是旗標**。
> 旗標仍以 `0x51E9` 本體（`offset+41..47`）為準，`0x4FC5` 的 echo 只當交叉驗證用即可。

### 解析建議

原本 parser 掃到 `e9 51 00 00` 展開 0x51E9 後，**再往後掃到下一個 `c5 4f 00 00`**（通常就在幾個 byte 之後），讀 payload offset 17..20 就是這筆傷害的技能 ID。

### 5.1 ⚠ 配對驗證尚未實作（2026-08-16）

上面那句「attacker/target 兩邊都 match，配對零歧義」**只寫在文件上，程式沒有實作**。

`find_skill_id_after()` 目前的行為是：**往後掃 200 bytes，抓到第一個 size=35 的 `0x4FC5` 就採用**，完全沒有比對攻擊者／目標 ID。

風險最大的情境是 **DoT tick**：

- DoT 不是「攻擊動作」（`b41 = 00` 已證實），**很可能根本不附帶自己的 `0x4FC5`**
- 這時掃到的會是**後面某筆別人的攻擊事件**的技能 ID → 技能排行被污染

**在補上比對之前，DoT 那幾筆的 skill ID 一律不可信。**

建議的驗證方式（僅顯示，不改變配對行為）：讀出 0x51E9 的攻擊者（`offset+9..16`）與目標（`offset+17..24`），
和候選 `0x4FC5` 的 `magic+9..16` / `magic+17..24` 比對，在開發者面板顯示距離與是否吻合：

```
[Flag] ... | 技能: 0x17F764D2 | 配對: d=+64 ID不符 ⚠
```

若大量出現「ID不符」，就改用治癒／護盾那邊已寫好的雙向 Near scan + anti-decoy 邏輯（見 `_find_heal_shield_skill_id`）。

### 已知技能 ID 對照表（戰士，2026-08 樣本）

| 技能 | Skill ID (uint32 LE) | 備註 |
|------|----------------------|------|
| 普攻 | `0x64d5b11d` | 3 樣本一致 |
| 技能1（base） | `0x21dd59c4` | 3 樣本一致 |
| 技能1（另一變體） | `0x54866b87` | 舊樣本推測為 技能1+，待確認 |
| 技能2（base） | `0x47903d5c` | 3 樣本一致 |
| 技能2（另一變體） | `0x0208bb05` | 舊樣本，pet-based 版，推測為 技能2+ |
| 技能4（base） | `0x6aff74ea` | 3 樣本一致 |
| **技能4+** | `0x563674cc` | **3 樣本一致；與 base 是完全不同的 ID** |
| 技能5 | `0x4018e42a` | 舊樣本，多目標多段命中共用同一 ID |

### 關鍵性質

- **+ 變體是獨立 skill ID**：技能4 (`0x6aff74ea`) vs 技能4+ (`0x563674cc`) 完全不同。伺服器把 + 變體當獨立技能傳，不是共用 ID 加旗標。
- **同技能跨施放 100% 一致**：不論爆擊、破防、命中不同目標，同一個技能的 ID 都一樣。
- **多段命中共用同 ID**：技能5 兩段打不同目標，都是 `0x4018e42a`。
- **不是雜湊或時間戳**：值穩定，可以直接當查表 key。

### 特殊值：`0x00000000` = **疑似符文傷害**

當 skill ID = `0x00000000` 時，這筆傷害**不是玩家主動施放的技能**，來源說法（使用者確認）：
> 遊戲中很多符文有「攻擊目標 N 次後造成 1 次額外傷害」之類的機制，這類**符文附加的額外傷害**就是 skill ID = 0。

**判定建議**：monitor 顯示這類傷害時直接標為 **「疑似符文傷害」**，不要試圖查名字。

**輔助訊號**（觀察自雷符文 3 個樣本，2026-08）：

- 附近會出現 UTF-16 字串（在 `0x00005096` size 104 的 TLV 內），命名格式類似：
  - `Elemental_Common_Hit_Lightning`（雷元素）
  - `BattleMusician_StarlightSonata_Hit_1`（詩人星光奏鳴曲）
  - 未來若錄到其他元素，字尾應為 `_Fire` / `_Ice` / `_Wind` 等
- `b42` 常出現原始 mask 外的位元 `0x08` 和 `0x80`（即 `0x88`），跟已知標籤 bit 不重疊。這兩個 bit 目前推測是「元素/被動效果類型旗標」，**不當作標籤顯示**
- 傷害數值通常比同段的一般攻擊高

**未驗證的點**（樣本不足，先假設寬鬆處理）：
- 只驗證過雷符文 1 種，**尚未確認所有符文附加傷害都用 skill ID = 0**。可能存在部分符文有自己的獨立 skill ID
- 若之後遇到「skill ID 非 0 但顯示行為像符文」的樣本，需要重新分類
- **2026-08-16 已遇到反例**：出血 DoT tick 的 skill ID 為 `0x17F764D2`（非 0）。
  但在 §5.1 的配對驗證補上之前，**無法排除這個 ID 是配對錯誤抓到隔壁事件的**，所以此處先不修改「skill ID = 0 → 符文」的既有判定。

### 樣本規模

戰士技能標籤測試共 15 筆封包（普攻 × 3、技能1 × 3、技能2 × 3、技能4 × 3、技能4+ × 3），每一組 3 筆的 skill ID 完全一致，跨組不同，交叉驗證通過。

---

## 5.5 技能「名稱」來源 ★ 2026-08-16 新增，尚未實作 ★

技能 ID 目前只能靠 `skills.ini` 人工建表。但 protocol 指出有一個封包**直接帶技能名稱字串**：

### `REPLICATION_ActorAction_SetAction_Skill_REPL`（protocol §6.2 Action）

content 佈局（**需在 offset ∈ {0, 2, 4} 三個對齊各試一次，先成功者勝**）：

| Rel | 型別 | 欄位 | 條件 |
|-----|------|------|------|
| 0 | UInt32 | `userId` | |
| 4 | UInt32 | 未用 | |
| 8 | Int32 | `nameLen` | `0..4096` 且不越界 |
| 12 | bytes | **`skillName`** | 先當 UTF-8；不可讀且長度為偶數時改 UTF-16。`U+FFFD` 比例 ≤ max(1, len/4) 才算可讀 |
| 其後 | UInt32 | **`skillId`** | 必有 |
| 其後 | UInt32 | skip | 可選 |
| 其後 | Float32 + skip 5 + UInt64 | `durationSeconds`、`targetId`（取 UInt64 低 32 位） | 需剩餘 ≥ 17 |
| 其後 | UInt32 | `keyAlt` | 可選；**非 0 則 `key1 = keyAlt`，否則 `key1 = skillId`** |

### 為什麼這很重要

protocol 明講 Action 的 `key1` 就是拿來跟 `HitPresentation` 的 `key1` 配對的 —— 而 `HitPresentation.key1` **正是本工具的 Skill ID**。

也就是說：

```
ActorAction_SetAction_Skill → (key1, skillName)
0x4FC5 (HitPresentation)    → (key1)            ← 本工具現用的 skill_id
=> skill_id 可以自動對到人類可讀的技能字串
```

**待辦**：先找出 `REPLICATION_ActorAction_SetAction_Skill_REPL` 在台服的 packetType 值（跟 `0x51E9`/`0x4FC5` 一樣要靠實測 magic 反查），就能把 §5 的「各職業 skill_id → skill_name 對照表」從人工建表改成**自動學習 + 寫回 skills.ini**。

> 注意：另有 `REPLICATION_ActorAction_SetAction_REPL`（非 Skill 變體），protocol 標為「無獨立欄位表」，不要混用。

---

## 6. 尚未鎖定的標籤

| 標籤 | 現況 |
|------|------|
| ~~**追擊**~~ | ✅ **已定位**：`b44 & 0x08`（flags[3] bit3 = `add_hit_flag`）。來源為 `packet-protocol.md`，**待本地樣本驗證**，見 §4 |
| `b41` bit1 / bit4 / bit5 | protocol 命名為 `what1` / `what05` / `what06`，雙方都不知道意義 |
| `b46` `b47`（flags[5..6]） | protocol 的位元表在 flags[4] 之後就沒有已知位元，可能全未使用 |
| 其他 | 若 `b41`/`b42` 出現已知遮罩以外的 bit → 日誌顯示 `未知(b41.XX,b42.XX)` 供人工比對 |

---

## 7. 標籤判定虛擬碼

### 7.1 目前程式實際跑的版本（2026-08-16 更新）

```python
# 旗標區一次讀滿 7 bytes
flags = [payload[offset + 41 + i] for i in range(7)]
b41, b42 = flags[0], flags[1]
b57 = payload[offset + 57]

# 持續傷害:四個 DoT 位元實測同時亮起,取聯集
DMG_DOT_BITS = ((1, 0x88), (2, 0x01), (4, 0x10))
is_dot = any(flags[idx] & mask for idx, mask in DMG_DOT_BITS)

KNOWN_MASK_B41 = 0xCD    # bit 0 + bit 2 + bit 3 + bit 6 + bit 7
KNOWN_MASK_B42 = 0x8F    # bit 0..3 + bit 7（bit3/bit7 = DoT，已確認）

tags = []
if b41 & 0x01:                              tags.append("爆擊")
if b42 & 0x02:                              tags.append("強擊")
if (b41 & 0x08) or (b57 & 0x01):            tags.append("破防")
if (b41 & 0x04) and not (b41 & 0x08):       tags.append("無防備")
if b42 & 0x04:                              tags.append("連擊")
if b42 & 0x01:                              tags.append("多重打擊")

# 檢查未知位元
unknown_b41 = b41 & ~KNOWN_MASK_B41 & 0xFF
unknown_b42 = b42 & ~KNOWN_MASK_B42 & 0xFF
if unknown_b41 or unknown_b42:
    tags.append(f"未知(b41.{unknown_b41:02X},b42.{unknown_b42:02X})")

# 全空 → 「普通」

# 持續傷害不進 tags,改在技能名稱後加註後綴(避免污染覆蓋率與標籤欄)
if is_dot:
    skill_display += "(Dot)"
```

**為什麼 DoT 用後綴而不是標籤？**

- 標籤欄（爆擊/強擊/連擊…）描述的是「這一次命中的品質」，DoT 描述的是「這筆傷害的來源性質」，語意不同層
- DoT tick 數量多，塞進標籤欄會把畫面洗掉
- 不進 `tag_counts` 就不會影響爆擊／強擊／連擊的覆蓋率分母以外的統計語意

### 7.2 補上 §4 缺漏後的建議版本 ★ 尚未套用到程式 ★

```python
# 旗標是連續 7 bytes：flags[0..6] = payload[offset+41 .. offset+47]
b41, b42, b43, b44, b45 = (payload[offset+41+i] for i in range(5))

KNOWN_MASK_B41 = 0xCD    # bit 1/4/5 仍未知
KNOWN_MASK_B42 = 0x8F    # ← 原 0x07；bit3/bit7 已確認為 dot_flag/dot_flag2
KNOWN_MASK_B43 = 0x01
KNOWN_MASK_B44 = 0xF8
KNOWN_MASK_B45 = 0x1F

tags = []
if b41 & 0x01:                              tags.append("爆擊")
if b42 & 0x02:                              tags.append("強擊")
if (b41 & 0x08) or (b57 & 0x01):            tags.append("破防")
if (b41 & 0x04) and not (b41 & 0x08):       tags.append("無防備")
if b42 & 0x04:                              tags.append("連擊")
if b42 & 0x01:                              tags.append("多重打擊")
if b44 & 0x08:                              tags.append("追擊")        # ★ 新

# 持續傷害（符文／DoT）：任一 DoT 旗標亮起
is_dot = bool(b42 & 0x08 or b42 & 0x80 or b43 & 0x01 or b45 & 0x10)
if is_dot:                                  tags.append("持續傷害")    # ★ 新

# 元素／傷害屬性（建議另開一欄顯示，不要塞進 tags 讓標籤爆量）
ELEMENTS = [
    (44, 0x10, "出血"), (44, 0x20, "暗"), (44, 0x40, "火"), (44, 0x80, "聖"),
    (45, 0x01, "冰"),   (45, 0x02, "雷"), (45, 0x04, "毒"), (45, 0x08, "心"),
]
element = [name for off, mask, name in ELEMENTS
           if payload[offset + off] & mask]

# 未知位元檢查同樣擴充到 b43/b44/b45
```

> 上線前建議先開發者模式跑一輪，確認 `b43/b44/b45` 在**已知無追擊、無元素**的普攻樣本上恆為 `00`，
> 再打開「追擊 / 持續傷害」這兩個新標籤，避免誤報。

---

## 8. 統計功能

### DPS（每秒傷害）
- 公式：`total_damage / max(last_damage_time - first_damage_time, 1.0)`
- 停手不打時 DPS 會**凍結**（不會因閒置而遞減）

### 覆蓋率
- 樣本門檻：`COVERAGE_MIN_HITS = 10`（未達門檻顯示 `—`）
- 公式：`(該標籤出現次數 / 總傷害筆數) * 100`
- 目前顯示：**爆擊 / 強擊 / 連擊** 三項

---

## 9. 驗證資料集

- **戰士職業封包 hex dump 19 筆**：用於確認旗標位元。
- **技能識別封包 15 筆**（普攻 / 技能1 / 技能2 / 技能4 / 技能4+ 各 3 筆）：用於確認 `0x00004fc5` skill ID 欄位。
- **符文攻擊封包 3 筆**（雷符文樣本）：用於觀察 skill ID = 0 的符文附加傷害行為。
- **出血 DoT tick 1 筆**（2026-08-16）：`flags = 00 88 01 10 10 00 00`，數值 215。
- **DoT／非 DoT 對照組 5 種**（2026-08-16）：被動毒DOT、2技追加傷害、3技創傷DOT、4技毒DOT、4技地面傷害 —— **推翻初版 DoT 判據**並驗證毒／出血元素旗標，見 §4.1–4.3。

### 已確認的 5 個標籤 + 2 個屬性 + 1 個技能識別
- 標籤：爆擊、強擊、連擊、破防、無防備、多重打擊
- 屬性：b41.bit7（普通攻擊指示）、b41.bit6（= `first_hit_flag` 首擊，不當 tag）
- 技能識別：`0x00004fc5` payload offset 17..20 = uint32 skill ID（= protocol `key1`）
- 特殊值：skill ID = `0x00000000` → 疑似符文傷害

### 待驗證清單（來自 `packet-protocol.md`，本地尚無樣本佐證）
- [ ] 追擊 = `b44 & 0x08`
- [x] ~~DoT = `b42 & 0x88` / `b43 & 0x01` / `b45 & 0x10`~~ ❌ **此結論已被推翻** → 正解為 **只有 `b45 & 0x10`**（§4.1）
- [x] **出血/創傷 = `b44 & 0x10`** ✅ 已驗證
- [x] **毒 = `b45 & 0x04`** ✅ 已驗證（三個技能交叉佐證）
- [ ] 其餘元素旗標：暗 `b44 0x20` / 火 `b44 0x40` / 聖 `b44 0x80` / 冰 `b45 0x01` / 雷 `b45 0x02` / 心 `b45 0x08`
- [ ] §5.1 的 skill ID 配對驗證（未完成前，DoT 的 skill ID 不可信）

---

## 10. 開發者模式 log 格式

程式勾選「🛠 開發者」後底部會出現診斷面板，每筆傷害輸出：

```
[Flag] 數值: 12345 | flags[41-47]: 81 02 00 00 00 00 00 | b57:00 | 技能: 0x64D5B11D
```

方便手動核對某個 bit 是否符合預期標籤。

### `DoT` 與「候選」欄位（2026-08-16）

```
[Flag] 數值: 215 | flags[41-47]: 00 88 01 10 10 00 00 | b57:00 | 技能: 0x17F764D2 | DoT | 候選: 出血?
[Flag] 數值: 9876 | flags[41-47]: 00 00 00 08 00 00 00 | b57:00 | 技能: 0x21DD59C4 | 候選: 追擊?
```

- **`| DoT`** — 已確認的持續傷害判定，同時會讓主日誌的技能名稱後面出現 `(Dot)`
- **`| 候選: XXX?`** — 尚未驗證的推論位元，對應表在程式的 `DMG_FLAG_CANDIDATES`（見設定區）
  - 名稱一律帶 `?`，提醒這些**只是推論**
  - **只在開發者面板顯示，不進入標籤、不進覆蓋率、不進技能排行**，誤判不會污染統計

**待驗證項目的錄製方式**：
1. 打一輪普攻 → `flags[2..6]` 應全為 `00`，不應出現任何候選
2. 開追擊符文／裝備後打 → 看 `flags[3]` 是否亮 `0x08`，且只在追擊那一段亮
3. 雷符文觸發時 → 看 `flags[4]` 是否為 `0x02`
4. 用**不同技能**引發出血 → 比對 skill ID 是否相同（分辨「出血效果 ID」vs「來源技能 ID」，見 §4.1）

---

## 11. 未來可補強方向

### 高優先（`packet-protocol.md` 已給答案，只差實作／驗證）

- [x] ~~補充 **追擊** 標籤的測試封包，鎖定其 bit 位置~~ → 位置已知 `b44 & 0x08`，改為**錄樣本驗證**
- [x] ~~**讀滿 7-byte 旗標區**（`offset+41..47`）~~ ✅ 已實作
- [x] ~~解讀 `b42` 的 bit 3 / bit 7~~ → `dot_flag` / `dot_flag2`，✅ 已確認
- [x] ~~**加入「持續傷害／DoT」判定**~~ ✅ 已實作，技能名後加註 `(Dot)`
- [x] ~~`KNOWN_MASK_B42` 由 `0x07` 改為 `0x8F`~~ ✅ 已實作（DoT 不再噴「未知(b42.88)」）
- [ ] **補上 §5.1 的 skill ID 配對驗證**（最高優先 —— 沒有它，DoT 的技能歸屬全部存疑）
- [x] ~~**加入「追擊」標籤**（`b44 & 0x08`）~~ ✅ 已實作（標籤＋覆蓋率＋高亮＋技能明細），**但位元本身仍待樣本驗證**
- [ ] **加入元素屬性欄**（`b44 bit4..7` + `b45 bit0..3`）取代猜字串 ← 等樣本
- [ ] **從 `REPLICATION_ActorAction_SetAction_Skill_REPL` 自動抓技能名**（見 §5.5），取代人工 `skills.ini`
- [ ] ~~TLV 前進步長由 `size + 8` 修正為 `size + 9`~~ → **刻意維持 `+8`**，理由見 §2

### 中優先（穩定度／正確度）

- [ ] **TCP 依 seq 重組**再餵解析器，避免跨 segment 的傷害封包被漏掉
- [ ] 處理 `encodingType == 1`（Brotli）內容
- [ ] `packetType` 不要硬編碼：加一層「開機自動校準 magic」或至少在統計長時間為 0 時提示可能已改版

### 低優先／仍待研究

- [ ] 探索寵物 vs 玩家的可靠區分方式（目前只能靠 attacker ID）
- [ ] 探索 `b41` bit 1 / bit 4 / bit 5（protocol 亦標為 `what1` / `what05` / `what06`）
- [x] ~~覆蓋率加入 追擊~~ ✅ 已實作（`COVERAGE_TAGS` 統一控制四個面板位置）
- [ ] 覆蓋率加入 破防 / 無防備 / 多重打擊（只要加進 `COVERAGE_TAGS` 即可）
- [ ] **驗證 skill ID = 0 是否涵蓋所有符文附加傷害**（目前只錄過雷符文，需要不同機制的符文交叉驗證）
- [ ] 釐清 `b57`（content+48）在 protocol `specialMeta` 中的真正語意
- [ ] 從 `0x00005096` TLV 內的 UTF-16 字串（`Elemental_*` / `Musician_*`）推導符文效果的可讀名稱（若元素旗標驗證成立，此項可降級）

---

## 12. 與 `packet-protocol.md` 的差異總表（2026-08-16）

| 項目 | 本工具（原） | packet-protocol.md | 處置 |
|------|-------------|-------------------|------|
| 標頭長度 | 8 bytes | **9 bytes**（多 `encodingType`） | ✅ 已修正，見 §2 |
| offset+8 | 「未知 byte」 | `encodingType`（0=raw, 1=Brotli） | ✅ 已修正 |
| `0x51E9` 身分 | 「傷害事件」 | `CHANNEL_ShowDamageFloater_NTF` | ✅ 已標註 |
| `0x4FC5` 身分 | 「skill ID 容器」 | `CHANNEL_HitPresentation_NTF` | ✅ 已標註 |
| Skill ID 欄位 | payload+17 | 同位置 = `key1` | ✅ 一致 |
| 旗標區 | 2 bytes（b41/b42） | **7 bytes** | ✅ 已實作讀滿 7 bytes |
| 追擊 | 未知 | flags[3] bit3 `add_hit_flag` | ⚠ 待樣本驗證（開發者模式候選） |
| `b41` bit6 | 「用途不明」 | `first_hit_flag` | ✅ 已命名 |
| `b42` bit3/bit7 | 「符文未知位元」 | `dot_flag` / `dot_flag2` | ⚠ protocol 命名有誤 → 實為「額外傷害」標記，見 §4.2 |
| DoT 判據 | （無） | `dot_flag`×4 | ✅ 實測只有 `b45 & 0x10` 是 DoT，見 §4.1 |
| 元素屬性 | 靠 UTF-16 字串猜 | flags[3]/flags[4] 位元 | ✅ 毒／出血已驗證；其餘待樣本 |
| skill ID 配對 | 抓最近的 0x4FC5，不比對 ID | attacker/target 應 match | ⚠ **未實作**，見 §5.1 |
| `b57` 破防備援 | 實測有效 | **無此定義** | ✅ 保留（本工具獨有） |
| `0xFFFFFFFF` 免疫 | 實測有效 | **無此定義** | ✅ 保留（本工具獨有） |
| skill ID = 0 → 符文 | 實測歸納 | 僅說 `key1==0` 時 content+24 改讀 `specialMeta` | ✅ 保留，但 echo 旗標在此情況不可信 |
| 傷害免疫判定 | `dmg == 0xFFFFFFFF` | 未提 | ✅ 保留 |
| TCP 重組 | 無 | 必要（seq 銜接） | ⚠ 已知漏包來源 |
| packetType 來源 | 硬編碼 | 遠端目錄，隨區服／版本變動 | ⚠ 改版風險 |

**結論：兩份文件在傷害解析上沒有互相矛盾的地方**，差別是
（a）本工具的座標系整體少算 1 byte 的 `encodingType`，但因為所有 offset 都是實測校準過的，**實際讀出來的位置是對的**；
（b）本工具只讀了 7-byte 旗標區的前 2 bytes，追擊／DoT／元素全在沒讀到的 3 bytes 裡；
（c）本工具有 3 項 protocol 沒記載的獨家發現（`b57`、`0xFFFFFFFF` 免疫、skill ID=0 符文）。

---

## 13. protocol 提到、本工具尚未利用的戰鬥封包

以下都在 protocol §6.2，若之後要擴充戰鬥面板可以直接接：

| protocol 名稱 | 內容 | 可做什麼 |
|--------------|------|---------|
| `REPLICATION_ActorAction_SetAction_Skill_REPL` | 技能名字串 + skillId | **技能名自動對照**（見 §5.5） |
| `REPLICATION_ActorBreak_BreakOccurred_REPL` | targetId + breakType + 持續秒數 | 真正的破防事件與破防窗口計時 |
| `REPLICATION_ActorBreak_BreakEnded_REPL` | targetId | 破防結束 |
| `REPLICATION_ActorStatus_SetBreakPoint_REPL` | targetId + gauge (Float32) | 破防槽即時進度 |
| `REPLICATION_ActorBuff_Add/Refresh/Expire_REPL` | buffKey + 結束時間 + 層數 | Buff／Debuff 軸，可分析增益覆蓋率 |
| `REPLICATION_SkillResource_SetValue_REPL` | playerId + mana | 資源監控 |
| `REPLICATION_ActorStatus_SetHealth_REPL` … `SetHealth6_REPL` | entityId + HP blob | 目標 HP（注意：blob 長度為 16 倍數時是 AES-128-CBC 加密，金鑰 = `channelObjectId` 重複填滿 16 bytes，IV 來自登場包） |

> 這些同樣需要先實測出台服的 packetType magic 值。
