# IntegrityGuard 1.1.1｜檔案完整性驗證

[![最新版本](https://img.shields.io/github/v/release/okokkook1/IntegrityGuard?label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC)](https://github.com/okokkook1/IntegrityGuard/releases/latest)
[![授權](https://img.shields.io/github/license/okokkook1/IntegrityGuard)](LICENSE)

Windows 10／11 x64 桌面工具，繁體中文介面。可指定資料夾路徑，建立可信雜湊基準、驗證檔案差異、暫停／繼續／取消工作，以及設定自動掃描排程。

## 下載

- **Windows 免安裝版（v1.1.1）**：[IntegrityGuard-v1.1.1-Windows.zip](https://github.com/okokkook1/IntegrityGuard/releases/download/v1.1.1/IntegrityGuard-v1.1.1-Windows.zip)
- 所有版本與變更紀錄：[Releases](https://github.com/okokkook1/IntegrityGuard/releases)

解壓縮完整套件後雙擊 `IntegrityGuard.exe` 即可使用，不需要安裝 Python。下載後建議先比對 `SHA256SUMS.txt`：

```powershell
Get-FileHash .\IntegrityGuard.exe -Algorithm SHA256
```

本儲存庫包含完整原始碼、測試與建置腳本；執行檔與發行套件放在 Releases，不納入版本控制。`SHA256SUMS.txt` 對應 Releases 中完整套件的內容，儲存庫內的原始碼因換行正規化，雜湊值可能與該清單不同。

## 此版修正

- 修正 Windows 對 `.exe`、`.bat`、`.cmd`、`.com` 的檔案屬性查詢差異，避免誤判為「開啟時已變更」。
- 掃描 Windows 磁碟根目錄（例如 `E:\`）時，自動排除 `$RECYCLE.BIN` 與 `System Volume Information`，並在基準與報告列出；一般資料夾中同名的子目錄不會因此自動排除。
- 新增明確選擇的「允許建立部分基準」，可先處理其他可讀檔案。未涵蓋項目會完整記錄，後續掃描仍標示不完整。
- 基準建立失敗時，在可捲動的結果欄列出全部項目，錯誤視窗提供下一步提示。

以下保留 v1.1 的功能：

- 移除 Windows SFC、DISM 系統檢查與管理員重新啟動功能。
- 新基準預設 BLAKE3-256，保留 SHA-256 舊基準相容性。
- 基準建立、更新及掃描均可並行讀取檔案，並限制等待佇列大小。
- 加入「暫停」、「繼續」、「取消」與實際檔案／讀取量進度。
- 取消未完成的基準建立，保留原基準；取消掃描會明確記錄未完成。

## 開始使用

1. 解壓縮完整套件至固定位置，雙擊 `IntegrityGuard.exe`，不需要安裝 Python。
2. 在「檔案掃描資料夾」輸入絕對路徑，例如 `D:\重要資料`，或按「選擇資料夾」。會包含其子資料夾。
3. 選擇演算法。新建立的基準建議使用預設 BLAKE3；既有 SHA-256 基準可直接沿用。
4. 設定並行檔案數，預設 `4`。SSD 可從 4 開始；傳統硬碟或網路分享若效能變差，可改為 `1`。
5. 在內容可信的狀態下按「建立／更新檔案基準」，之後按「立即掃描」。
6. 在「報告」分頁查看新增、修改、刪除與無法讀取的明細。TXT 可直接閱讀，JSON 包含完整雜湊與差異。

更新基準會把目前內容視為可信，需先確認差異。一般掃描不會自動更新基準。

## 無法建立基準時

此版已修正穩定 `.exe` 等檔案的誤判。使用新版直接重試「建立／更新檔案基準」即可；不需為此改變檔案權限。磁碟根目錄的資源回收筒與系統磁碟資訊資料夾會自動略過，略過範圍會列在結果與報告。

若其他項目仍真正無法讀取，未勾選「允許建立部分基準」時，程式會保留原基準，並在結果欄列出全部失敗路徑。可以關閉正在寫入的程式、選擇有權限讀取的資料夾，或明確加入排除規則後重試。

需要先驗證可讀檔案時，勾選「允許建立部分基準」再建立。這項設定預設關閉；啟用後仍需確認建立／覆寫。部分基準會保存成功讀取的檔案，以及全部未涵蓋路徑與錯誤。若沒有任何可讀檔案，仍會拒絕建立基準。

部分基準的後續掃描會回報 `incomplete`，即使可讀檔案全部相符，也不會回報完整性通過。修正讀取問題後，取消勾選並重建基準，才能恢復完整涵蓋。重新建立部分基準可能移除原基準中未能讀取的項目；請先備份重要基準。

## 暫停、繼續與取消

建立基準與立即掃描開始後，「暫停」與「取消」會啟用。

- 「暫停」保留已讀取的進度，按鈕變成「繼續」。按「繼續」接著處理。
- 「取消」會停止後續工作，喚醒暫停中的工作者，並等待正在處理的讀取區塊完成。
- 取消未完成的基準，不會取代原基準；未完成的掃描不會顯示完整性通過。
- 暫停／取消在每個 1 MiB 讀取區塊間檢查。正在等待的 Windows／網路讀取無法強制瞬間結束，可能需要稍候。
- 最後儲存結果採短暫的原子提交。已完成提交的作業會回報成功；這個時點之後的取消不會回復已完成的結果。
- 掃描中關閉視窗時，可選擇取消並關閉，工具會先等背景工作停止再關閉。

GUI 的按鈕控制目前這個視窗開始的作業。Windows 排程在獨立程序執行，不會被另一個視窗的暫停／取消按鈕控制。

## 加速方式與測量

BLAKE3 使用原生程式與 CPU 可用的 SIMD 指令；此版每個檔案採單一 BLAKE3 工作者，另以有限的檔案工作者同時讀取不同檔案，避免兩層大量併行。

每次仍讀取完整檔案內容，不使用「時間與大小未變就跳過雜湊」的捷徑。測試也確認同大小檔案被修改且恢復原時間時，仍能偵測差異。[官方 BLAKE3 實作](https://github.com/BLAKE3-team/BLAKE3)、[Python bindings](https://github.com/oconnor663/blake3-py)。

在本機以 2,000 個 4 KiB 檔案及 8 個 32 MiB 檔案測試，共 2,008 檔、263.8125 MiB。每個版本先暖機，再測三次，表中為中位數，包含基準／報告寫入：

| 作業 | v1.0 SHA-256，單工 | v1.1 BLAKE3，並行 4 | 速度比 |
| --- | ---: | ---: | ---: |
| 建立基準 | 1.9921 秒 | 0.9466 秒 | 2.10 倍 |
| 完整掃描 | 1.8906 秒 | 0.9529 秒 | 1.98 倍 |

這是合成資料、暖檔案快取的測量，不能保證所有電腦相同；磁碟、CPU、檔案大小分布、防毒與網路延遲會影響結果。減少並行數有時可改善傳統硬碟效能。

## 排程

在「排程」分頁設定每天、每週或每小時，以及 24 小時制時間，例如 `02:30`。每週可選多天。每小時從下一個符合指定分鐘數的時點起，每小時執行。

按「套用／啟用排程」後，Windows 工作排程器會使用目前帳號執行，關閉 GUI 後仍有效。不保存密碼，也不要求系統檢查用的管理員權限。

- 電腦需開機，且目前使用者保持登入；螢幕鎖定可以執行。
- 不主動喚醒睡眠中的電腦，錯過時間由 Windows 在條件允許時補跑。
- 排程使用已儲存的路徑、排除規則、演算法與並行數。
- 改變路徑、排除規則或演算法後，先重建基準。改變時間或移動程式後，重新套用排程。
- 同一設定的掃描不會重疊。已在掃描時，新執行不會開始另一份掃描。
- 「查詢排程狀態」查看實際設定；「移除排程」停止之後的自動執行。
- 排程結果在「報告」分頁按「重新整理」查看。本版不發送外部通知。

升級後原排程名稱與設定路徑會保留。請用新版重新套用排程，讓 Windows 更新執行檔位置與一般權限設定。舊設定中的系統掃描模式會轉成檔案模式；原本沒有檔案路徑者，需先指定路徑。

## 比對範圍與排除規則

只讀取一般檔案內容，偵測新增、修改、刪除與讀取失敗。單純變更時間不算內容修改。讀取期間檔案變動會標為未完整讀取；基準建立有讀取失敗時，預設拒絕寫入並保留既有基準，只有明確選擇部分基準才會記錄未涵蓋範圍並建立。

符號連結、junction、其他重新解析點與特殊檔案不跟隨，會列在報告。原本的一般檔案被連結取代時，原檔案判為刪除。空資料夾、ACL、擁有者與 NTFS 替代資料流不在此版內容比對範圍。逐一讀取不是整個磁碟同一瞬間的快照。

排除規則每行一條，使用相對路徑、`/` 與 `*`、`?`、`[字元集合]` 萬用字元。單一檔名規則適用各層級，Windows 不區分大小寫；目錄匹配時略過整個子樹，`*` 可匹配 `/`。

```text
*.tmp
cache
logs/*
```

工具設定資料夾、基準及報告會自動排除並列於報告，避免產生假差異；設定資料夾本身不能當作掃描根目錄。

雜湊比對不是數位簽章或第三方認證。請從可信內容建立基準，並將 `baseline.json` 備份至受保護的位置；有相同權限的人仍可能改寫本機基準。

## 結果與資料位置

| 結果 | 意義 |
| --- | --- |
| `clean` | 已完成，監測範圍未發現差異 |
| `changed` | 發現檔案差異 |
| `incomplete` | 讀取或操作失敗，無法完整確認 |
| `cancelled` | 已取消，無法完整確認 |

預設位置為 `%LOCALAPPDATA%\IntegrityGuard`：`profile.json` 設定、`baseline.json` 基準、`last_run.json` 最近結果、`scan.lock` 跨程序鎖，以及 `reports\` 歷史報告。

新基準每個檔案的雜湊欄位是 `blake3`；SHA-256 基準沿用 `sha256`。演算法記在基準根層的 `algorithm`，掃描依該值比對。SHA-256 舊基準不會被自動改寫；要獲得 BLAKE3 加速，選擇 BLAKE3 後重新建立基準。

報告不會自動清除，可自行備份與整理。檔案報告使用 UTC，排程依 Windows 本機時區。可用 `IntegrityGuard.exe gui --data-dir "D:\GuardData"` 指定其他設定資料夾。

## 原始碼與命令列

原始碼需要 Python 3.10 以上、Tkinter，以及 `requirements.txt` 中的 BLAKE3。執行檔已包含全部需求。

```powershell
python -m pip install -r requirements.txt
python integrity_guard.py gui
python integrity_guard.py baseline --profile "D:\GuardData\profile.json"
python integrity_guard.py baseline --profile "D:\GuardData\profile.json" --overwrite
python integrity_guard.py baseline --profile "D:\GuardData\profile.json" --overwrite --allow-incomplete
python integrity_guard.py run --profile "D:\GuardData\profile.json"
python integrity_guard.py schedule install --profile "D:\GuardData\profile.json"
python integrity_guard.py schedule status --profile "D:\GuardData\profile.json"
python integrity_guard.py schedule remove --profile "D:\GuardData\profile.json"
```

先在 GUI 儲存設定，命令列再引用設定檔。建立基準預設拒絕覆寫，需明確使用 `--overwrite`。`--allow-incomplete` 明確允許部分基準，也可在設定檔選擇 `allow_incomplete_baseline: true`。成功建立部分基準會保存基準並回傳結束代碼 `2`，避免排程／腳本將未完整涵蓋視為通過。終端按 Ctrl+C 會請求合作式取消並清理後退出。掃描結束代碼 `0` 通過、`1` 差異、`2` 不完整／失敗、`3` 取消。

執行檔無主控台視窗，排程不會跳出黑色視窗；需要終端輸出時使用原始碼，執行檔的結果仍存於報告。

開發測試：`python -m unittest discover -s tests -v`。`build.ps1` 會下載指定版 PyInstaller、BLAKE3 到建置目錄，再產生獨立執行檔。第三方授權見 `THIRD_PARTY_NOTICES.txt` 與 `LICENSES`。

