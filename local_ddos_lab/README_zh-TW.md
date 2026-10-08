# 應用層資源防護：第一週起始實驗

> 本文保留起始包的說明。新增的 Envoy、PostgreSQL、Python RLS、取消探針與最新驗證請看上一層 [專案 README](../README.md)。本資料夾的 Compose 仍是單服務 SQLite 版本；完整架構的 Compose 位於專案根目錄。

這份程式讓五人專題小組先跑通「真實 SQL 工作 → 壅塞量測 → 防護比較 → 訂單核對」。
**它不是完成的專題、不是新穎性已驗證的演算法，也不是可部署於公開網站的 DDoS 產品。**
只測本機、假資料與受控負載。不需要真實攻擊、殭屍網路、外部網站或付費雲端。

## 1. 已包含與尚未包含

已包含：FastAPI、SQLite、商品讀取、訂單交易、受限的 SQL 統計報表、三種入站控制模式、
四種客戶端情境、可重現的操作時程、CSV/JSON 原始結果、資料庫訂單核對、六項單元測試。

未包含：獨立反向代理、多機或多 IP 測試、完整身分驗證、IP/帳號公平配額、網路頻寬清洗、
AI 成本預測、CPU/資料庫完整遙測、成熟儀表板、正式統計推論、商用安全加固。

防護現在整合在同一個服務內。SQLite 工作者與後端共用程序資源，這不是獨立 PostgreSQL
伺服器的效能模型。後續應替換成獨立後端與 PostgreSQL，研究結果不能直接跨環境推論。

## 2. 檔案

- `server.py`：三個 API、資源名額、管理介面及控制循環。
- `database.py`：實際 SQL 讀取、交易與報表聚合，不使用 sleep 假裝資料庫工作。
- `policy.py`：簡單、可替換的動態名額規則；不是已證實優於其他方法的演算法。
- `experiment.py`：只能連 `127.0.0.1:8000` 的有界限測試程式。
- `test_core.py`：單元測試。
- `compose.yaml` / `Dockerfile`：可選的單服務容器配置，未在交付環境實際啟動驗證。
- `sources.md`：官方方法與技術參考。
- `VALIDATION.md`：本次實際執行範圍。

## 3. 原生 Python 起步（先用這個）

使用 Python 3.11 以上並包含 sqlite3。交付前的原生測試環境是 Python 3.13.5。
requirements 固定了本次使用的核心套件版本，但不是所有間接依賴的完整鎖檔。

### macOS / Linux：終端機 A

解壓縮後進入 `local_ddos_lab`：

```bash
cd local_ddos_lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v test_core.py
python server.py
```

伺服器啟動後，瀏覽 `http://127.0.0.1:8000`。API 文件在 `/docs`。
`/docs` 介面的前端資源可能需要網際網路；首頁、測試與 API 本身不依賴它。

### macOS / Linux：終端機 B

```bash
cd local_ddos_lab
source .venv/bin/activate
python experiment.py --scenario normal --mode off --seconds 30
```

### Windows PowerShell

不需要變更 PowerShell 的腳本執行政策，直接使用虛擬環境的 Python：

```powershell
cd local_ddos_lab
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest -v test_core.py
.\.venv\Scripts\python.exe server.py
```

另一個終端機進入同一資料夾：

```powershell
.\.venv\Scripts\python.exe experiment.py --scenario normal --mode off --seconds 30
```

首次啟動會建立 20 筆商品及 40,000 筆合成銷售資料。沒有完整購物網站畫面是正常的：
這一階段先確認後端與實驗流程。每輪會清空本程式的測試訂單並重設測試庫存；
不要將這個資料庫換成真實資料庫。

## 4. 三種防護模式

| 模式 | 含義 |
|---|---|
| `off` | 不加報表專用名額限制。所有共同的實驗安全上限仍存在。 |
| `fixed` | 報表在途數固定上限，預設 2；可在 1～3 之間校準。 |
| `adaptive` | 報表名額在 1～3 之間調整，根據瀏覽/訂單等前景工作的排隊等待與逾時。 |

所有模式共同最多 4 個資料庫工作者、24 個已接受且未完成工作、1.5 秒排隊上限。
SQL 透過 progress handler 施加約 1.5 秒的執行期限，另有 250 毫秒鎖等待設定。
它們是安全實驗邊界，不是嚴格即時保證。`off` 不等於撤除所有安全限制。

`fixed` 是**固定並行名額限制**，不是「每秒固定請求數」；正式專題要另加 token bucket
或 NGINX 限流與整體自適應並行控制等合理比較對象。

動態規則每約 2 秒檢查：前景排隊 p95 > 50ms 或有排隊逾時時，減少一個報表名額；
連續兩個視窗有前景樣本、p95 < 10ms 且報表被拒絕時，增加一個名額。
門檻只是教學初值，不是公認最佳值；記錄規則與理由，保留獨立校準及評估資料。
這不是攻擊分類器，前景工作也可能被濫用，報表也可能是正常需求。

**不要改成多個 Uvicorn workers。** 現階段計數器只在單一程序內共享。

## 5. 四種情境

| 情境 | 基本正常需求 | 中段額外需求 | 用途 |
|---|---|---|---|
| `normal` | 約 4 次/秒 | 無 | 確認正常成本及防護額外影響 |
| `surge` | 約 4 次/秒 | 約 8 次/秒，同樣屬正常需求 | 檢查正常流量突增 |
| `mixed` | 約 4 次/秒 | 約 6 次/秒，報表工作 | 資源競爭 |
| `critical` | 約 4 次/秒 | 約 6 次/秒，訂單工作 | 檢查高優先功能也被濫用的限制 |

正常需求混合商品瀏覽、訂單與少量報表，因此不能把所有報表一律當攻擊。
每輪前 20% 是暖機、中間 60% 加入情境负載、後 20% 是恢復；normal 沒有額外負載。
預設 30 秒適合熟悉流程；正式實驗先校準暖機是否足夠，再固定設定。

所有「normal / pressure」標籤僅存於客戶端日誌，不會傳給防護規則。
所有來源均為同一台電腦的 loopback，**不是不同 IP，也不是真正的分散式 DDoS**。
中段的壓力工作是對自己實驗服務的合成負載，不應把流量標籤當作現實惡意的證明。

```bash
# 初步比較：同一組時程跑三種模式；執行順序依種子打亂
python experiment.py --scenario mixed --mode all --seconds 30

# 正常量突然增加
python experiment.py --scenario surge --mode all --seconds 30

# 被保護的訂單功能也受到額外需求
python experiment.py --scenario critical --mode all --seconds 30

# 校準後再用未參與調參的種子重複評估
python experiment.py --scenario mixed --mode all --seconds 60 --repeats 5 --seed 100
```

`--repeats 5` 使用連續五個種子，每個種子在三個模式使用相同請求時程。
總完成時間包含三種模式、重複次數與排空，`--seconds` 是每個模式的送入窗口。
一次只執行一個 experiment.py，避免不同實驗互相重设資料庫。

## 6. 負載不夠／太重時

先讀取 `requests.csv` 的排隊時間與 `summary.json` 的結果，不要先追求把電腦弄掛。

若三種模式都很順，這就是目前條件下的結果，不是程式故障：
先使用容器固定本程式可用 CPU，再在保留安全界線下校準報表聚合批數。
可用 `--report-rounds 20` 降低或 `--report-rounds 60` 增加**本機受保護的報表工作量**。
這只適用於封閉實驗的 admin 設定，沒有給外部使用者自選運算量的 API。
三種模式必须使用相同批數、相同硬體配額；不要替某一組偷改工作量。

若出現 generator drops，代表產生器未按預定時程送出所有需求，不應聲稱比較維持了相同到達率。
停止測試、檢查本機其他負載與伺服器配額；必要時將後端工作量調低後重測。
不要解除腳本上限，也不要改成公網測試。Ctrl+C 停止測試；已在途工作會在有界限期限內收尾。

## 7. 輸出如何解讀

每個實驗資料夾：

- `requests.csv`：每一個預定請求的角色標籤、階段、功能、狀態、正確性、端到端時間。
- `summary.json`：整體與分情境的統計。
- `state.jsonl`：每秒左右的名額、執行數、計數器與控制決策。
- `order_audit.json`：資料庫實際提交的訂單、庫存核對及回應落差。
- `schedule.json`：可重現的相對送入時程。
- `metadata.json`：參數、環境版本與關鍵程式 SHA-256。

主指標讀取 `summary.json` 的 `normal_orders_load_phase`：

`completion_rate = 在1秒內正確完成的正常訂單數 / 中段原訂正常訂單數`。
1秒是起始實驗的建議門檻，不是正式標準；後續可先約定合理門檻再測。
若 planned=0，比例為 null，不要寫成 0% 或 100%。

還要一起讀：`http_429`、`http_5xx`、`client_timeouts`、`generator_drops`。
成功回應的 p95 不包含失敗、拒絕或未發出的工作，不能拿它單獨說系統更好。
CSV 中端到端時間從預定送入時刻起算，包含產生器延遲與伺服器排隊。
`queue_ms` 是等待工作名額的時間，不是 CPU 用量；`work_ms` 也可能包含資料庫鎖等待。
沒有完成的延遲是缺值，不會被當作零秒。

訂單成功不只看 HTTP 200：回應需含匹配的訂單 ID 及已落地標記，測試結束後再獨立查核。
`committed_without_successful_ack` 表示可能提交成功但回應失敗或逾時，不能抹去；
本程式用相同 request_id 的冪等寫入避免重試造成重複扣庫存，但測試預設不自動重試。

每輪自動排空、清除訂單與重設控制器，**並不清除 OS/SQLite 的全部快取**。
正式研究應採一致暖機、隨機化順序、記錄冷/熱快取條件，不可稱為完全乾淨的機器狀態。

## 8. Docker 選項（配置未在本次環境實跑）

若已有 Docker Compose，可以用附檔固定本程式的 CPU 與記憶體配額。
先停止原生 `python server.py`，不可讓兩個服務共用同一個資料庫與埠。

```bash
mkdir -p runtime
docker compose up --build -d
# 測試程式仍在本機 Python 執行
python experiment.py --scenario normal --mode off --seconds 30
docker compose down
```

配置只發布 `127.0.0.1:8000`，不應改為公網綁定。SQLite 與 token 放在 runtime 掛載資料夾。
初次建置需要網路下載映像和套件，測試請求本身只連本機。
Dockerfile 採通用 Python 映像標籤；正式可重現實驗應另外鎖定映像 digest。

## 9. 五人第一週驗收

A：讀懂 database.py，示範商品、報表與真實訂單寫入，畫出資料表關係。
B：讀懂 server.py，分清排隊、執行、資料庫鎖等待，確認名額不會漏還。
C：讀懂 policy.py，用自己的話解釋每次增加/減少名額的依據，提出一個可測的改進。
D：執行四種情境，保存結果與參數，確認三組請求時程一致，查核訂單。
E：整理結果欄位，先做最小展示：模式、正常訂單完成率、排隊時間、報表拒絕数。

第一週不要急著做登入、漂亮 Dashboard 或接大模型。先讓五個人都能在自己的機器跑通。
第二階段再拆代理/後端、換 PostgreSQL、加入真實帳號/配額與完整遙測。
正式比較加入合理調參的固定限流、分功能固定配額、整體自適應控制，並做模組消融。

## 10. 常見問題

- `No module named fastapi`：使用虛擬環境 Python 執行 `-m pip install -r requirements.txt`。
- 8000 已被使用：停止佔用的舊實驗服務。腳本不允許換成任意目標。
- 找不到 admin.token：先從同一專案啟動伺服器；Docker 選項確認 runtime 掛載成功。
- 409：上一輪還有工作或另一個實驗正在重設，先停止其他測試並等待排空。
- SQL interrupted/503：執行碰到實驗安全期限，結果必須記錄；先降低本機報表批數。
- 三種都很好或 fixed 更好：如實保留結果。動態規則並不保證勝出。

**可交付專題的核心仍是你們後續提出、解釋並驗證的策略，而不是原封不動提交這份起始程式。**
