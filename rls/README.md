# Python RLS 擴充

日期：2026-10-01

這是供隔離實驗使用的單程序、單實例 Envoy v3 Rate Limit Service。它控制**送入速率**，不代表資料庫工作完成，也不發放需要歸還的並行名額。
計數保存在本機記憶體，不能直接開多個 replica 後宣稱仍有相同全域限制；本版未實作分散式共享額度。

## 啟動與接口

```bash
.venv/bin/python -m pip install -r rls/requirements.txt
RLS_MODE=fixed .venv/bin/python -m rls.server
```

預設連接 `http://127.0.0.1:8000` 並讀取 `local_ddos_lab/runtime/admin.token`。
容器環境使用 `LAB_ORIGIN_URL=http://app:8000`、`LAB_ADMIN_TOKEN_FILE=/app/runtime/admin.token`、`RLS_BIND=0.0.0.0:50051`。
原生預設只監聽 `127.0.0.1:50051`。只有 Envoy／測試程式會呼叫此服務，沒有對外發布 RLS 埠。

使用官方 `envoy.service.ratelimit.v3.RateLimitService/ShouldRateLimit`：

- `domain` 必須為 `local-ddos-lab`。
- 每個 descriptor 必須恰有一個 `kind=products|orders|report` entry。
- `hits_addend` 未指定或為 0 時消耗 1；可用整數 1～100，一次最多 32 個 descriptor。
- 多個 descriptor 必須全部有額度才一起扣除，失敗不會先扣另一個功能的額度。相同 descriptor 重複出現會累加消耗。
- 不接受客戶端覆寫 descriptor 的額度或各別 hits；未知 domain、kind 與格式均回 `OVER_LIMIT`，`bypass` 也不例外。
- 除是否放行外，`dynamic_metadata` 包含模式、報表速率、決策與目前 `run_id`；不包含管理 token。

## 模式與參數

| 參數 | 預設 | 允許值 |
|---|---|---|
| `RLS_MODE` | `bypass` | `bypass`、`fixed`、`feedback` |
| `RLS_PRODUCTS_RATE` | 12 | 每秒 0.5～50 |
| `RLS_ORDERS_RATE` | 8 | 每秒 0.5～50 |
| `RLS_REPORT_RATE` | 2 | 每秒 0.5～50 |
| `RLS_PRODUCTS_BURST` | 該功能速率，至少 1 | 1～100 |
| `RLS_ORDERS_BURST` | 該功能速率，至少 1 | 1～100 |
| `RLS_REPORT_BURST` | 該功能速率，至少 1 | 1～100 |

`bypass` 在格式驗證後直接放行；`fixed` 對三類功能各用 token bucket。啟動與新實驗的 bucket 都從完整 burst 開始，正式比較需一致暖機。
Compose 明確設定 burst 為 12／8／2；容器調整 rate 時若也要調整 burst，需一起設定相對應環境變數。

`feedback` 每次輪詢後等待 250 ms，再讀取 `/lab/state`；HTTP 期限 500 ms。控制器最多每秒更新一次，只改報表 refill rate：

1. 執行中工作／worker 數至少 75%，**且**有工作排隊或實際 `active_after_disconnect` 非零時，報表速率減半，最低 0.5／秒。低使用率下的單一取消殘留工作不會觸發縮限。
2. 使用率低於 50%、沒有排隊，且當個窗口真的有 received 增量，才計入穩定窗口；連續 3 個才增加 0.25／秒，最多回到設定基準。低占用下的取消後殘留工作不會單獨阻止恢復。
3. 單純取消次數增加不會縮限；沒有新工作不會累積恢復窗口。
4. 啟動尚無有效狀態，或最後有效狀態超過 2 秒時，恢復基準固定速率。這是預先約定的故障退回策略，並不保證比目前動態值更低。
5. 讀到不同 `run_id` 時重設所有 bucket、恢復窗口與速率，避免沿用上一個實驗的控制狀態。

取消後殘留工作可能比輪詢間隔更短而沒有被取樣，因此這份原型不能宣稱已完整量測所有取消成本。結束後還需用後端事件檔計算實際殘留時間。
背景輪詢在三種模式都執行，讓量測負擔一致。HTTP 管理 token 每次重讀以支援後端重啟；輪詢錯誤只記錄錯誤類型，連續錯誤只輸出一次。

實驗 reset 後，在送入下一組工作前留出輪詢同步時間；正式實驗使用一致暖機，並保存 RLS 的 `run_reset`／`control_update` JSON 紀錄。服務不逐筆印出准入紀錄，以免日誌成為額外負載。

## 驗證

```bash
.venv/bin/python -m unittest rls.test_policy rls.test_service -v
RUN_RLS_SOCKET_TESTS=1 .venv/bin/python -m unittest rls.test_service.GrpcTransportTests -v
```

已通過 20 項無 socket 的策略／protobuf 介面測試，以及 1 項真實 localhost gRPC server／官方 client 測試。
測試涵蓋 refill、突發上限、原子扣額、run reset、資料過期、取消訊號、無樣本恢復抑制、格式拒絕及並行 RPC。
這些測試不等於已證明 feedback 模式能改善正常訂單；結論仍須依相同負載的完整比較。
