# Siteguard 的本機整合驗證

這組 fixture 與既有 `local_ddos_lab` 分離。只使用 `127.0.0.1:18100`、`18101` 與 gateway `18088`，不接受其他主機、埠、代理環境變數或重新導向目標。核心驗證器只需要 Python 標準函式庫；HTTP/2 額外需要開發依賴 `h2`，缺少時結果明確標示 `skipped`。

## 執行

先啟動指向 `127.0.0.1:18100` 的 Siteguard gateway，監聽 `18088`。請使用 `mode: enforce`，並讓 `/heavy` 使用較小的資源額度；不要限制 `/events`、`/ws` 的串流。

驗證器可以自行管理 fixture，完成後一定關閉自己啟動的服務：

```sh
.venv/bin/python tests/integration/verify.py \
  --base-url http://127.0.0.1:18088 \
  --fixture-url http://127.0.0.1:18100 \
  --own-fixture --suite all --seconds 6 --seed 42 \
  --output artifacts/siteguard/verification.json
```

`--own-fixture` 會額外暫停自己建立的來源 listener，驗證 gateway 回傳 502／503／504，重啟來源後恢復 200。埠被其他程式占用時啟動會失敗，不會停止或替換其他人的服務。若要保留 fixture 方便手動除錯，可在另一個終端啟動，然後省略 `--own-fixture`：

```sh
.venv/bin/python tests/integration/fixture.py --port 18100
.venv/bin/python tests/integration/verify.py \
  --base-url http://127.0.0.1:18088 --fixture-url http://127.0.0.1:18100 \
  --suite functional --output artifacts/siteguard/http-compatibility.json
```

不啟動 gateway 也可以自測 HTTP/1.1 fixture：

```sh
.venv/bin/python -m unittest discover -s tests/integration -p 'test_*.py' -v
```

## 第二個 HTTP stack：Node.js

`node_fixture.cjs` 使用 Node.js 內建 `http`、`crypto` 與 `worker_threads`，沒有 npm 套件。它只能綁定 `127.0.0.1:18101`，與 Python fixture 的 `18100` 分開；功能 endpoint 與 JSON 稽核格式相同，`/fixture/state` 另有 `implementation: "node"`。控制介面仍是 `/fixture/availability`、`/fixture/reset`、`/fixture/state`；`/fixture/control` 是 availability 的別名。

```sh
node tests/integration/node_fixture.cjs
```

將 gateway 的 upstream 指向 Node fixture，再執行：

```sh
.venv/bin/python tests/integration/verify.py \
  --base-url http://127.0.0.1:18088 --fixture-url http://127.0.0.1:18101 \
  --suite all --seconds 6 --seed 42 \
  --output artifacts/siteguard/node-verification.json
```

此時不要加 `--own-fixture`，該選項管理的是 Python fixture。Node fixture 由啟動它的終端以 Ctrl-C 停止。它有 4 個真實工作執行緒，`/heavy` 在執行緒內做約 350 ms 的 PBKDF2 CPU 工作，訂單共享同一組工人。`test_node_fixture.py` 會自行啟停 Node fixture 做功能與工作稽核測試；找不到 Node 時明確跳過。不同 stack 的結果分別保存，不把同介面通過等同於所有框架都相容。

## 涵蓋範圍與結果

`--suite functional` 實際檢查 HTML、HEAD、表單／JSON、Cookie／Authorization、重複 query 參數與中文路徑、redirect Location、ETag／304、Range／206、64 KiB multipart 檔案完整性、SSE 首段到達、WebSocket 雙向文字／二進位／ping-pong／正常 close，以及來源 503／恢復。HTTP/2 使用 cleartext prior knowledge，沒有驗證 TLS／ALPN。

`--suite load` 用同一份 seed 排程依序跑 direct 與 gateway；`--gateway-first` 可反轉順序。每批到達窗口 3～10 秒、固定每秒 16 筆 `/heavy` 與 4 筆 `/orders`，client inflight 最多 32；產生器落後超過 100 ms 時保留 drop，不補送。窗口結束後等待既有請求與來源工作排空。每個 HTTP 請求最多等待 3.5 秒。

來源有共享的 4 個工作執行緒；`/heavy` 在工作執行緒內進行約 350 ms 的 PBKDF2 CPU 工作，`/orders` 使用同一組工人。工作不讀取 gateway 標頭、不因請求走哪條路徑而改變成本。訂單以預定到達時間起算 300 ms 作為本 fixture 的期限。

JSON 保存排程、每筆 request ID／時程／輸入摘要、HTTP 結果、延遲、來源工作記錄與最終訂單。拒絕與漏送都留在分母；同一訂單鍵即使只建立一次，只要來源收到兩次合法 POST，也會被 `duplicate_post_attempts` 抓出。只有無 drop、稽核通過且排程相同時，`valid_comparison` 才成立；`business_benefit_observed` 只表示這一對本機樣本的準時訂單有所改善。

POST 計數在合法請求解析完成後、准入判斷之前增加，包含來源容量不足而回 503 的那次請求。`post_attempts` 記收到幾次、`post_executions` 記工人實際執行幾次、`orders` 記唯一提交；負載摘要的 `acknowledged_orders`／`successful_orders` 則記客戶端收到有效成功 ACK 幾次。這四者分開保存，因此「先拒絕、再重送成功」也不會漏掉重送行為。

## 有界標頭與非串流路由檢查

`verify_security.py` 最多發出 7 筆本機請求，不會啟動、修改或重載 gateway。它檢查傳入的 `x-envoy-*` 控制值是否被移除、偽造 forwarded identity 是否被替換；沒有指定額外測試 profile 時，body／timeout 檢查會明確跳過。

```sh
.venv/bin/python tests/integration/verify_security.py \
  --base-url http://127.0.0.1:18088 \
  --output artifacts/siteguard/header-isolation.json
```

完整路由邊界檢查需要由操作者先啟用獨立 profile：`mode: enforce`、`policy.max_body_bytes: 1024`、`policy.request_timeout_seconds: 1`、`trusted_proxy_cidrs: []`，而 `/echo` 與 `/delay` 保持非串流路由。全域與每 IP rate／burst 需足以容納這 7 筆檢查。接著執行：

```sh
.venv/bin/python tests/integration/verify_security.py \
  --base-url http://127.0.0.1:18088 --body-limit-bytes 1024 --timeout-seconds 1 \
  --output artifacts/siteguard/route-isolation.json
```

body 檢查每項兩筆請求；timeout 檢查每項三筆。先驗證一般請求的限制真的生效，再加入 Upgrade 或客戶端 timeout 控制標頭，避免把「本來就沒有套用限制」誤認為安全。來源 `/delay` 最多延遲 1500 ms，不執行訂單工作。

要驗證偽造 XFF 無法取得不同 per-IP 額度，必須另開全新的低 rate profile（`per_ip_rate: 1`、`per_ip_burst: 1`），在一秒內從同一來源送最多三筆、每筆換不同假 XFF 的 GET，預期 200／429／429。先跑其他檢查會消耗那一個 token；本工具只在 JSON 留下這份操作要求，沒有自行啟動該 profile或宣稱此項已通過。

這些結果不能證明「適用大多數網站」、分散式 DDoS 防護、網際網路部署安全性，或未測過的框架／瀏覽器／TLS／代理組合。沒有觀察到收益時保留原始結果，不調整 fixture 讓 gateway 必然勝出。

## Body 大小限制的 10 案例矩陣

`verify_body_limits.py` 僅連線本機 gateway `127.0.0.1:18088`，不啟動或修改 Docker、設定或 fixture。先由操作者準備 `mode: enforce`、`policy.max_body_bytes: 1024`，且 `/echo` 是未覆寫上限的普通非串流路由；來源必須為上述測試 fixture。全域、路由及每 IP rate／burst 要足以容納本輪請求。上限固定為 **1024 bytes**，本工具不讀取部署設定，也不能用預設 10 MiB 上限執行後宣稱通過。

```sh
.venv/bin/python tests/integration/verify_body_limits.py \
  --base-url http://127.0.0.1:18088 \
  --output artifacts/siteguard/body-matrix.json
```

五種傳輸各送 1024 與 1025 bytes，共 10 筆：HTTP/1.1 Content-Length 一次寫入、Content-Length 兩次寫入、chunked 兩個 body 區塊，以及 HTTP/2 一個或兩個 DATA frames。HTTP/2 使用 cleartext prior knowledge、不帶 Content-Length，需安裝開發依賴 `h2`；缺少依賴會記為失敗。兩段之間間隔 50 ms，TCP 實際分段仍由網路堆疊決定。

1024 bytes 必須回 200 並逐 byte 符合原始 body；1025 bytes 必須收到完整 HTTP 413。reset、EOF、timeout、429、503 都不能算 body 限制成功；單段與分段結果不可互相替代。JSON 保留原始 payload／hash、回應、傳送與接收事件、傳輸錯誤；任一案例不符即以非零狀態退出。重驗時分別保存檔案；若核對來源請求與 `lua.errors` 指標，應確認同一部署未重啟並保留前後值。三輪矩陣應只有 15 筆界內請求到達來源。

這是普通路由的邊界回歸，不是壓力測試。路由覆寫、觀察模式、串流豁免及 TLS 應另驗；完成矩陣後仍需重跑上述完整標頭／Upgrade／timeout 檢查。

## 等待 100 Continue 的上傳用戶端

`verify_expect_continue.py` 固定連到 `127.0.0.1:18088` 的普通 `/echo`，先只送 HTTP/1.1 標頭，包含 `Expect: 100-continue`；收到 100 後才傳送短 body。gateway 與 fixture 必須已啟動，Host 規則須容許 `localhost`，body 上限及速率額度須容許這一筆合法請求；可使用上述 1024-byte profile。

```sh
.venv/bin/python tests/integration/verify_expect_continue.py \
  --output artifacts/siteguard/expect-continue.json
```

通過條件是先收到 100 Continue，再得到 200 與完全相同的 body。僅收到 100 不算成功；等待時回 408、直接回其他狀態、連線結束、逾時或 body 不一致都會失敗，不能改成先傳 body 來避開等待問題。JSON 保存 interim response、最終狀態、回應與錯誤，失敗以非零狀態退出。此工具不修改服務，只驗證一筆 HTTP/1.1 上傳握手；不能取代 body 超限矩陣。


## 0.2.0 資安防護

`security_fixture.py` 使用 127.0.0.1:18102，僅含刻意製造的假秘密。測試閘道固定 127.0.0.1:18090。`verify_incident_prevention.py --suite all --own-fixture --output <檔案>` 驗證 36 項請求／回應案例，逐筆核對來源呼叫數與完整 wire。`verify_incident_protocols.py --phase enforce|observe|scanner-down|canonical-broken --own-fixture --output <檔案>` 驗證對應模式；切換與故障注入須只操作自己擁有的隔離部署。

原始設定、單元測試及原生結果保存在 `artifacts/siteguard/incidents/`。本輪含觀察模式、精確 CIDR 放行、巢狀 guard、檢查服務斷線與 Lua 錯誤；故障測試完成後恢復原設定。


## 0.3.0 網站入口防火牆

`verify_firewall.py --phase deny|allow|observe|deny-all --own-fixture --output <檔案>` 使用既有 18102 自有來源站及 18090 隔離閘道，驗證拒絕時來源呼叫為零、放行時恰為一次；同時覆蓋 SSE 首段、WebSocket 握手與 `OPTIONS *`。不會自行修改閘道設定。

本輪 profile 與結果位於 `artifacts/siteguard/firewall/`，另有可信代理壞 XFF、IPv4-mapped IPv6 與 IP 家族隔離的有限測試。`run_acceptance.py` 僅供自有 `siteguard-firewall` 測試部署使用，切換各 profile 後重驗原有 36 項資安案例。
