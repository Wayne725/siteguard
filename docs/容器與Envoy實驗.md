# 容器與 Envoy 實驗

日期：2026-10-01

## 已完成與尚待驗證

已提供四份 Envoy 設定、Compose、容器建置檔、產生設定工具及 8 項靜態測試。
設定已通過 `xds-protos` 官方生成 protobuf 型別解析與路由隔離檢查。
本機已安裝 Docker CLI、Compose、Buildx 與 Colima，專用 profile 為 `data-security`。完整的 binary validate、HTTP 與 PostgreSQL 實跑狀態集中記錄於 [原型驗證紀錄](原型驗證紀錄.md)，不可用靜態解析替代這些檢查。

## 架構與模式

```text
測試程式 → 127.0.0.1:8080 Envoy → app:8000 FastAPI → postgres:5432
                                 ↘ rls:50051 Python RLS
                                      ↘ app:8000/lab/state（管理 token）

測試管理與訂單稽核 → 127.0.0.1:8000（管理 token）
Envoy 狀態與統計   → 127.0.0.1:9901
```

資料庫與 RLS 不發布主機埠，主機的 8000、8080、9901 僅綁定 loopback。
資料庫與 RLS 僅加入 internal 的 `lab` 網路；app 與 Envoy 另加入 `edge` bridge，讓 localhost port publishing 生效。本機實測僅加入 internal bridge 時，HostConfig 有綁定但 NetworkSettings.Ports 為 null，主機無法連線。雙網路的 app／Envoy 仍有對外連線能力，不能宣稱整套容器都禁止 egress；參考 [Docker Compose 網路說明](https://docs.docker.com/compose/how-tos/networking/)。
Envoy 入口只轉送 `/`、`/health`、`/live`、`/ui.js`、`/api/products`、`/api/orders`、`/api/report`；其他路徑回覆 404。
`/lab/*`、`/stats`、`/config_dump` 不能從 8080 代理到管理介面。`x-lab-admin` 不會由入口轉送。
`/health` 以有期限、共用且最多 5 秒快取的 DB 探測回覆就緒；資料庫不可用時回 503。`/live` 僅表示程序存活。兩者由 health-check filter 標記，原版 adaptive filter 跳過該類取樣。

| ENVOY_MODE | RLS_MODE | 控制內容 |
|---|---|---|
| `off` | `bypass` | 共同資源限制；無額外 RLS 或 adaptive filter |
| `adaptive` | `bypass` | Envoy 原版 gradient adaptive concurrency |
| `rls` | `bypass` | 只有 RLS RPC 開銷，准入放行 |
| `rls` | `fixed` | Python 固定速率額度 |
| `rls` | `feedback` | Python 後端回饋速率額度 |
| `rls_adaptive` | `bypass`／`fixed`／`feedback` | 先 RLS，再原版 adaptive，屬組合策略 |

三個 RLS 模式共用同一個獨立 `rls` service，由環境變數切換，避免同時運行互相競爭。
`rls_adaptive` 會有兩個控制器互相影響；報告必須寫成「組合策略」，不能當成改寫原版 gradient 的效果。
比較組合時也要包含 `rls_adaptive + bypass`，以區分 RPC 開銷與策略效果。

原有五個代理比較組的 FastAPI 內部模式設成 `off`；新增 `backend-fixed` 組使用後端 `fixed`、Envoy `off`、RLS `bypass`。全部保留相同總工作上限、有限排隊、SQL 期限與取消回收；後端報表額度是明確的比較變因。
`experiment.py --mode all` 比較的是後端原始三種策略，**不會自動切換 Envoy 或 RLS**。
Envoy 不自動重試訂單；每個組別的共同上限、請求時程、查詢成本與資料集維持一致。

## RLS 接口契約

- 使用官方 `envoy.service.ratelimit.v3.RateLimitService/ShouldRateLimit` gRPC 方法。
- `domain=local-ddos-lab`，descriptor 為固定路由產生的 `kind=products|orders|report`。
- 請求分類由路由決定，不信任用戶提供的 header；正常／額外需求標籤不送給策略。
- RLS `OK` 放行，`OVER_LIMIT` 由 Envoy 回覆 429。
- RPC 期限 100 ms；服務故障時拒絕並回覆 503，與策略超額分開分析。
- RLS 只管理速率額度，沒有完成通知；實際資料庫在途數由 FastAPI 量測。
- Python 啟動命令為 `python -m rls.server`。環境變數為 `RLS_MODE`、`RLS_BIND`、`LAB_ORIGIN_URL`、`LAB_ADMIN_TOKEN_FILE`，詳見 Compose。

## 有 Docker 後啟動

在專案根目錄執行。需要支援 `--wait` 的 Docker Compose。本機 Colima 配置為 2 vCPU、3 GiB 記憶體。
四個容器的 CPU 配額合計 3 核心，記憶體上限合計約 1.5 GiB；容器仍會競爭 VM 的 2 vCPU，配額總和不代表有 3 個實體核心。這些是尚未校準的初值，正式比較需同時固定 VM 與容器資源。

```bash
mkdir -p local_ddos_lab/runtime
export LAB_UID="$(id -u)" LAB_GID="$(id -g)"
docker compose config
docker compose up --build -d --wait
docker compose ps
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/api/products
curl --fail http://127.0.0.1:9901/ready
```

`LAB_UID`、`LAB_GID` 讓容器與主機使用者一致，避免 `runtime/admin.token` 的 0600 權限讓本機產生器讀不到。
首次初始化會建立合成商品與銷售資料。若啟動失敗，先看 `docker compose logs app postgres rls envoy`，不要直接開始負載測試。
若本機已有原生 FastAPI 使用 8000，先在原終端以 Ctrl-C 停止，再啟動 Compose。
Windows PowerShell 可用預設 UID/GID 1000；需要確認 Docker Desktop 允許掛載此專案資料夾。

容器版使用 PostgreSQL 17 與 named volume `postgres_data`。這是合成資料實驗帳號，沒有連接正式資料庫。
本版 Python、PostgreSQL 與 Envoy 已固定到 2026-10-01 向官方 registry 查得的 manifest digest；見 `deploy/image-pins.json`、Dockerfile 與 Compose。更新版本時仍需重新驗證。

```bash
docker image inspect postgres:17-alpine --format '{{json .RepoDigests}}'
docker image inspect envoyproxy/envoy:v1.39.1 --format '{{json .RepoDigests}}'
docker image inspect python:3.13-slim --format '{{json .RepoDigests}}'
docker compose images
```

保存這些輸出、`docker compose config`、主機規格、runtime 版本及程式版本。若只以 digest 拉取而沒有本機 tag，可用 Compose 實際 image reference 或 container image ID 查詢；不要填造出的 digest。

## 驗證設定與入口隔離

無 Docker 也可以執行第一組檢查：

```bash
.venv/bin/python -m pip install -r deploy/requirements.txt
.venv/bin/python deploy/validate_config.py
.venv/bin/python -m unittest deploy.test_config -v
```

`xds-protos` 的版本跟 Envoy release 不同；這一層只檢查官方 wire schema，不能檢查指定 Envoy 版本的所有語意限制。
有 Docker 後，用固定映像逐份驗證：

```bash
ENVOY_MODE=off docker compose run --rm --no-deps envoy envoy --mode validate -c /etc/envoy/envoy.yaml
ENVOY_MODE=adaptive docker compose run --rm --no-deps envoy envoy --mode validate -c /etc/envoy/envoy.yaml
ENVOY_MODE=rls docker compose run --rm --no-deps envoy envoy --mode validate -c /etc/envoy/envoy.yaml
ENVOY_MODE=rls_adaptive docker compose run --rm --no-deps envoy envoy --mode validate -c /etc/envoy/envoy.yaml
curl -i http://127.0.0.1:8080/lab/state
curl -i http://127.0.0.1:8080/config_dump
```

後兩項應回覆 404，管理操作不得到達後端。正式驗收再測：RLS 不可達回覆 503、RLS 超額回覆 429、資料庫中止後 health 與 API 的結果、恢復後可重新下單。
RLS Compose healthcheck 僅確認 TCP listener 存活；正確 protobuf 回應與模式行為要用 Python RLS 測試及上述 HTTP 整合測試確認。

## 跑第一個有界實驗

以下先確認串接與訂單正確性；短測試不證明改良有效。不要同時在 8000 與 8080 送入業務負載，以免干擾 Envoy 的並行控制。

```bash
.venv/bin/python local_ddos_lab/experiment.py --base-url http://127.0.0.1:8080 --scenario normal --mode off --seconds 10 --label envoy-off
ENVOY_MODE=adaptive RLS_MODE=bypass docker compose up -d --force-recreate --wait rls envoy
.venv/bin/python local_ddos_lab/experiment.py --base-url http://127.0.0.1:8080 --scenario mixed --mode off --seconds 10 --label envoy-adaptive
ENVOY_MODE=rls RLS_MODE=fixed docker compose up -d --force-recreate --wait rls envoy
.venv/bin/python local_ddos_lab/experiment.py --base-url http://127.0.0.1:8080 --scenario mixed --mode off --seconds 10 --label rls-fixed
ENVOY_MODE=rls RLS_MODE=feedback docker compose up -d --force-recreate --wait rls envoy
.venv/bin/python local_ddos_lab/experiment.py --base-url http://127.0.0.1:8080 --scenario mixed --mode off --seconds 10 --label rls-feedback
```

每組之前先確認上組工作已排空；Envoy 與 RLS 重建後狀態歸零。正式比較應加入一致暖機，凍結參數後用相同種子重播，隨機化模式順序，檢查 generator drops 與訂單稽核。
原版 adaptive 的 minRTT 取樣期可能收緊名額並產生 503；需要保存 `min_rtt_calculation_active` 與名額變化，不能把這段略去不報。

```bash
curl --fail 'http://127.0.0.1:9901/stats?filter=adaptive_concurrency'
curl --fail 'http://127.0.0.1:9901/stats?filter=ratelimit'
docker compose logs --no-color envoy rls
```

## 沒有 Docker 的 macOS

本機 Apple Silicon 已安裝 Colima 0.10.3、Docker CLI 29.8.0、Compose 5.5.1 與 Buildx 0.37.0；以下供新機器參考。
可選 Docker Desktop，或依 [Colima 官方說明](https://github.com/abiosoft/colima) 使用 Homebrew 安裝 `colima`、`docker` 與 `docker-compose`。
Homebrew 的 Compose CLI plugin 路徑設定應依 `brew info docker-compose` 輸出操作，完成後先確認 `docker compose version`。

```bash
brew install colima docker docker-compose docker-buildx
colima start data-security --cpus 2 --memory 3 --disk 15 --activate=false
export DOCKER_CONTEXT=colima-data-security
docker version
docker compose version
```

本機首次 VM 開機曾在 SSH session 建立階段逾時等待，最終成功；沒有修改主機網路或重建 VM。停止實驗後可用 `colima stop data-security` 釋放 VM 資源。

若已自行備妥 **原生 Envoy v1.39.1**，可以直接接原生 FastAPI／RLS，不必使用容器 DNS 名稱：

```bash
.venv/bin/python deploy/render_envoy.py --mode adaptive --upstream 127.0.0.1 --rls-host 127.0.0.1 --bind 127.0.0.1 --admin-bind 127.0.0.1 --output /tmp/ddos-lab-envoy.yaml
envoy --mode validate -c /tmp/ddos-lab-envoy.yaml
envoy -c /tmp/ddos-lab-envoy.yaml --concurrency 1 --log-level warn
```

不可直接在主機使用預設容器版 YAML：它綁定 0.0.0.0 且使用 Compose DNS。原生測試的資料庫與 CPU 配額不同，結果要分開保存。

## 停機與資料保存

先停負載產生器，再等待後端工作排空並完成訂單稽核，最後停止服務：

```bash
docker compose stop envoy rls
docker compose stop app postgres
docker compose down
```

`down` 保留 PostgreSQL named volume；`local_ddos_lab/runtime` 與結果檔也保留。
不必用 `down --volumes` 重設每次實驗，測試工具的受保護 reset API 已負責還原合成訂單及庫存。
僅在確定要刪掉所有容器合成資料時才使用 `docker compose down --volumes`。

## 官方依據

- [Envoy v1.39.1 Docker 與權限](https://www.envoyproxy.io/docs/envoy/v1.39.1/start/docker)
- [Adaptive concurrency 行為與限制](https://www.envoyproxy.io/docs/envoy/v1.39.1/configuration/http/http_filters/adaptive_concurrency_filter)
- [Adaptive v3 設定](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/extensions/filters/http/adaptive_concurrency/v3/adaptive_concurrency.proto)
- [RLS v3 官方介面](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/service/ratelimit/v3/rls.proto)
- [PostgreSQL 支援版本](https://www.postgresql.org/support/versioning/)
- [Colima 官方安裝與使用](https://github.com/abiosoft/colima)

## 新版六組配對工具

目前操作入口與參數集中於 [README](../README.md)。`scripts/run_comparison.py --plan` 可先預覽六組模式、種子與順序，再移除 `--plan` 執行。支援一般負載及 `--workload cancellation`、可重播 arrival、1～10 輪與平衡順序；不同組排程 hash 不一致或批次中途來源程式變更會中止。

取消探針各 round 保存 `gateway_stats_start.json` 與 `gateway_stats_end.json`。wait/cancel 之間重設 app/RLS，但仍共用 Envoy 控制器；兩筆暖機不保證完成 minRTT 初始估測。metadata 與報告會明示此限制，平衡順序也不能單獨消除所有狀態差異；正式因果研究仍須另外控制閘道初始化。
