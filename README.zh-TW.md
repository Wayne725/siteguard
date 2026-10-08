# SiteGuard 網站資源防護閘道

部署在現有網站前方，限制過量 HTTP 請求、隔離耗資源路由，保留其他請求的處理額度。網站不必導入 SDK 或逐筆呼叫雲端 API：流量經過 Envoy，Python 工具管理設定與部署，私有的政策程序處理額度，並可檢查指定 API 的敏感回應。

```text
使用者 → 既有 HTTPS／CDN／反向代理 → SiteGuard → 原有網站
                                        ↓
                                  私有限流程序
```

目前提供 **0.3.0 可受控試用版**：[下載安裝包](https://github.com/Wayne725/siteguard/releases/download/v0.3.0/siteguard-0.3.0.zip)、[快速開始](docs/套件快速開始.md)、[防火牆與新版驗收](docs/網站入口防火牆.md)。安裝包已在乾淨環境驗證，含 wheel、設定範例、操作指南及 SHA-256。

0.1.0 的 72 項自動化回歸、Python／Node 網站協定案例、Nginx 私有網路接入與更新回復皆通過。本機受控過載中準時訂單從 3／24 提升到 24／24，同時拒絕更多耗資源請求；正常流量樣本皆 40／40 成功，p95 從 1.967 ms 增為 7.067 ms。這些有限證據不等於大部分真實網站已證實有效。

0.2.0 通過 117 項自動化測試、56 項原生資安案例及 17 項原有 Python 網站功能回歸。新版增加敏感檔案封鎖、管理入口來源限制、安全標頭，以及指定小型 API 的私鑰／token 洩漏阻擋。預設 observe 不封鎖、不掃描回應；功能範圍與啟用方式見 [資安防護功能](docs/資安防護功能.md)。

0.3.0 通過 135 項自動化測試、51 項原生防火牆驗收，並重驗 36 項資安與 17 項網站功能。新增 [網站入口防火牆](docs/網站入口防火牆.md)：全站 IPv4／IPv6 允許與封鎖清單、封鎖優先、可信代理來源失效時拒絕。設定範例：[siteguard-firewall.yaml](examples/siteguard-firewall.yaml)。

## 安裝

需要 Python 3.11 以上、Docker 與 Compose，使用 Linux／macOS；Windows 可在 WSL2 執行。在此專案目錄執行：

```bash
python3 -m venv .siteguard-venv
.siteguard-venv/bin/python -m pip install .
.siteguard-venv/bin/siteguard init --upstream http://host.docker.internal:3000
.siteguard-venv/bin/siteguard check
.siteguard-venv/bin/siteguard up
.siteguard-venv/bin/siteguard status
```

下載 wheel 時，把 `pip install .` 換成 `pip install siteguard_gateway-0.3.0-py3-none-any.whl`。首次啟動需下載固定版本映像與套件；不需要 API key，也不把網站流量或設定送往雲端服務。

預設建立 `siteguard.yaml`，只綁 `127.0.0.1:8088`、採觀察模式。先開啟 `http://127.0.0.1:8088` 驗證原網站，再把既有反向代理指向此埠。管理介面與限流埠都不對外公開。

Colima 的 macOS 主機來源請用 `host.lima.internal`；既有容器可指定 `upstream.network` 加入原網站網路。容器內的 `127.0.0.1` 不是主機。完整接入、HTTPS、串流、限制設定及回復流程見 [網站安裝與操作](docs/網站安裝與操作.md)。

## 操作

```bash
siteguard metrics --format prometheus
siteguard logs --service all --tail 100
siteguard up
siteguard rollback
siteguard down
```

更新先建置候選並執行 Envoy 原生驗證；成功版本保留內容雜湊與快照。更新失敗時保存診斷並嘗試還原。`status` 的 ready 代表代理與限流程序就緒，來源網站仍需實際請求驗證。

本工具防護 HTTP 層的資源競爭，不能處理已塞滿的上游頻寬，也不能取代網站授權、交易冪等或 SQL 期限。多副本尚不共用限流額度。效果應用相同負載比較，連同合法請求的代價一起判讀。

可用性、誤擋、效能與回復的逐步驗收，見 [可用性測試指南](docs/可用性測試指南.md)。

開發者測試與原始證據工具位於 [tests/integration](tests/integration/README.md)。原研究實驗完整保留，操作入口移至 [實驗室指南](LAB_README.md)。

## 授權與參與

本專案原創程式與文件採 [MIT License](LICENSE)，允許商業使用、修改與再散布，需保留授權與著作權聲明。第三方依賴維持各自授權，見 [第三方說明](THIRD_PARTY_NOTICES.md)。

問題修正與驗收方法見 [貢獻指南](CONTRIBUTING.md)；安全漏洞請依 [安全政策](SECURITY.md) 私下回報。版本變更見 [CHANGELOG](CHANGELOG.md)。

歷史測試數據依原文件保留；本次公開發布的重新驗證範圍見 [發布驗證](docs/發布驗證.md)。本機 runtime、管理 token、虛擬環境及完整執行產物不納入原始碼儲存庫。
