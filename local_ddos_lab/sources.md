# 官方參考資料

查閱日期：2026-09-30。起始程式是本次撰寫的教學實作，不是下列專案的官方範例。

1. Python sqlite3：SQLite 可做原型；參數化 SQL、交易及 progress handler 中斷查詢。
   https://docs.python.org/3/library/sqlite3.html
2. FastAPI：同步/非同步工作與執行緒的處理方式。
   https://fastapi.tiangolo.com/async/
3. Docker Compose 網路：服務網路、port mapping 與內部網路。
   https://docs.docker.com/compose/how-tos/networking/
4. Docker localhost port publishing。
   https://docs.docker.com/engine/network/port-publishing/
5. Grafana k6：open/closed model；不能因後端變慢而讓到達率悄悄降低。
   https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/open-vs-closed/
6. OWASP API4：資源消耗、執行期限、用量與請求限制。
   https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
7. Envoy Adaptive Concurrency：已有動態並行控制；不能把相同概念直接宣稱新穎。
   https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter
