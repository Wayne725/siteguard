# 第三方來源與授權

本儲存庫的 MIT License 適用於原創程式與文件，不重新授權第三方依賴、容器映像或其所包含的作業系統套件。本儲存庫未將虛擬環境或第三方套件原始碼複製納入。

## 執行與研究依賴

第三方套件由 pip 或 Docker 另行下載；請以安裝版本隨附的 LICENSE／NOTICE 為準。容器映像同時含有其他套件，各自授權仍適用。

| 元件 | 使用方式／原始來源 |
| --- | --- |
| PyYAML | Python 設定解析：[官方儲存庫](https://github.com/yaml/pyyaml) |
| Envoy | 閘道與協定實作：[官方儲存庫](https://github.com/envoyproxy/envoy) |
| xds-protos／gRPC | 限流與回應檢查的 protobuf／gRPC 介面：[xDS](https://github.com/cncf/xds)、[gRPC](https://github.com/grpc/grpc) |
| FastAPI／Uvicorn／Pydantic | 本機研究 fixture：[FastAPI](https://github.com/fastapi/fastapi)、[Uvicorn](https://github.com/encode/uvicorn)、[Pydantic](https://github.com/pydantic/pydantic) |
| Psycopg／PostgreSQL | 研究資料庫與驅動：[Psycopg](https://github.com/psycopg/psycopg)、[PostgreSQL](https://www.postgresql.org/) |
| HTTPX／h2 | 開發與協定驗證：[HTTPX](https://github.com/encode/httpx)、[h2](https://github.com/python-hyper/h2) |
| Python 與基礎映像 | Python 執行環境：[Python](https://www.python.org/)、[Docker Official Images](https://github.com/docker-library/official-images) |

完整直接依賴與固定版本見 pyproject.toml、各 requirements.txt、Dockerfile 與 deploy/image-pins.json；這些不是所有間接依賴的完整授權清單。

## 原始教學實作與研究參考

local_ddos_lab 的來源說明將起始程式描述為原創教學實作，並非 Envoy、FastAPI 或其他專案的官方範例。原始匯入摘要保留在 docs/starter-provenance.json，代表性合成 smoke-test 結果保留在 local_ddos_lab/examples/smoke_tests。

Netflix concurrency-limits、APISIX 與 Aperture 等研究參考見 docs/開源底座與創新驗證.md；參考概念不代表本產品包含其實作或受到其背書。
