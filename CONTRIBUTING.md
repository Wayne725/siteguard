# 貢獻指南

請先閱讀 README 與對應功能文件。一般缺陷請附版本、Python／Docker 版本、去識別設定及最小重現步驟；安全漏洞依 SECURITY.md 私下回報。

## 開發與測試

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests/siteguard -p 'test_*.py'
.venv/bin/python -m unittest discover -s tests -p 'test_cli.py'
.venv/bin/python -m unittest discover -s deploy -p 'test_*.py'
.venv/bin/python -m unittest discover -s rls -p 'test_*.py'
.venv/bin/python -m unittest discover -s scripts -p 'test_*.py'
```

原生 Docker／Envoy 驗收與本機 fixture 方法見 [整合測試說明](tests/integration/README.md)。一般自動化測試通過不能代替實際閘道接入驗收。

## 修改原則

- Python 變數使用 snake_case，僅在邏輯不直觀時加註解。
- 行為修正附可重現案例及必要回歸測試，保留 observe／enforce 的區別。
- 不提交 runtime、token、憑證、真實網站流量、私人資料、虛擬環境或建置輸出。
- 文件中的效能與收益數據必須附測試條件，不能將有限樣本解讀為普遍保證。
- 提交 Pull Request 時描述使用者可見的改變、驗證方式及仍未驗證的範圍。

貢獻原創內容時，以本專案 MIT License 提供；第三方程式須保留原授權與出處，不要求移轉著作權。
