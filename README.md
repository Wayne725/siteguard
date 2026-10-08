# SiteGuard

A self-hosted HTTP resource protection gateway for existing websites. SiteGuard limits excessive requests, isolates expensive routes, and preserves capacity for other traffic. Envoy handles incoming traffic; Python tools manage configuration and deployment, while a private policy service enforces rate budgets and optionally inspects responses from selected APIs.

No application SDK or per-request cloud API call is required.

[繁體中文](README.zh-TW.md)

```text
Client → Existing HTTPS / CDN / reverse proxy → SiteGuard → Your website
                                                  ↓
                                          Private policy service
```

**Version 0.3.0 is available for controlled evaluation:** [download the installation bundle](https://github.com/Wayne725/siteguard/releases/download/v0.3.0/siteguard-0.3.0.zip) or [browse the release](https://github.com/Wayne725/siteguard/releases/tag/v0.3.0). The bundle includes a wheel, configuration examples, operating guides, and SHA-256 checksums. The wheel has been installed and checked in a clean environment.

## Features

- HTTP request rate budgets and route isolation for expensive endpoints.
- Site-wide IPv4 / IPv6 allowlists and denylists, with deny rules taking precedence.
- Trusted-proxy validation and rejection when the configured client identity cannot be established.
- Sensitive-path blocking, administrative-path source restrictions, and security headers.
- Optional response checks for a limited set of private-key and token patterns on explicitly selected small APIs.
- Configuration generation, deployment validation, metrics, logs, and update rollback.

The default `observe` mode does not block requests or inspect response content. Configure and validate `enforce` mode before relying on protection.

Configuration examples: [firewall](examples/siteguard-firewall.yaml), [security](examples/siteguard-security.yaml). Detailed guides are currently in Traditional Chinese: [firewall behavior](docs/網站入口防火牆.md), [security features and limitations](docs/資安防護功能.md).

## Installation

Requirements: Python 3.11 or later, Docker, and Docker Compose. macOS / Colima deployment has been tested. Installation and configuration generation have been checked in Linux containers; complete Linux-host and Windows / WSL2 deployments still require environment-specific validation.

From the repository directory:

```bash
python3 -m venv .siteguard-venv
.siteguard-venv/bin/python -m pip install .
.siteguard-venv/bin/siteguard init --upstream http://host.docker.internal:3000
.siteguard-venv/bin/siteguard check
.siteguard-venv/bin/siteguard up
.siteguard-venv/bin/siteguard status
```

Replace port `3000` with your application's port. When installing the downloaded wheel, replace `pip install .` with:

```bash
.siteguard-venv/bin/python -m pip install ./siteguard_gateway-0.3.0-py3-none-any.whl
```

The first deployment downloads pinned container images and dependencies. SiteGuard does not require a cloud API key or send website traffic or configuration to a hosted SiteGuard service.

The generated `siteguard.yaml` defaults to `observe` mode and binds the gateway to `127.0.0.1:8088`. Verify your website through `http://127.0.0.1:8088` before pointing your existing reverse proxy at that port. Management and policy-service ports are not published externally.

For macOS with Colima, use `host.lima.internal` for a host application. For an existing containerized website, configure `upstream.network` to join its Docker network. A container's `127.0.0.1` refers to that container, not the host.

See the [quick start](docs/套件快速開始.md) and [installation and operations guide](docs/網站安裝與操作.md), both in Traditional Chinese, for HTTPS, streaming routes, limits, and recovery procedures.

## Operations

```bash
.siteguard-venv/bin/siteguard metrics --format prometheus
.siteguard-venv/bin/siteguard logs --service all --tail 100
.siteguard-venv/bin/siteguard up
.siteguard-venv/bin/siteguard rollback
.siteguard-venv/bin/siteguard down
```

Updates build a candidate configuration and run native Envoy validation before deployment. Successful versions retain content hashes and snapshots. Failed updates preserve diagnostics and attempt to restore the previous deployment.

A `ready` result from `status` means the gateway and policy service are ready; it does not verify that the upstream application works. Check the application's actual endpoints after deployment.

## Verification

For the initial public release, **159 local regression tests passed**, and [GitHub CI passed on Python 3.11, 3.12, and 3.13](https://github.com/Wayne725/siteguard/actions/runs/37711713917). A fresh Python 3.12 environment installed the wheel and successfully ran version lookup, initialization, configuration checking, and rendering outside the repository. See the [publication verification record](docs/發布驗證.md) for the scope and exclusions.

Historical validation is retained separately:

| Version | Historical checks |
| --- | --- |
| 0.1.0 | 72 automated regression tests, Python / Node protocol cases, private-network Nginx integration, and update recovery. |
| 0.2.0 | 117 automated tests, 56 native security cases, and 17 existing Python website functionality checks. |
| 0.3.0 | 135 automated tests, 51 native firewall cases, and repeat checks of 36 security and 17 website functionality cases. |

In one controlled local overload comparison, on-time orders increased from 3/24 to 24/24 while more expensive requests were rejected. In a normal-traffic sample, both paths completed 40/40 requests; p95 latency increased from 1.967 ms to 7.067 ms. These are bounded local results, not evidence of effectiveness across most production websites.

The public-release checks did not rerun the historical native Docker / Envoy matrices, overload experiments, or production-site integration.

The [usability validation guide](docs/可用性測試指南.md), in Traditional Chinese, covers false positives, performance costs, and recovery. Developer fixtures and verification tools are documented in [tests/integration](tests/integration/README.md). The original research implementation remains in the repository; see the [lab guide](LAB_README.md).

## Scope and limitations

SiteGuard addresses resource competition at the HTTP layer. It cannot recover bandwidth that is already saturated upstream or replace application authorization, transaction idempotency, or SQL execution deadlines. Multiple replicas do not currently share rate budgets.

Response inspection covers only the documented patterns and explicitly enabled routes; it is not a general detector for all credentials or sensitive data. Evaluate protection with the same workload on both paths and include the cost to legitimate requests.

The repository excludes local runtime data, management tokens, virtual environments, and full execution artifacts. Representative synthetic smoke-test results are included. Some historical artifact references describe locally generated output and are not downloadable public evidence.

## License and contributing

Original project code and documentation are licensed under the [MIT License](LICENSE), permitting commercial use, modification, and redistribution with the copyright and license notice retained. Third-party dependencies keep their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).

Read the [contributing guide](CONTRIBUTING.md) for changes and verification. Report vulnerabilities privately using the process in [SECURITY.md](SECURITY.md). Version history is recorded in [CHANGELOG.md](CHANGELOG.md).
