# Repository Guidelines

## Project Structure & Module Organization

This repository is the v1 monorepo for `srouter`: the local macOS client, Flask dashboard, diagnostics, installer, and server Docker templates/assets for Reality nodes. Real rendered configs, deploy bundles, keys, logs, and local state stay ignored and must not be committed.

- `dashboard.py` is the main app: probe helpers, Flask routes, and embedded dashboard UI.
- `srouter.local.example.json` is the committed local-state template. Copy or generate `srouter.local.json` for real local values.
- `srouter_config.example.py` is legacy/bootstrap-only until the runtime moves fully to `srouter.local.json`; do not expand it as the primary config contract.
- `diag-proxy.sh` checks direct, HTTP bridge, and SOCKS connectivity for key Claude Code hosts.
- `server/` stores committed Docker-first templates and scripts when those issues land; generated artifacts under `server/.generated/`, `server/generated/`, `server/rendered/`, and `server/deploy-bundles/` are ignored.
- `static/` stores vendored Bootstrap and Bootstrap Icons assets.

## Build, Test, and Development Commands

- `cp srouter.local.example.json srouter.local.json` creates the unified local state/config file; fill or generate real node, network, probe, and guard values there.
- `cp srouter_config.example.py srouter_config.py` is a temporary bootstrap path for the current dashboard implementation only.
- `python3 dashboard.py` starts the loopback-only dashboard at `http://127.0.0.1:8787`.
- `./diag-proxy.sh novpn` and `./diag-proxy.sh vpn` run comparable proxy diagnostics for no-VPN and VPN states.
- `python3 -m py_compile dashboard.py srouter_config.example.py` is the quick syntax check.
- Build system / package metadata: `pyproject.toml` (setuptools backend, PEP 621). Install the console entry point with `python3 -m pip install --upgrade pip` (needs pip ≥ 21.3 for PEP 660 editable install), then `pip install -e .` — this exposes the `srouter` command.
- Test runner: `pytest` (declared in `[project.optional-dependencies].dev`). Run the suite with `pytest` from the repo root after `pip install -e '.[dev]'`.
- **gh / git to github.com — direct, never via proxy/VPS** (#199), but `gh` and `git` are **different proxy stacks** with **different commands**: `gh` reads env proxy (`HTTP_PROXY`/`http_proxy`, both cases — Go `httpproxy` fallback) → unset both cases with `env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy gh ...`; `git` over https reads git-config `http.https://github.com.proxy` (scoped, `git_proxy.py`) which `env -u` does **NOT** touch → use `git -c http.https://github.com.proxy= fetch|pull|push`. `gh repo clone` delegates to git → scoped config applies, so a VPS-independent clone needs `git -c ...proxy=` (or `gh api`, or SSH `git@github.com:` — port 22 is open directly). github TCP is directly reachable and `gh`'s Go stack bypasses GFW TLS blocking, so this is VPS-independent. `srouter doctor` shows this as the `gh/git direct` check with both commands. **Central toggle `srouter git-proxy status|enable|disable [--full]`** (2026-09-30): the effective-verdict composer over ALL git-proxy layers (local urlmatch > global urlmatch > global generic http.proxy/https.proxy > env) — prefer it over per-repo `.git/config` overrides, which both `status` and doctor now surface; `disable --full` also removes stray global generic keys (foreign values need `--force`, #307). Caveat (2026-09-29/30): direct `github.com` can be a TCP black hole in GFW windows (cellular/"103" networks) while the tunnel path works — direct is a probabilistic fallback, not a guarantee.

- **Active-node switching on hybrid-adopt machines is manual** (2026-09-30): `POST /api/node/select/<name>` returns `409` (#136/#313 — select regenerates the config and destroys the managed whitelist). Procedure: edit `address`/`port` in the `reality-out` outbound of the live xray config → set `active_node.name` in `srouter.local.json` to the target node (`enabled: true`; keeps the #200 endpoint-sync guard green) → `brew services restart xray` → verify exit IP with `curl -x http://127.0.0.1:8118 https://api.ip.sb/ip` (api.ip.sb is not in the routing list, so it must be checked via 8118). The dashboard recommendation badge (`/api/nodes/ranking` → `node_selector.recommendation`) probes all `enabled` nodes in parallel through per-node probe inbounds (`probe-<name>` on `probe.socks_port`); on adopt machines a new node's probe inbound/outbound/rule must be hand-written into the live config following `gen_xray_config._probe_inbound`/`_vless_outbound`, or the node is invisible to the recommendation. No auto-switching (roadmap policy above).

- **Go module fetches through the `srouter go-proxy` toggle** (2026-09-30): `proxy.golang.org` is GFW-blocked directly (same class as github.com in bad windows) and Go has NO transport-proxy config (`go env -w HTTPS_PROXY` is rejected — proxy env only). Modes: `enable` (default mirror) writes `GOPROXY=https://goproxy.cn,direct` via `go env -w` (VPS-independent, #199 canon); `enable --mode=tunnel` installs a marker-managed `~/bin/go` wrapper exporting `HTTPS_PROXY=socks5://127.0.0.1:10808` (codex-wrappers precedent). `status` shows wrapper/GOPROXY/env layers + the effective verdict; `disable --full` resets managed GOPROXY; foreign values and marker-less wrappers need `--force` (#307 canon). State lives in the GOENV file + the wrapper itself — no separate srouter state.

## Coding Style & Naming Conventions

Use Python 3 with 4-space indentation and standard-library APIs where possible. Keep probe functions named `probe_*`; each probe should return a dict with `status` (`ok`, `warn`, `down`, or `unknown`) and should not raise on ordinary runtime failures.

For subprocesses, use `run(cmd_list, timeout)` with argument lists only. Do not introduce `shell=True`. Keep system binary paths explicit because GUI/launchd environments may lack Homebrew paths.

Comments and UI strings are currently mostly Russian; preserve that style unless changing a fully English section.

Roadmap automation policy is locked: first observe/measure, then expose a manual action, then add automation in a separate follow-up only after manual validation. Do not hide automatic node, route, channel, or Traffic Guard policy changes inside v1 observe/manual tasks.

Local state should be unified in `srouter.local.json` with sections for nodes, active/pending node, probes, network detection, Traffic Guard, detected environment, and runtime results. Do not reintroduce separate `nodes.json`, `active_node.json`, or `traffic_guard.json` as primary contracts.

For apply/restart flows, use two-phase state: write pending intent, generate/apply/restart, then promote to active only after success. On failure, keep the previous active state and report the error/retry path.

## Testing Guidelines

Tests live under `tests/` (pytest-style, `test_*.py`). Run `pytest` from the repo root; `tests/conftest.py` adds the repo root to `sys.path` so root-level modules import without installing the package. Existing coverage spans local-state helpers, probe helpers, route validation, two-phase apply behavior, and the launchd/uninstall flow. Prefer adding tests there for non-trivial changes.

Keep tests and review cycles off the live macOS proxy stack. Do not run host `brew services start|stop|restart privoxy|xray`, `srouter install|uninstall`, or matching `launchctl bootout/kickstart` commands unless the active task explicitly authorizes a live lifecycle change; use the Docker acceptance environment for lifecycle tests. A `Privoxy version` startup banner proves only that a process started, not that Privoxy crashed or launchd KeepAlive restarted it. Preserve `launchctl print` evidence (`runs`, PID, last exit/signal, and plist identity/mtime) before classifying a lifecycle event.

## Commit & Pull Request Guidelines

Recent history uses short, descriptive subjects, including Conventional Commit-style prefixes such as `chore:`. Keep commit subjects concise and imperative when possible, for example `fix: handle ip.sb geo timeout`.

Pull requests should describe the operational impact, list manual checks performed, and call out any changes touching routes, privileged commands, proxy behavior, or config shape. Include screenshots for visible dashboard UI changes.

## Security & Configuration Tips

Never commit `srouter.local.json`, `srouter_config.py`, `.env*`, real diagnostic logs, API keys, IP addresses, local MCP config, generated server deploy bundles, rendered configs, or Reality keys. Update only committed examples/templates with safe placeholders.

## Routing contract — strict whitelist (2026-10-07)

**Only traffic that explicitly asks for the tunnel goes through it; everything else goes direct. No ambient env proxy is seeded into any layer.** Single source of the whitelist: `srouter.local.json` (`routing.active`/`routing.active_ips`).

- xray managed rule (domains+ip → reality-out, catch-all direct) is mutated only via `srouter routing` (transactional `routing_apply`).
- LaunchAgent `com.srouter.codenv` does NOT seed proxy vars (pre-2026-10-07 it seeded privoxy 8118, fail-closed "no direct egress" — deliberately retired): it only periodically `unsetenv`s residual proxy keys in the launchctl gui domain.
- CC sessions carry no global `HTTPS_PROXY` (empty strings in `~/.claude/settings.json` + NO_PROXY loopback/z.ai/yandex).
- Explicit tunnel consumers: git per-host config, `codex-srouter` wrapper (socks5h pointwise), `curl -x socks5h://127.0.0.1:10808`.
- Contract test: `tests/test_codex_env_contract.py` (stub launchctl: zero setenv + all six unsetenv).

## Manual PF isolation of Anthropic

`srouter protect on|off|status` (aliases enable/disable/вкл/выкл) — strict mode: subnets `160.79.104.0/21` + `2607:6bc0::/32` are dropped on direct egress interfaces en*/ppp* (ports 80/443). The lease lives in `runtime.active_isolate` with `phase: "strict"` — the same key the dashboard card reads (single state contour); repeated `on` with a live lease refuses BEFORE any pfctl call (each `enable_strict` grabs a new `pfctl -E` ref).

