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
