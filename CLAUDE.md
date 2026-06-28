# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file async MTProto proxy for Telegram, written in Python with no framework. Effectively all logic lives in `mtprotoproxy.py` (~2400 lines); `config.py` is user configuration; `pyaes/` is a vendored pure-Python AES fallback. There is no test suite, linter, or build step.

## Running

```bash
python3 mtprotoproxy.py                 # uses config.py from CWD
python3 mtprotoproxy.py myconfig.py     # custom config file
python3 mtprotoproxy.py PORT SECRET[,SECRET2] [AD_TAG] [TLS_DOMAIN]  # undocumented CLI form, see init_config()
docker-compose up -d                    # production: host networking, mounts config.py + mtprotoproxy.py
docker-compose logs                     # prints shareable tg:// / https://t.me proxy links on startup
```

There are no dependencies to install for a basic run — the proxy degrades to the bundled `pyaes` if no native crypto is present, but that is *much* slower and prints a warning. For real use install one of: `cryptography` (preferred), `pycryptodome`/`pycrypto`. `uvloop` is auto-detected for extra speed. `pysocks` is needed only for the upstream SOCKS5 feature.

To launch multiple instances for multi-core scaling, run the script several times — they balance clients via `SO_REUSEPORT`.

## Configuration model

`init_config()` is the single source of truth for every tunable. It loads `config.py` (or a CLI-specified file) via `runpy`, keeps only UPPERCASE keys, and fills defaults with `setdefault`. **To add or change a setting, edit `init_config()`** — there is no schema file. The merged config becomes a global `config` object accessed by attribute (`config.PORT`, `config.MODES`, etc.).

Several defaults are *derived*, which is easy to miss:
- `USE_MIDDLE_PROXY` defaults to true iff a 16-byte `AD_TAG` is set (middle proxy is required to show channel ads).
- `PREFER_IPV6` is disabled automatically when middle proxy is on (IPv6 middle proxies are unstable).
- Setting `SOCKS5_HOST`/`SOCKS5_PORT` forces `USE_MIDDLE_PROXY` off (incompatible).
- `MODES` (`classic`/`secure`/`tls`) gates which client handshake types are accepted; legacy `SECURE_ONLY`/`TLS_ONLY` are translated into `MODES` with a deprecation warning.

## Connection pipeline (the core architecture)

Every client connection flows through `handle_client_wrapper` → `handle_client` → `handle_handshake`, then data is pumped bidirectionally.

1. **Handshake detection** (`handle_handshake`): peeks the first bytes. `\x16\x03\x01` ⇒ fake-TLS path (`handle_fake_tls_handshake`), otherwise raw MTProto. Optional PROXY-protocol v1/v2 parsing happens first if `PROXY_PROTOCOL` is set (for nginx/haproxy front-ends).
2. **User/secret matching**: the 64-byte handshake is AES-CTR-decrypted once per configured user until the proto tag (`abridged`/`intermediate`/`secure`) matches an enabled mode. The matched user, DC index, and crypto state are returned. Unmatched or replayed handshakes go to `handle_bad_client`, which transparently proxies the connection to `MASK_HOST` so the proxy looks like a normal TLS site to scanners. Replay protection: recently-seen handshake prekeys are tracked in `used_handshakes` (bounded by `REPLAY_CHECK_LEN`).
3. **Upstream connect**: either `do_direct_handshake` (direct to a Telegram DC, see `TG_DATACENTERS_V4/V6`) or `do_middleproxy_handshake` (via Telegram's middle proxies, required for ads — see `middleproxy_handshake` and `TG_MIDDLE_PROXIES_V4/V6`, which are refreshed at runtime by `update_middle_proxy_info`).
4. **Bidirectional pump**: two `tg_connect_reader_to_writer` tasks race with `FIRST_COMPLETED`; whichever side closes first tears down the other. Per-user limits (`USER_MAX_TCP_CONNS`, `USER_EXPIRATIONS`, `USER_DATA_QUOTA`) are enforced here before pumping begins.

### Layered stream wrappers

Encryption and framing are composed as a stack of decorators over the raw asyncio reader/writer, all subclassing `LayeredStreamReaderBase` / `LayeredStreamWriterBase`. Each layer only knows about its `upstream`. Typical client-side stack (outer→inner): `FakeTLS` → `CryptoWrapped` (AES-CTR) → MTProto frame codec (`Compact`/`Intermediate`/`SecureIntermediate`). When adding a transport/framing variant, add a reader+writer pair following this pattern rather than threading flags through the pump.

### FAST_MODE

When connecting directly (no middle proxy) with `FAST_MODE` on (default), tg→client traffic is **not re-encrypted**: the code swaps in `FakeEncryptor`/`FakeDecryptor` no-op shims so bytes pass through, trading a small amount of security for throughput. Be careful editing `handle_client` around this — the framing wrappers are only applied in the middle-proxy path.

## Crypto module selection

At import time the module picks an AES backend in order: `cryptography` → `pycrypto`/`pycryptodome` → vendored `pyaes`. Each path defines `create_aes_ctr` / `create_aes_cbc` with a uniform `.encrypt()/.decrypt()` interface. If you touch crypto, keep all three backends' adapters in sync.

## Background tasks & observability

`create_utilitary_tasks` starts long-running coroutines: `stats_printer` (periodic stats to stderr), `update_middle_proxy_info` + `get_srv_time` (only when middle proxy is enabled), `get_mask_host_cert_len`, and `clear_ip_resolving_cache`. Stats live in the global `stats` / `user_stats` counters updated via `update_stats` / `update_user_stats`. If `METRICS_PORT` is set, `handle_metrics` serves a Prometheus exposition endpoint (whitelist via `METRICS_WHITELIST`, prefix via `METRICS_PREFIX`).

## Conventions

- Pure standard-library style: globals for shared state, attribute-access config, `print_err` for stderr logging. No logging framework.
- New tunables: add to `init_config()` with a `setdefault` and a one-line comment explaining it — that comment is the de facto documentation.
- The `mtprotoproxy.py` (and `config.py`) files are bind-mounted into the container, so editing them and restarting the container picks up changes without rebuilding the image.
