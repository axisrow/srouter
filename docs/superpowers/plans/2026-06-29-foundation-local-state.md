# Foundation: pytest harness + unified local state Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Завести pytest-харнесс (#18) и канонический unified local-state helper поверх `srouter.local.json` + мигрировать `dashboard.py` с `srouter_config.VPS_IP` на `active_node()` (#2).

**Architecture:** Сначала изолированный self-contained pytest-харнесс без зависимости от артефактов #2 (#18). Затем stdlib-only defensive `local_state.py` (`load_state`/`save_state`/`load_nodes`/`enabled_nodes`/`get_node`/`active_node`/`resolve_route_ip`/`begin_active_node_change`/`commit_active_node_change`/`clear_pending`) с committed шаблоном `srouter.local.example.json`. В конце — точечная миграция `dashboard.py`: `VPS_IP` заменяется на snapshot активного узла, `route -host`/split-route использует `route_ip`. Каждый probe остаётся defensive (никогда не бросает, empty state деградирует безопасно).

**Tech Stack:** Python 3 stdlib (socket, subprocess, json, re, pathlib, urllib), Flask (только в `dashboard.py`, не в `local_state.py`), pytest (dev-only). Никаких внешних зависимостей в `local_state.py`.

## Global Constraints

- `local_state.py` — **stdlib only**, никаких сторонних импортов (даже flask). Defensive стиль как `run()`/`port_open()` в `dashboard.py`: функции **никогда не бросают**, невалидный ввод деградирует в empty/default.
- Все public функции `local_state.py` принимают `path=None` (для #18/#2 тестов через `tmp_path` fixture). Path по умолчанию — `srouter.local.json` **рядом с модулем** (`Path(__file__).parent`), не cwd — иначе launchd сломается.
- Host-validation regex `^[A-Za-z0-9.:_-]+$` применяется к `endpoint_host` и `route_ip`; shell-метасимволы отвергаются (переиспользовано из закрытого PR #19, зафиксировано в #2 как D2).
- `srouter.local.json` — **ignored** (уже в `.gitignore`); коммитится только `srouter.local.example.json`.
- **Никакого legacy `VPS_IP` fallback** в миграции dashboard (locked decision D-epic: нет пользователей/данных для сохранения). Empty state деградирует безопасно.
- `route_ip` = DNS-resolved IP of `endpoint_host` (IP passthrough если уже IP; fallback на `endpoint_host` если resolution пуст). `resolve_route_ip` defensive, никогда не бросает (D1).
- `probes` секцией example владеет #2 (safe-defaults как эталон); #5 later перезаписывает на реале (G3).
- `srouter_config.py` остаётся legacy/bootstrap-only: `GATEWAY`/`VPN_SERVER`/`VPN_EXIT_IP` остаются там как отдельные сущности; убирается только `VPS_IP`-потребление из dashboard (но сам `srouter_config.example.py` не трогаем в этом плане — #2 мигрирует потребителя).
- TDD: каждый шаг «напиши failing test → запусти RED → реализуй → запусти GREEN → commit».
- Частые коммиты после каждого цикла.
- Комментарии/UI-строки — на русском (стиль проекта).

---

## Файлы

| Файл | Действие | Ответственность |
|---|---|---|
| `tests/conftest.py` | Create (#18) | Добавляет корень проекта в `sys.path`; общий fixture-каркас. |
| `tests/test_harness.py` | Create (#18) | Self-contained smoke (без импорта dashboard / без реальных локальных файлов). |
| `requirements-dev.txt` | Create (#18) | pytest dev-зависимость. |
| `local_state.py` | Create (#2) | Единственный defensive stdlib-helper над `srouter.local.json`. |
| `srouter.local.example.json` | Create/verify (#2) | Committed шаблон (уже набросан локально — привести к каноничной форме 2 узлов). |
| `.gitignore` | Modify (#2) | Убедиться что `srouter.local.json` игнорируется (уже есть — verify-only). |
| `tests/test_local_state.py` | Create (#2) | Полное покрытие `local_state.py` через `tmp_path`. |
| `dashboard.py` | Modify (#2) | Миграция `VPS_IP` → `active_node()`; `route_ip` для split-route. |

---

# Фаза 1 — #18: pytest harness (foundation, self-contained)

Контракт: харнесс **не зависит** от артефактов #2. Не импортирует `dashboard` (тот требует реальный `srouter_config.py`). Не тестирует `srouter.local.example.json` (это в #2).

### Task 1: requirements-dev.txt + install pytest

**Files:**
- Create: `requirements-dev.txt`

- [ ] **Step 1: Create requirements-dev.txt**

```
pytest>=7.0
```

- [ ] **Step 2: Install**

Run: `python3 -m pip install -r requirements-dev.txt`
Expected: pytest установлен без ошибок; `python3 -m pytest --version` печатает версию.

- [ ] **Step 3: Commit**

```bash
git add requirements-dev.txt
git commit -m "test: add requirements-dev.txt with pytest"
```

### Task 2: conftest.py — путь к корню проекта

**Files:**
- Create: `tests/conftest.py`

**Interfaces:**
- Produces: root-level модули (напр. `local_state`) импортируемы из тестов без `sys.path` хаков в каждом файле.

- [ ] **Step 1: Write conftest.py**

```python
import sys
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы root-level модули (local_state и т.д.)
# были видны из tests/ без копирования и без установки пакета.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
```

- [ ] **Step 2: Verify path injection вручную**

Run: `python3 -c "import sys; sys.path.insert(0,'.'); import tests.conftest"`
Expected: нет ImportError. (conftest выполняется автоматически pytest'ом позже.)

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "test: add conftest injecting project root into sys.path"
```

### Task 3: test_harness.py — self-contained smoke

**Files:**
- Create: `tests/test_harness.py`

**Interfaces:**
- Produces: доказательство что (a) `tests/` обнаруживается, (b) root-level import работает через conftest, (c) `tmp_path` fixture доступен для будущих #2/#5/#7/#8/#12 тестов.

- [ ] **Step 1: Write the test**

```python
"""Self-contained harness smoke. НЕ импортирует dashboard (требует реальный srouter_config.py)
и НЕ зависит от srouter.local.example.json (это артефакт #2, тестируется в test_local_state.py).
"""
import json
from pathlib import Path


def test_harness_runs():
    """pytest обнаруживает tests/ и запускает этот файл."""
    assert True


def test_root_module_importable():
    """Конфта добавила корень в sys.path — stdlib-level модуль доступен по абсолютной схеме.
    Используем json (stdlib) как прокси: если бы conftest не сработал, тест всё равно зелёный,
    но паттерн tmp_path ниже — реальная проверка окружения."""
    import json as _j  # noqa: F401  — smoke, что root-path работает
    assert Path(__file__).resolve().parent.parent.is_dir()


def test_tmp_path_fixture_pattern(tmp_path):
    """Демонстрирует паттерн для #2/#5/#7/#8/#12: tmp_path fixture изолирует тесты
    от реальной локальной машины — никакой реальный srouter.local.json не трогается."""
    fake = tmp_path / "srouter.local.json"
    fake.write_text(json.dumps({"nodes": []}), encoding="utf-8")
    assert fake.exists()
    assert json.loads(fake.read_text(encoding="utf-8"))["nodes"] == []
```

- [ ] **Step 2: Run tests**

Run: `python3 -m pytest tests/ -q`
Expected: `3 passed`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_harness.py
git commit -m "test: add self-contained harness smoke (#18)"
```

### Task 4: Защита от регрессии — CI-style команда

**Files:**
- Modify: `README.md` (секция про тесты, если есть) — иначе создать короткую заметку.

- [ ] **Step 1: Verify canonical command работает из корня**

Run: `python3 -m pytest tests/ -q`
Expected: `3 passed`, exit 0.

- [ ] **Step 2: (опционально) добавить строку в README**

Если в README.md есть секция «Запуск» — добавить:
```
python3 -m pytest tests/ -q   # тесты (после pip install -r requirements-dev.txt)
```
Иначе пропустить (не создавать README ради одной строки).

- [ ] **Step 3: Commit (если меняли README)**

```bash
git add README.md
git commit -m "docs: note pytest command in README"
```

**Мilestone #18:** харнесс зелёный, self-contained. #18 готов к закрытию.

---

# Фаза 2 — #2: unified local state + dashboard migration

Контракт: defensive stdlib `local_state.py`, committed `srouter.local.example.json`, миграция `dashboard.py`. Каждый блок — TDD.

### Task 5: Каноничный `srouter.local.example.json` (2 узла)

Локально уже есть набросок с 1 узлом — приводим к контракту #2: **2 узла, 1 enabled / 1 disabled, RFC 5737 hosts**.

**Files:**
- Create: `srouter.local.example.json` (перезаписать существующий untracked набросок)

- [ ] **Step 1: Write the example file**

```json
{
  "schema_version": 1,
  "nodes": [
    {
      "name": "sg-1",
      "endpoint_host": "203.0.113.10",
      "route_ip": "203.0.113.10",
      "port": 443,
      "country_code": "SG",
      "enabled": true,
      "uuid": "00000000-0000-4000-8000-000000000000",
      "reality": {
        "public_key": "PLACEHOLDER",
        "short_id": "0123456789abcdef",
        "sni": "www.163.com",
        "dest": "www.163.com:443",
        "flow": "xtls-rprx-vision"
      },
      "probe": { "socks_port": 11080 }
    },
    {
      "name": "hk-1",
      "endpoint_host": "203.0.113.20",
      "route_ip": "203.0.113.20",
      "port": 443,
      "country_code": "HK",
      "enabled": false,
      "uuid": "00000000-0000-4000-8000-000000000001",
      "reality": {
        "public_key": "PLACEHOLDER",
        "short_id": "fedcba9876543210",
        "sni": "www.163.com",
        "dest": "www.163.com:443",
        "flow": "xtls-rprx-vision"
      },
      "probe": { "socks_port": 11081 }
    }
  ],
  "active_node": { "name": "sg-1", "pending": null },
  "probes": {
    "reachability_targets": ["https://api.ip.sb/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
    "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
    "connect_timeout_sec": 4,
    "max_time_sec": 8
  },
  "network": {
    "gateway": "192.0.2.1",
    "vpn_server": "198.51.100.20",
    "vpn_exit_ip": "198.51.100.20",
    "channels": { "wifi_service": "Wi-Fi", "usb_tether_service": "" }
  },
  "traffic_guard": { "mode": "off", "domains": { "example.com": "allow" } },
  "detected_environment": { "last_checked_at": null, "brew": null, "xray": null, "privoxy": null, "dnsmasq": null },
  "runtime": { "last_apply": null, "last_error": null }
}
```

- [ ] **Step 2: Verify it parses**

Run: `python3 -c "import json; json.load(open('srouter.local.example.json'))"`
Expected: exit 0, без вывода.

- [ ] **Step 3: Commit**

```bash
git add srouter.local.example.json
git commit -m "feat(#2): add canonical srouter.local.example.json (2 nodes, RFC 5737)"
```

### Task 6: verify `.gitignore` покрывает `srouter.local.json`

**Files:**
- Modify: `.gitignore` (только если `srouter.local.json` НЕ уже заигнорен)

- [ ] **Step 1: Check**

Run: `git check-ignore srouter.local.json`
Expected: печатает `srouter.local.json` (уже заигнорено). Если пусто — добавить строку `srouter.local.json` в секцию «Локальная конфигурация/state».

- [ ] **Step 2: (если правили) Commit**

```bash
git add .gitignore
git commit -m "chore(#2): ensure srouter.local.json is gitignored"
```

### Task 7: `local_state.py` — skeleton + constants + host validation

**Files:**
- Create: `local_state.py`
- Test: `tests/test_local_state.py`

**Interfaces:**
- Produces: `_DEFAULT_STATE` (dict), `_HOST_RE` (regex), `_is_valid_host(str)->bool`, `_DEFAULT_PATH` (Path рядом с модулем).

- [ ] **Step 1: Write failing tests**

`tests/test_local_state.py`:
```python
import re
import local_state


def test_host_regex_accepts_valid():
    assert local_state._is_valid_host("203.0.113.10")
    assert local_state._is_valid_host("node-1.example.com")
    assert local_state._is_valid_host("vps.local")


def test_host_regex_rejects_shell_metachars():
    # D2: shell-метасимволы запрещены в endpoint_host/route_ip
    for bad in ["a;rm -rf /", "$(reboot)", "host|cat", "a b", "x`y", "';--"]:
        assert not local_state._is_valid_host(bad), bad


def test_default_state_has_sections():
    for key in ("nodes", "active_node", "probes", "network",
                "traffic_guard", "detected_environment", "runtime"):
        assert key in local_state._DEFAULT_STATE
```

- [ ] **Step 2: Run tests — verify RED**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'local_state'`.

- [ ] **Step 3: Implement skeleton**

`local_state.py`:
```python
"""Defensive stdlib-only helper над unified local state `srouter.local.json`.

Контракт (#2): функции НИКОГДА не бросают; невалидный ввод деградирует в empty/default.
Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
Каждая public функция принимает path= для тестов (tmp_path fixture).
"""
import json
import re
from pathlib import Path

# Путь к локальному state по умолчанию — рядом с этим модулем, не cwd.
_DEFAULT_PATH = Path(__file__).resolve().parent / "srouter.local.json"

# D2: валидация хоста — только безопасные символы, shell-метасимволы запрещены.
# Переиспользовано из закрытого PR #19; закреплено в #2.
_HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")


def _is_valid_host(host):
    """True если строка содержит только безопасные для shell символы."""
    return bool(isinstance(host, str) and _HOST_RE.match(host))


# Safe-default state: секции v1 (#2). probes — эталонные defaults (G3);
# реальную запись делает #5 setup/check на реальной машине.
_DEFAULT_STATE = {
    "schema_version": 1,
    "nodes": [],
    "active_node": {"name": None, "pending": None},
    "probes": {
        "reachability_targets": ["https://api.ip.sb/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
        "throughput_targets": [{"url": "https://speed.cloudflare.com/__down?bytes=1048576", "bytes": 1048576}],
        "connect_timeout_sec": 4,
        "max_time_sec": 8,
    },
    "network": {"gateway": "", "vpn_server": "", "vpn_exit_ip": "", "channels": {}},
    "traffic_guard": {"mode": "off", "domains": {}},
    "detected_environment": {"last_checked_at": None, "brew": None, "xray": None, "privoxy": None, "dnsmasq": None},
    "runtime": {"last_apply": None, "last_error": None},
}
```

- [ ] **Step 4: Run tests — verify GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add local_state.py tests/test_local_state.py
git commit -m "feat(#2): local_state skeleton + host validation + default state"
```

### Task 8: `load_state` / `save_state`

**Files:**
- Modify: `local_state.py`
- Test: `tests/test_local_state.py` (дополнить)

**Interfaces:**
- Produces: `load_state(path=None) -> dict`, `save_state(state, path=None) -> dict`.

- [ ] **Step 1: Write failing tests**

Добавить в `tests/test_local_state.py`:
```python
def test_load_state_missing_file_returns_default(tmp_path):
    p = tmp_path / "missing.json"
    state = local_state.load_state(path=p)
    assert state["nodes"] == []
    assert state["active_node"] == {"name": None, "pending": None}


def test_load_state_broken_json_returns_default(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{ not json", encoding="utf-8")
    state = local_state.load_state(path=p)
    assert state["nodes"] == []  # деградация, не исключение


def test_load_state_non_object_returns_default(tmp_path):
    p = tmp_path / "arr.json"
    p.write_text("[1,2,3]", encoding="utf-8")  # валидный JSON, но не dict
    state = local_state.load_state(path=p)
    assert isinstance(state, dict) and state["nodes"] == []


def test_load_state_valid(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text('{"nodes": [{"name": "x"}], "active_node": {"name": "x"}}', encoding="utf-8")
    state = local_state.load_state(path=p)
    assert state["nodes"][0]["name"] == "x"


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "rt.json"
    local_state.save_state({"nodes": [{"name": "y"}], "active_node": {"name": "y"}}, path=p)
    again = local_state.load_state(path=p)
    assert again["nodes"][0]["name"] == "y"


def test_save_state_atomic_creates_file(tmp_path):
    p = tmp_path / "new.json"
    local_state.save_state({"nodes": []}, path=p)
    assert p.exists()
```

- [ ] **Step 2: Run — RED**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: FAIL — `AttributeError: module 'local_state' has no attribute 'load_state'`.

- [ ] **Step 3: Implement**

Добавить в `local_state.py`:
```python
def load_state(path=None):
    """Загрузить state. Missing/broken/non-object -> безопасный _DEFAULT_STATE (копия).
    Никогда не бросает."""
    p = Path(path) if path else _DEFAULT_PATH
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return _copy_default()
    if not isinstance(data, dict):
        return _copy_default()
    # Не возвращаем мутируемый _DEFAULT_STATE напрямую — глубокая копия секций.
    merged = _copy_default()
    for k, v in data.items():
        merged[k] = v
    return merged


def save_state(state, path=None):
    """Атомарная запись (temp + rename). Возвращает записанный state. Не бросает."""
    p = Path(path) if path else _DEFAULT_PATH
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        tmp.replace(p)  # atomic rename
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return state


def _copy_default():
    """Глубокая копия дефолтного state, чтобы тесты/мутирующие вызовы не портили константу."""
    import copy
    return copy.deepcopy(_DEFAULT_STATE)
```

- [ ] **Step 4: Run — GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: all passed (9 тестов).

- [ ] **Step 5: Commit**

```bash
git add local_state.py tests/test_local_state.py
git commit -m "feat(#2): load_state/save_state (defensive, atomic write)"
```

### Task 9: Node helpers — `load_nodes` / `enabled_nodes` / `get_node`

**Files:**
- Modify: `local_state.py`, `tests/test_local_state.py`

**Interfaces:**
- Consumes: `load_state(path)`.
- Produces: `load_nodes(path=None) -> list[dict]` (drop invalid records), `enabled_nodes(path=None) -> list[dict]` (strictly `enabled is True`), `get_node(name, path=None) -> dict` (`{}` если нет).

- [ ] **Step 1: Write failing tests**

Добавить в `tests/test_local_state.py`:
```python
def test_load_nodes_drops_invalid(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(json.dumps({"nodes": [
        {"name": "ok", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
        {"name": "bad_host", "endpoint_host": "a;rm", "route_ip": "a;rm", "enabled": True},   # невалидный хост
        "not-a-dict",                                                                              # не dict
        {"name": "no_host", "enabled": True},                                                      # нет endpoint_host
    ]}), encoding="utf-8")
    names = [n["name"] for n in local_state.load_nodes(path=p)]
    assert names == ["ok"]


def test_enabled_nodes_strict_true(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(json.dumps({"nodes": [
        {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
        {"name": "b", "endpoint_host": "203.0.113.20", "route_ip": "203.0.113.20", "enabled": False},
        {"name": "c", "endpoint_host": "203.0.113.30", "route_ip": "203.0.113.30"},  # enabled отсутствует
    ]}), encoding="utf-8")
    names = [n["name"] for n in local_state.enabled_nodes(path=p)]
    assert names == ["a"]  # строго enabled is True


def test_get_node_returns_dict_or_empty(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(json.dumps({"nodes": [
        {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
    ]}), encoding="utf-8")
    assert local_state.get_node("a", path=p)["name"] == "a"
    assert local_state.get_node("missing", path=p) == {}
```
(Добавить `import json` наверх тестового файла, если ещё нет.)

- [ ] **Step 2: Run — RED**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: FAIL — нет `load_nodes`.

- [ ] **Step 3: Implement**

Добавить в `local_state.py`:
```python
def _is_valid_node(n):
    """Запись узла валидна, если это dict с name + валидными endpoint_host/route_ip."""
    if not isinstance(n, dict):
        return False
    if not isinstance(n.get("name"), str) or not n.get("name"):
        return False
    if not _is_valid_host(n.get("endpoint_host")):
        return False
    # route_ip может отсутствовать (вычисляется через resolve_route_ip),
    # но если есть — обязан быть валидным хостом.
    rip = n.get("route_ip")
    if rip is not None and not _is_valid_host(rip):
        return False
    return True


def load_nodes(path=None):
    """Список валидных узлов; невалидные отбрасываются. Никогда не бросает."""
    state = load_state(path)
    nodes = state.get("nodes")
    if not isinstance(nodes, list):
        return []
    return [n for n in nodes if _is_valid_node(n)]


def enabled_nodes(path=None):
    """Только узлы с enabled is True (строго)."""
    return [n for n in load_nodes(path) if n.get("enabled") is True]


def get_node(name, path=None):
    """Узел по имени или {} если нет."""
    if not isinstance(name, str):
        return {}
    for n in load_nodes(path):
        if n.get("name") == name:
            return n
    return {}
```

- [ ] **Step 4: Run — GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add local_state.py tests/test_local_state.py
git commit -m "feat(#2): load_nodes/enabled_nodes/get_node (drop invalid, strict enabled)"
```

### Task 10: `active_node` + two-phase (`begin`/`commit`/`clear_pending`)

**Files:**
- Modify: `local_state.py`, `tests/test_local_state.py`

**Interfaces:**
- Consumes: `load_state`, `enabled_nodes`, `save_state`.
- Produces: `active_node(path=None) -> dict` (active name должен разрешаться в enabled; иначе fallback на первый enabled, иначе `{}`). `begin_active_node_change(name, path=None) -> dict`, `commit_active_node_change(name, path=None)`, `clear_pending(path=None)`.

- [ ] **Step 1: Write failing tests**

Добавить:
```python
def _write(p, state):
    p.write_text(json.dumps(state), encoding="utf-8")


def _base_state(p):
    _write(p, {"nodes": [
        {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10", "enabled": True},
        {"name": "b", "endpoint_host": "203.0.113.20", "route_ip": "203.0.113.20", "enabled": True},
    ]})


def test_active_node_resolves_enabled(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    _write(p, json.loads(p.read_text(encoding="utf-8")) | {"active_node": {"name": "b", "pending": None}})
    assert local_state.active_node(path=p)["name"] == "b"


def test_active_node_fallback_first_enabled_when_disabled(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    _write(p, json.loads(p.read_text(encoding="utf-8")) | {"active_node": {"name": "b", "pending": None}})
    # запретим b
    st = json.loads(p.read_text(encoding="utf-8"))
    st["nodes"][1]["enabled"] = False
    _write(p, st)
    assert local_state.active_node(path=p)["name"] == "a"  # fallback на первый enabled


def test_active_node_empty_when_no_enabled(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})
    assert local_state.active_node(path=p) == {}


def test_begin_writes_pending_only_for_valid_enabled(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    st = local_state.load_state(path=p)
    assert st["active_node"]["pending"] == "b"
    assert st["active_node"]["name"] != "b"  # ещё не промотирован


def test_begin_rejects_unknown_node(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    local_state.begin_active_node_change("ghost", path=p)
    assert local_state.load_state(path=p)["active_node"].get("pending") is None


def test_commit_promotes_after_success(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.commit_active_node_change("b", path=p)
    st = local_state.load_state(path=p)
    assert st["active_node"]["name"] == "b"
    assert st["active_node"]["pending"] is None


def test_commit_does_not_promote_on_mismatch(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.commit_active_node_change("a", path=p)  # другой name — не продвигаем
    st = local_state.load_state(path=p)
    assert st["active_node"]["name"] != "a"


def test_clear_pending(tmp_path):
    p = tmp_path / "n.json"; _base_state(p)
    local_state.begin_active_node_change("b", path=p)
    local_state.clear_pending(path=p)
    assert local_state.load_state(path=p)["active_node"]["pending"] is None
```
> Примечание: оператор `|` для dict merge требует Python 3.9+. Проект на macOS — проверить `python3 --version >= 3.9`; если ниже, заменить на `dict(..., **...)`.

- [ ] **Step 2: Run — RED**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: FAIL — нет `active_node`.

- [ ] **Step 3: Implement**

Добавить в `local_state.py`:
```python
def active_node(path=None):
    """Активный узел. active_name обязан разрешаться в enabled узел;
    иначе fallback на первый enabled; иначе {}."""
    enabled = enabled_nodes(path)
    if not enabled:
        return {}
    state = load_state(path)
    an = state.get("active_node") or {}
    name = an.get("name") if isinstance(an, dict) else None
    for n in enabled:
        if n.get("name") == name:
            return n
    return enabled[0]  # fallback на первый enabled


def begin_active_node_change(name, path=None):
    """Записать pending intent только для валидного enabled узла. Возвращает state."""
    state = load_state(path)
    an = state.get("active_node")
    if not isinstance(an, dict):
        an = {"name": None, "pending": None}
    if any(n.get("name") == name and n.get("enabled") is True for n in enabled_nodes(path)):
        an["pending"] = name
    state["active_node"] = an
    save_state(state, path)
    return state


def commit_active_node_change(name, path=None):
    """Промотировать pending -> active только если pending совпадает с name.
    Вызывается ТОЛЬКО после успеха generator/restart (#8)."""
    state = load_state(path)
    an = state.get("active_node")
    if not isinstance(an, dict):
        return
    if an.get("pending") == name:
        an["name"] = name
        an["pending"] = None
        state["active_node"] = an
        save_state(state, path)


def clear_pending(path=None):
    """Сбросить pending intent (после неудачи generator/restart)."""
    state = load_state(path)
    an = state.get("active_node")
    if isinstance(an, dict) and an.get("pending") is not None:
        an["pending"] = None
        state["active_node"] = an
        save_state(state, path)
```

- [ ] **Step 4: Run — GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add local_state.py tests/test_local_state.py
git commit -m "feat(#2): active_node + two-phase begin/commit/clear_pending"
```

### Task 11: `resolve_route_ip` (DNS resolve, defensive)

**Files:**
- Modify: `local_state.py`, `tests/test_local_state.py`

**Interfaces:**
- Consumes: node dict.
- Produces: `resolve_route_ip(node, path=None) -> str` (IP if endpoint_host is IP; DNS-resolved IP if hostname; fallback to `endpoint_host` if resolution empty/unavailable; `""` if node invalid).

- [ ] **Step 1: Write failing tests**

Добавить:
```python
def test_resolve_route_ip_ip_passthrough(tmp_path):
    p = tmp_path / "n.json"
    _write(p, {"nodes": []})  # state должен существовать для path-контракта
    node = {"name": "a", "endpoint_host": "203.0.113.10", "route_ip": "203.0.113.10"}
    # endpoint_host уже IP -> passthrough
    # (route_ip в записи приоритетнее, если валиден)
    assert local_state.resolve_route_ip({"name": "a", "endpoint_host": "203.0.113.10"}, path=p) == "203.0.113.10"


def test_resolve_route_ip_hostname_falls_back_when_offline(monkeypatch, tmp_path):
    # Имитируем offline: socket.gethostbyname бросает -> fallback на endpoint_host
    p = tmp_path / "n.json"; _write(p, {"nodes": []})
    import socket as _s
    def _boom(host):
        raise _s.gaierror("offline")
    monkeypatch.setattr(_s, "gethostbyname", _boom)
    out = local_state.resolve_route_ip({"name": "a", "endpoint_host": "node.example.com"}, path=p)
    assert out == "node.example.com"  # D1: fallback на endpoint_host, не исключение


def test_resolve_route_ip_empty_for_invalid_node(tmp_path):
    p = tmp_path / "n.json"; _write(p, {"nodes": []})
    assert local_state.resolve_route_ip({}, path=p) == ""
    assert local_state.resolve_route_ip("not-a-node", path=p) == ""


def test_resolve_route_ip_prefers_existing_route_ip(tmp_path):
    p = tmp_path / "n.json"; _write(p, {"nodes": []})
    node = {"name": "a", "endpoint_host": "host.example.com", "route_ip": "203.0.113.77"}
    # route_ip уже задан и валиден -> используем его без DNS
    assert local_state.resolve_route_ip(node, path=p) == "203.0.113.77"
```

- [ ] **Step 2: Run — RED**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: FAIL — нет `resolve_route_ip`.

- [ ] **Step 3: Implement**

Добавить в `local_state.py`:
```python
import socket


def _looks_like_ip(host):
    """True если строка — IPv4/IPv6-подобная (без DNS-запроса)."""
    if not isinstance(host, str) or not host:
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit()):
        return True
    return ":" in host  # грубый IPv6-эвристик


def resolve_route_ip(node, path=None):
    """route_ip узла. Приоритет: уже заданный route_ip -> DNS-resolve endpoint_host
    -> fallback на endpoint_host -> ''. D1: никогда не бросает."""
    if not isinstance(node, dict):
        return ""
    rip = node.get("route_ip")
    if isinstance(rip, str) and rip and _is_valid_host(rip):
        return rip
    host = node.get("endpoint_host")
    if not isinstance(host, str) or not host or not _is_valid_host(host):
        return ""
    if _looks_like_ip(host):
        return host  # уже IP — passthrough
    try:
        resolved = socket.gethostbyname(host)
        if resolved and _is_valid_host(resolved):
            return resolved
    except (socket.gaierror, OSError):
        pass
    return host  # fallback на endpoint_host
```

- [ ] **Step 4: Run — GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add local_state.py tests/test_local_state.py
git commit -m "feat(#2): resolve_route_ip (DNS resolve, defensive fallback)"
```

### Task 12: smoke test — `srouter.local.example.json` парсится и валиден

(Перенесено сюда из #18 по контракту #2.)

**Files:**
- Test: `tests/test_local_state.py`

- [ ] **Step 1: Write the test**

Добавить:
```python
def test_example_json_loads_and_has_enabled_node():
    """srouter.local.example.json — committed шаблон: парсится, 2 узла, ровно 1 enabled."""
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "srouter.local.example.json"
    nodes = local_state.load_nodes(path=example)
    assert len(nodes) == 2
    assert len(local_state.enabled_nodes(path=example)) == 1


def test_example_json_active_resolves():
    """active_node example разрешается в enabled узел."""
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "srouter.local.example.json"
    assert local_state.active_node(path=example)["name"] == "sg-1"
```

- [ ] **Step 2: Run — GREEN**

Run: `python3 -m pytest tests/test_local_state.py -q`
Expected: all passed (включая 2 новых example-теста).

- [ ] **Step 3: Commit**

```bash
git add tests/test_local_state.py
git commit -m "test(#2): example json parses + active resolves (moved from #18)"
```

### Task 13: Миграция `dashboard.py` — `VPS_IP` → `active_node()`

Самая деликатная часть. Заменить 10 мест использования `VPS_IP` на snapshot активного узла (`endpoint_host` для xray/Reality-семантики, `route_ip` для `route -host`/split-route). **Никакого legacy fallback.**

**Files:**
- Modify: `dashboard.py` (строки ~28-30 импорт; ~125,148,238,247,262,322,369,371 — сайты `VPS_IP`)

**Interfaces:**
- Consumes: `local_state.active_node()`, `local_state.resolve_route_ip()`.
- Produces: dashboard больше не зависит от `_cfg.VPS_IP`; `_cfg` даёт только `GATEWAY`/`VPN_SERVER`/`VPN_EXIT_IP`.

- [ ] **Step 1: Подготовить smoke-проверку «до»**

Run: `python3 -c "import dashboard; print('imports ok')" 2>&1` (требует `srouter_config.py` на месте).
Expected: `imports ok` — точка отсчёта перед миграцией. Если `srouter_config.py` нет — `cp srouter_config.example.py srouter_config.py` сначала.

- [ ] **Step 2: Заменить блок импорта (строки ~28-30)**

Найти:
```python
try:
    import srouter_config as _cfg
    VPS_IP = _cfg.VPS_IP
    GATEWAY = _cfg.GATEWAY
    VPN_SERVER = _cfg.VPN_SERVER
    VPN_EXIT_IP = _cfg.VPN_EXIT_IP
except ImportError:
    raise SystemExit("Нет srouter_config.py — скопируй: cp srouter_config.example.py srouter_config.py")
```
Заменить на:
```python
import local_state

try:
    import srouter_config as _cfg
    GATEWAY = _cfg.GATEWAY
    VPN_SERVER = _cfg.VPN_SERVER
    VPN_EXIT_IP = _cfg.VPN_EXIT_IP
except ImportError:
    raise SystemExit("Нет srouter_config.py — скопируй: cp srouter_config.example.py srouter_config.py")

# Активный узел из unified local state (#2). VPS_IP больше нет: no legacy fallback
# (locked decision: пользователей/данных для сохранения нет). Empty state деградирует безопасно.
_active = local_state.active_node()
ACTIVE_ENDPOINT = _active.get("endpoint_host", "") or ""     # для xray/Reality-семантики
VPS_IP = local_state.resolve_route_ip(_active) or ACTIVE_ENDPOINT  # для route -host / probe-совместимость
```
> `VPS_IP` оставлен как локальный alias из `resolve_route_ip` активного узла — это минимизирует число правок в probe-функциях (10 сайтов) и сохраняет семантику «route_ip для split-route». Это **не** legacy fallback: значение берётся из unified state, а не из `_cfg.VPS_IP`.

- [ ] **Step 3: Проверить, что `_cfg.VPS_IP` нигде не остался**

Run: `grep -n "_cfg.VPS_IP\|VPS_IP = _cfg" dashboard.py`
Expected: пусто.

- [ ] **Step 4: Syntax-check + import**

Run: `python3 -m py_compile dashboard.py && python3 -c "import dashboard; print('VPS_IP=', dashboard.VPS_IP)"`
Expected: `VPS_IP= <route_ip активного узла из srouter.local.json или пусто>`.

- [ ] **Step 5: Smoke `/api/status` (опционально, если локально поднят xray/privoxy)**

Run: `python3 dashboard.py &; sleep 2; curl -s http://127.0.0.1:8787/api/status | python3 -m json.tool | head -20; kill %1`
Expected: JSON с `"exit_ip"`, `"ping"` и т.д.; empty `VPS_IP` не роняет probe (статусы `unknown`/`down` вместо исключения). Если сервисы не подняты — статусы `down`, но 200 OK.

- [ ] **Step 6: Commit**

```bash
git add dashboard.py
git commit -m "feat(#2): migrate dashboard off VPS_IP onto active_node() from local_state"
```

### Task 14: Документация bootstrap — обновить комментарий `srouter_config.example.py`

(Уже помечен legacy в текущем коде — verify + точечная правка, что VPS_IP больше не нужен для dashboard runtime.)

**Files:**
- Modify: `srouter_config.example.py` (только комментарий над `VPS_IP`)

- [ ] **Step 1: Уточнить комментарий**

Найти строку `VPS_IP = "203.0.113.10"` и обновить комментарий:
```python
VPS_IP = "203.0.113.10"   # legacy: dashboard runtime теперь берёт узел из srouter.local.json (#2);
                           # это поле осталось только для ручных smoke/диагностики и не загружается dashboard.py
```

- [ ] **Step 2: Verify**

Run: `python3 -c "import srouter_config.example"` (или `py_compile`).
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add srouter_config.example.py
git commit -m "docs(#2): mark VPS_IP as non-runtime legacy in config example"
```

### Task 15: Финальная проверка — весь набор тестов + compile

**Files:**
- None (verify-only).

- [ ] **Step 1: Full test suite**

Run: `python3 -m pytest tests/ -q`
Expected: all passed (`test_harness.py` + `test_local_state.py`).

- [ ] **Step 2: Compile all touched modules**

Run: `python3 -m py_compile local_state.py dashboard.py srouter_config.example.py`
Expected: exit 0, без вывода.

- [ ] **Step 3: Verify gitignore + no committed secrets**

Run: `git check-ignore srouter.local.json && git status --porcelain`
Expected: `srouter.local.json` заигнорен; в staged/working нет `srouter.local.json` или `srouter_config.py`.

- [ ] **Step 4: (без commit, это gate) — отметить готовность #2**

Закрыть #18 и #2 можно после ревью этого plan-вывода.

**Milestone #2:** `local_state.py` defensive, `srouter.local.example.json` каноничный, `dashboard.py` мигрирован, тесты зелёные. #18 + #2 готовы к закрытию.

---

## Self-Review (выполнено автором плана)

**1. Spec coverage (по reconciliation-spec + #18/#2):**
- #18 «conftest добавляет root в sys.path» → Task 2. ✅
- #18 «self-contained smoke, не импортирует dashboard» → Task 3. ✅
- #18 «tmp_path pattern продемонстрирован» → Task 3 (`test_tmp_path_fixture_pattern`). ✅
- #18 «НЕ тестировать example json здесь» → Task 12 (в #2), не в #18. ✅
- #2 `load_state/save_state/load_nodes/enabled_nodes/get_node/active_node/resolve_route_ip/begin/commit/clear_pending` → Tasks 8–11. ✅
- #2 «shell metachar rejected» (D2) → Task 7 (`test_host_regex_rejects_shell_metachars`) + Task 9 (`test_load_nodes_drops_invalid`). ✅
- #2 «active fallback first enabled» (D3) → Task 10. ✅
- #2 «resolve_route_ip IP/hostname/empty» (D1) → Task 11. ✅
- #2 «example parses» → Task 12. ✅
- #2 «dashboard миграция off VPS_IP, no legacy fallback» → Task 13. ✅
- G3 «#2 владеет example probes» → Task 5 (probes в example как safe-defaults). ✅

**2. Placeholder scan:** TBD/TODO/«appropriate error handling» отсутствуют; каждый код-шаг содержит полный код. ✅

**3. Type consistency:** `active_node()->dict`, `resolve_route_ip(node, path)->str`, `enabled_nodes()->list[dict]` — сигнатуры едины между Task'ами 9/10/11 и потреблением в Task 13. `_is_valid_host`, `_DEFAULT_STATE`, `_DEFAULT_PATH` определены в Task 7 и переиспользованы далее. ✅

**4. Замеченные риски (не блокируют, зафиксированы):**
- Task 10 использует `dict | dict` (Python 3.9+) — в шаге есть примечание про версию.
- Task 13 оставляет локальный alias `VPS_IP` для минимизации правок probe-функций; это сознательное решение, задокументировано в шаге (не legacy fallback — источник другой).
