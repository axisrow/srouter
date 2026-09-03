"""ТДД-тесты vscode_proxy: scoped SOCKS5 для codex-расширения openai.chatgpt через VSCode http.proxy.

Контекст (issue #185): VSCode-расширение openai.chatgpt запускает свой codex-binary (мимо wrapper),
наследует HTTP_PROXY=privoxy из ~/.claude/settings.json → privoxy рвёт long-lived WS (#96/#120).
Глобальный SOCKS5 в gui-домене (com.srouter.codenv) ломает Claude Code (#130 — CC не поддерживает SOCKS5).
Scoped-решение: VSCode-настройка `http.proxy=socks5h://127.0.0.1:10808`. Расширение (verify из extension.js)
читает http.proxy и строит HTTP_PROXY/HTTPS_PROXY В ENV ПОРОЖДАЕМОГО codex-процессА ({...process.env,...n}),
а не системно → CC (отдельный процесс, свой ~/.claude/settings.json) не затрагивается.

Канон: claude_proxy.py (read-modify-write JSON, atomic tmp+replace, fail-soft, provenance через
значение-совпадение — чужой http.proxy не трогаем, fail-closed #112).
"""
import json

import vscode_proxy
from dashboard_common import SOCKS_PROXY_URL


EXPECTED_PROXY = "socks5h://127.0.0.1:10808"


def _setup(monkeypatch, tmp_path, *, paths=None):
    """Перенаправить vscode_proxy.SETTINGS_PATHS на tmp-файлы (не трогаем реальные settings.json)."""
    if paths is None:
        paths = [tmp_path / "Code" / "settings.json", tmp_path / "Cursor" / "settings.json"]
    monkeypatch.setattr(vscode_proxy, "SETTINGS_PATHS", tuple(paths))
    return paths


def test_status_off_when_no_file(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)  # файлов нет
    s = vscode_proxy.status()
    assert s["enabled"] is False
    assert s["proxy"] == ""


def test_enable_writes_proxy_and_status_on(monkeypatch, tmp_path):
    paths = _setup(monkeypatch, tmp_path)
    # Предсоздать settings.json Code (как реальный редактор)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text("{}", encoding="utf-8")

    r = vscode_proxy.enable()

    assert r["ok"] is True
    data = json.loads(paths[0].read_text())
    assert data["http.proxy"] == EXPECTED_PROXY
    s = vscode_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == EXPECTED_PROXY


def test_default_proxy_is_socks5_from_single_source():
    """Контракт фиксируется из dashboard_common (issue #155 — единый источник порта 10808)."""
    assert SOCKS_PROXY_URL == EXPECTED_PROXY
    assert vscode_proxy.PROXY == EXPECTED_PROXY


def test_enable_preserves_other_keys(monkeypatch, tmp_path):
    """read-modify-write: чужие настройки редактора (claudeCode.preferredLocation и пр.) не теряем."""
    paths = _setup(monkeypatch, tmp_path)
    original = {"claudeCode.preferredLocation": "panel", "git.autofetch": True}
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps(original), encoding="utf-8")

    vscode_proxy.enable()

    data = json.loads(paths[0].read_text())
    assert data["http.proxy"] == EXPECTED_PROXY
    assert data["claudeCode.preferredLocation"] == "panel"
    assert data["git.autofetch"] is True


def test_enable_idempotent(monkeypatch, tmp_path):
    """Двойной enable = одно значение, без дублей/мусора."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text("{}", encoding="utf-8")

    vscode_proxy.enable()
    vscode_proxy.enable()

    data = json.loads(paths[0].read_text())
    assert data["http.proxy"] == EXPECTED_PROXY
    assert list(data.keys()) == ["http.proxy"]


def test_disable_removes_managed(monkeypatch, tmp_path):
    """disable убирает srouter-managed http.proxy."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": EXPECTED_PROXY, "other": 1}), encoding="utf-8")

    r = vscode_proxy.disable()

    assert r["ok"] is True
    data = json.loads(paths[0].read_text())
    assert "http.proxy" not in data
    assert data["other"] == 1  # чужое сохранено


def test_disable_does_not_touch_foreign_proxy(monkeypatch, tmp_path):
    """fail-closed provenance (#112): чужой http.proxy (корпоративный/ручной) НЕ трогаем."""
    paths = _setup(monkeypatch, tmp_path)
    foreign = "http://corp-proxy.internal:3128"
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": foreign}), encoding="utf-8")

    r = vscode_proxy.disable()

    assert r["ok"] is True
    data = json.loads(paths[0].read_text())
    assert data["http.proxy"] == foreign  # чужой — на месте


def test_disable_idempotent_when_no_file(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)  # файлов нет
    r = vscode_proxy.disable()
    assert r["ok"] is True


def test_disable_idempotent_when_already_clean(monkeypatch, tmp_path):
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"other": 1}), encoding="utf-8")

    r = vscode_proxy.disable()

    assert r["ok"] is True
    assert json.loads(paths[0].read_text()) == {"other": 1}


def test_enable_does_not_create_missing_editor_settings(monkeypatch, tmp_path):
    """Несуществующий settings.json НЕ создаём — VSCode сам создаст при первом запуске (не плодим мусор).

    status для отсутствующего редактора = enabled=False (корректно «редактор не установлен»).
    """
    paths = _setup(monkeypatch, tmp_path)  # ни одного файла нет

    r = vscode_proxy.enable()

    assert r["ok"] is True
    assert not paths[0].exists()
    assert not paths[1].exists()
    s = vscode_proxy.status()
    assert s["enabled"] is False


def test_enable_covers_both_editors(monkeypatch, tmp_path):
    """Code и Cursor — оба редактора получают http.proxy (пользователь может пользоваться любым)."""
    paths = _setup(monkeypatch, tmp_path)
    for p in paths:
        p.parent.mkdir(parents=True)
        p.write_text("{}", encoding="utf-8")

    r = vscode_proxy.enable()

    assert r["ok"] is True
    for p in paths:
        assert json.loads(p.read_text())["http.proxy"] == EXPECTED_PROXY


def test_enable_rejects_non_socks_scheme_without_mutating(monkeypatch, tmp_path):
    """Регрессия #127-класс: даже ошибочная смена константы не должна записать HTTP в scoped-proxy.

    codex через privoxy (HTTP 8118) рвёт WS (#120) — http.proxy обязан быть SOCKS5.
    """
    paths = _setup(monkeypatch, tmp_path)
    original = {"other": 1}
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(vscode_proxy, "PROXY", "http://127.0.0.1:8118")

    r = vscode_proxy.enable()

    assert r["ok"] is False
    assert "socks" in r["err"].lower() or "scheme" in r["err"].lower()
    assert json.loads(paths[0].read_text()) == original  # не мутирован


# ==================== issue #307: foreign/mixed state + force-gate + provenance ====================

def test_status_reports_foreign_state(monkeypatch, tmp_path):
    """ДЫРА #307 (ложный configured=false): чужое http.proxy — отдельное состояние foreign,
    а не неотличимо от «не настроено»."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": "http://corp-proxy:3128"}), encoding="utf-8")
    s = vscode_proxy.status()
    assert s["state"] == "foreign"
    assert s["enabled"] is False


def test_status_reports_managed_on_and_absent(monkeypatch, tmp_path):
    paths = _setup(monkeypatch, tmp_path)
    assert vscode_proxy.status()["state"] == "absent"
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text("{}", encoding="utf-8")
    vscode_proxy.enable()
    assert vscode_proxy.status()["state"] == "managed-on"


def test_status_reports_mixed_when_editors_disagree(monkeypatch, tmp_path):
    """mixed: в Code — наше значение, в Cursor — чужое. Один клик «Включить» сейчас
    молча затирает чужое — обязан отказывать как конфликт."""
    paths = _setup(monkeypatch, tmp_path)
    for p, val in ((paths[0], EXPECTED_PROXY), (paths[1], "http://corp-proxy:3128")):
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({"http.proxy": val}), encoding="utf-8")
    s = vscode_proxy.status()
    assert s["state"] == "mixed"


def test_enable_on_foreign_fails_closed_without_mutation(monkeypatch, tmp_path):
    """ДЫРА #307 (перезапись чужого): enable() на чужое значение обязан отказать ЯВНО."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    original = {"http.proxy": "http://corp-proxy:3128", "editor.fontSize": 14}
    paths[0].write_text(json.dumps(original), encoding="utf-8")

    r = vscode_proxy.enable()

    assert r["ok"] is False
    assert r["conflict"] is True
    assert r["state"] == "foreign"
    assert json.loads(paths[0].read_text()) == original, "чужое значение не тронуто"


def test_enable_on_mixed_fails_closed_without_mutation(monkeypatch, tmp_path):
    paths = _setup(monkeypatch, tmp_path)
    for p, val in ((paths[0], EXPECTED_PROXY), (paths[1], "http://corp-proxy:3128")):
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({"http.proxy": val}), encoding="utf-8")

    r = vscode_proxy.enable()

    assert r["ok"] is False
    assert r["conflict"] is True
    assert r["state"] == "mixed"
    assert json.loads(paths[1].read_text())["http.proxy"] == "http://corp-proxy:3128"


def test_enable_force_overwrites_and_backs_up_foreign_value(monkeypatch, tmp_path):
    """force — осознанная перезапись: чужое значение уходит в sidecar-backup (#112)."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": "http://corp-proxy:3128"}), encoding="utf-8")

    r = vscode_proxy.enable(force=True)

    assert r["ok"] is True
    assert json.loads(paths[0].read_text())["http.proxy"] == EXPECTED_PROXY
    backup = vscode_proxy._backup_path(paths[0])
    assert backup.exists()
    assert json.loads(backup.read_text())["http.proxy"] == "http://corp-proxy:3128"


def test_disable_after_force_restores_backed_up_foreign_value(monkeypatch, tmp_path):
    """Provenance-цикл: force-enable -> disable() восстанавливает ЧУЖОЕ значение из backup."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": "http://corp-proxy:3128"}), encoding="utf-8")
    assert vscode_proxy.enable(force=True)["ok"] is True

    assert vscode_proxy.disable()["ok"] is True

    data = json.loads(paths[0].read_text())
    assert data["http.proxy"] == "http://corp-proxy:3128"
    assert not vscode_proxy._backup_path(paths[0]).exists(), "backup потреблён, не висит сиротой"


# ============ issue #307 round 2 (Codex cycle-review PR #328): находки 2-4 ============

def test_disable_backup_survives_failed_save(monkeypatch, tmp_path):
    """Codex finding 2: backup удаляется ТОЛЬКО после подтверждённой записи settings.json."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text(json.dumps({"http.proxy": "http://corp-proxy:3128"}), encoding="utf-8")
    assert vscode_proxy.enable(force=True)["ok"] is True

    real_save = vscode_proxy._save

    def _failing_save(path, data):
        return {"ok": False, "err": "simulated disk full"}

    monkeypatch.setattr(vscode_proxy, "_save", _failing_save)
    r = vscode_proxy.disable()
    monkeypatch.setattr(vscode_proxy, "_save", real_save)

    assert r["ok"] is False
    backup = vscode_proxy._backup_path(paths[0])
    assert backup.exists(), "backup НЕ удалён при упавшей записи"
    # После "починки" disable доводит restore до конца.
    assert vscode_proxy.disable()["ok"] is True
    assert json.loads(paths[0].read_text())["http.proxy"] == "http://corp-proxy:3128"
    assert not backup.exists()


def test_status_reports_unknown_on_unreadable_settings(monkeypatch, tmp_path):
    """Codex finding 3: malformed JSON — НЕ absent. state=unknown; enable отказывает без
    перезаписи файла (раньше битый/не-dict файл заменялся на наш)."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    broken = "{ not valid json"
    paths[0].write_text(broken, encoding="utf-8")

    s = vscode_proxy.status()
    assert s["state"] == "unknown", s
    assert s["paths"][str(paths[0])]["state"] == "unknown"

    r = vscode_proxy.enable(force=True)
    assert r["ok"] is False
    assert paths[0].read_text(encoding="utf-8") == broken, "битый файл не перезаписан"


def test_enable_refuses_non_dict_json(monkeypatch, tmp_path):
    """Валидный JSON не-object — чужой документ: не заменяем на наш dict (finding 3)."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text('["some", "list"]', encoding="utf-8")
    r = vscode_proxy.enable(force=True)
    assert r["ok"] is False
    assert json.loads(paths[0].read_text(encoding="utf-8")) == ["some", "list"]


def test_enable_rechecks_disk_state_before_save(monkeypatch, tmp_path):
    """Codex finding 4 (TOCTOU): foreign между gate-чтением и записью -> отказ, не тихая
    перезапись без force и backup."""
    paths = _setup(monkeypatch, tmp_path)
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text("{}", encoding="utf-8")

    real_read = vscode_proxy._read_settings
    calls = {"n": 0}

    def _racing_read(path):
        calls["n"] += 1
        if calls["n"] > 1:
            # Чужое появилось в гонке ПОСЛЕ gate-чтения (kind='ok' — легитимный файл).
            return {"http.proxy": "http://corp-proxy:3128"}, "ok"
        return real_read(path)

    monkeypatch.setattr(vscode_proxy, "_read_settings", _racing_read)
    r = vscode_proxy.enable()
    monkeypatch.setattr(vscode_proxy, "_read_settings", real_read)

    assert r["ok"] is False, "устаревшее решение -> отказ"
    # _load замокан, запись не состоялась: файл остался в исходном виде.
    assert json.loads(paths[0].read_text(encoding="utf-8")) == {}, "запись не должна была состояться"
