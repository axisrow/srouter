"""ТДД-тесты claude_proxy: round-trip enable/disable/status на tmp-файле (не реальный settings.json).

Проверяет контракт: enable/disable не теряют другие env-ключи, идемпотентны, fail-soft.
"""
import contextlib
import fcntl
import json
import os

import pytest

import claude_proxy
from dashboard_common import HTTP_PROXY_URL


EXPECTED_CLAUDE_PROXY = "http://127.0.0.1:8118"


def _setup(monkeypatch, tmp_path):
    """Перенаправить claude_proxy.SETTINGS на tmp-файл (не трогаем реальный ~/.claude/settings.json)."""
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(claude_proxy, "SETTINGS", settings)
    return settings


def test_status_off_when_no_file(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)  # файла нет
    s = claude_proxy.status()
    assert s["enabled"] is False
    assert s["proxy"] == ""


def test_enable_creates_env_and_status_on(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    r = claude_proxy.enable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY
    assert data["env"]["HTTP_PROXY"] == EXPECTED_CLAUDE_PROXY
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == EXPECTED_CLAUDE_PROXY


def test_default_proxy_is_supported_http_bridge():
    """Regression #127: контракт фиксируется независимо от изменяемой `_PROXY`."""
    assert HTTP_PROXY_URL == EXPECTED_CLAUDE_PROXY
    assert claude_proxy._PROXY == EXPECTED_CLAUDE_PROXY


def test_enable_rejects_socks_without_mutating_settings(monkeypatch, tmp_path):
    """Даже будущая ошибочная смена константы не должна записать SOCKS в чужой settings.json."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"EXISTING_KEY": "keep-me"}, "model": "opus"}
    settings.write_text(json.dumps(original))
    monkeypatch.setattr(claude_proxy, "_PROXY", "socks5h://127.0.0.1:10808")

    result = claude_proxy.enable()

    assert result["ok"] is False
    assert "unsupported proxy scheme" in result["err"]
    assert json.loads(settings.read_text()) == original
    assert claude_proxy.status()["enabled"] is False


def test_enable_overwrites_stale_socks5_from_previous_experiments(monkeypatch, tmp_path):
    """Regression issue #130: settings.json с мусором от экспериментов (SOCKS5 fiasco #127) —
    HTTPS_PROXY=socks5h://... — install-путь (force=True) ДОЛЖЕН уметь перезаписать на HTTP.

    Issue #307: без force такой ключ теперь ЧУЖОЕ значение (state=foreign, enable отказывает);
    перезапись — осознанный force с backup. Модуль не отличает «наш старый мусор» от
    корпоративной настройки — решение принимает вызывающий (CLI install зовёт с force).
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "HTTPS_PROXY": "socks5h://127.0.0.1:10808",
        "HTTP_PROXY": "socks5h://127.0.0.1:10808",
        "KEEP": "yes",
    }}))

    r = claude_proxy.enable(force=True)

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY, "SOCKS5-мусор перезаписан на HTTP"
    assert data["env"]["KEEP"] == "yes"
    # Provenance #307: чужое значение забэкаплено, не потеряно.
    backup = json.loads(claude_proxy._backup_path().read_text())
    assert backup["env"]["HTTPS_PROXY"] == "socks5h://127.0.0.1:10808"
    assert data["env"]["HTTP_PROXY"] == EXPECTED_CLAUDE_PROXY, "SOCKS5-мусор перезаписан на HTTP"
    assert data["env"]["KEEP"] == "yes"
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["proxy"] == EXPECTED_CLAUDE_PROXY


def test_enable_preserves_existing_env(monkeypatch, tmp_path):
    """enable НЕ должен терять другие env-ключи (TRAVELPAYOUTS_TOKEN, IS_DEMO и т.д.)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"EXISTING_KEY": "keep-me"}, "model": "opus"}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    assert data["env"]["EXISTING_KEY"] == "keep-me"  # существующий ключ сохранён
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY  # proxy добавлен
    assert data["model"] == "opus"  # другие секции не тронуты


def test_disable_removes_proxy_keys(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://127.0.0.1:8118",
                                            "HTTP_PROXY": "http://127.0.0.1:8118",
                                            "KEEP": "yes"}}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert "HTTPS_PROXY" not in data["env"]
    assert "HTTP_PROXY" not in data["env"]
    assert data["env"]["KEEP"] == "yes"  # другие ключи не задеты


def test_disable_idempotent(monkeypatch, tmp_path):
    """Повторный disable (ключей уже нет) → ok, не ломает."""
    _setup(monkeypatch, tmp_path)
    r1 = claude_proxy.disable()
    r2 = claude_proxy.disable()
    assert r1["ok"] is True
    assert r2["ok"] is True  # идемпотентно


def test_round_trip_enable_disable_status(monkeypatch, tmp_path):
    """Полный цикл: off → enable → on → disable → off."""
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.status()["enabled"] is False
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.status()["enabled"] is True
    assert claude_proxy.disable()["ok"] is True
    assert claude_proxy.status()["enabled"] is False


def test_enable_handles_broken_json(monkeypatch, tmp_path):
    """settings.json битый → enable НЕ падает и НЕ затирает файл (issue #307 round 2,
    Codex finding 3: раньше битый JSON схлопывался в {} и перезаписывался целиком —
    молчаливая потеря всего чужого settings.json)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text("{ not valid json")
    r = claude_proxy.enable()
    assert r["ok"] is False  # честный отказ, не «создаём свежий env» поверх чужого файла
    assert claude_proxy.status()["state"] == "unknown"


# ============================ NO_PROXY для z.ai (glm идёт напрямую, мимо privoxy) ============================
def test_enable_adds_zai_no_proxy_from_anthropic_base_url(monkeypatch, tmp_path):
    """enable ставит NO_PROXY с хостом из ANTHROPIC_BASE_URL — чтобы glm/z.ai шёл напрямую.

    Без этого z.ai (через privoxy → xray → VPS) = лишний хоп. NO_PROXY = только хост (без suffix —
    parent-доменная эвристика ломалась на country-TLD вроде .co.uk).
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" in no_proxy, "NO_PROXY содержит хост из ANTHROPIC_BASE_URL"
    assert data["env"].get("no_proxy", "") == no_proxy, "оба регистра NO_PROXY/no_proxy синхронны"


def test_enable_preserves_existing_no_proxy(monkeypatch, tmp_path):
    """enable НЕ затирает чужой NO_PROXY — merge ( corp.local сохраняется, z.ai добавляется)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "corp.local,10.0.0.1",
    }}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"]["NO_PROXY"]
    assert "corp.local" in no_proxy, "чужой NO_PROXY-хост сохранён (merge, не затёр)"
    assert "10.0.0.1" in no_proxy, "чужой NO_PROXY-IP сохранён"
    assert "api.z.ai" in no_proxy, "z.ai-хост добавлен"


def test_enable_skips_no_proxy_when_no_base_url(monkeypatch, tmp_path):
    """Без ANTHROPIC_BASE_URL (CC на дефолтном api.anthropic.com) → NO_PROXY не ставим (gate)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"EXISTING": "keep"}}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    assert "NO_PROXY" not in data["env"], "без ANTHROPIC_BASE_URL NO_PROXY не добавляется"
    assert data["env"]["EXISTING"] == "keep"


def test_disable_removes_only_zai_hosts(monkeypatch, tmp_path):
    """disable убирает только z.ai-хосты из NO_PROXY, чужие (corp.local) сохраняет."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": "http://127.0.0.1:8118",
        "NO_PROXY": "corp.local,api.z.ai",
    }}))
    claude_proxy.disable()
    data = json.loads(settings.read_text())
    no_proxy = data["env"].get("NO_PROXY", "")
    assert "api.z.ai" not in no_proxy, "provider-хост убран"
    assert "corp.local" in no_proxy, "чужой хост сохранён"


def test_disable_idempotent_no_proxy(monkeypatch, tmp_path):
    """Повторный disable (NO_PROXY уже без z.ai) → ok, не падает, чужое не трогает."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "corp.local",  # z.ai уже убран
    }}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["NO_PROXY"] == "corp.local", "чужой NO_PROXY не изменён"


def test_status_reports_provider_direct(monkeypatch, tmp_path):
    """status() отдаёт provider_direct=True когда хост ANTHROPIC_BASE_URL в NO_PROXY, False иначе."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": EXPECTED_CLAUDE_PROXY,
        "NO_PROXY": "api.z.ai",
    }}))
    s = claude_proxy.status()
    assert s["enabled"] is True
    assert s["provider_direct"] is True, "хост провайдера в NO_PROXY → provider_direct=True"
    assert "z.ai" in s.get("no_proxy", "")


def test_enable_merges_divergent_no_proxy_variants(monkeypatch, tmp_path):
    """Regression (cycle 2): рассинхронные NO_PROXY/no_proxy — enable сохраняет хосты из ОБОИХ.

    Раньше enable брал `NO_PROXY or no_proxy` (только одну variant) → при NO_PROXY=a.com,
    no_proxy=b.com вторая терялась. Теперь merge обеих → provider-хост добавляется к полному множеству.
    """
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "NO_PROXY": "a.com",
        "no_proxy": "b.com",
    }}))
    claude_proxy.enable()
    data = json.loads(settings.read_text())
    # Оба ключа синхронны и содержат хосты из обеих variant + provider.
    for k in ("NO_PROXY", "no_proxy"):
        np = data["env"][k]
        assert "a.com" in np, f"{k}: a.com (из NO_PROXY) сохранён"
        assert "b.com" in np, f"{k}: b.com (из no_proxy) сохранён"
        assert "api.z.ai" in np, f"{k}: provider-хост добавлен"


# ==================== issue #307: foreign state + force-gate + provenance ====================

def test_status_reports_foreign_state_not_configured_false(monkeypatch, tmp_path):
    """ДЫРА #307 (ложный configured=false): чужое HTTPS_PROXY рапортуется как отдельное
    состояние foreign, а не неотличимо от «не настроено»."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))
    s = claude_proxy.status()
    assert s["state"] == "foreign"
    assert s["enabled"] is False
    assert s["proxy"] == "http://corp-proxy:3128"


def test_status_states_absent_and_managed_on(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.status()["state"] == "absent"
    claude_proxy.enable()
    assert claude_proxy.status()["state"] == "managed-on"


def test_enable_on_foreign_fails_closed_without_mutation(monkeypatch, tmp_path):
    """ДЫРА #307 (перезапись чужого): enable() на чужое значение обязан отказать ЯВНО
    (conflict) и НЕ трогать settings.json (канон privileged-boundary-fail-closed)."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"HTTPS_PROXY": "http://corp-proxy:3128", "KEEP": "x"}}
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(original))

    r = claude_proxy.enable()

    assert r["ok"] is False
    assert r["conflict"] is True
    assert r["state"] == "foreign"
    assert json.loads(settings.read_text()) == original, "чужое значение не тронуто"


def test_enable_force_overwrites_and_backs_up_foreign_value(monkeypatch, tmp_path):
    """force — осознанная перезапись: чужое значение сохраняется в sidecar-backup
    (прецедент #112 provenance), не исчезает безвозвратно."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))

    r = claude_proxy.enable(force=True)

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == EXPECTED_CLAUDE_PROXY
    backup = claude_proxy._backup_path()
    assert backup.exists()
    saved = json.loads(backup.read_text())
    assert saved["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"


def test_enable_without_force_is_idempotent_on_managed_on(monkeypatch, tmp_path):
    """Повторный enable на своём значении — обычный ok, force не нужен."""
    _setup(monkeypatch, tmp_path)
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.enable()["ok"] is True
    assert claude_proxy.enable(force=True)["ok"] is True


def test_disable_on_foreign_value_does_not_delete_it(monkeypatch, tmp_path):
    """ДЫРА #307 (удаление чужого при disable): сегодня disable() безусловно удаляет
    env.HTTPS_PROXY/HTTP_PROXY даже когда там чужое значение."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"HTTPS_PROXY": "http://corp-proxy:3128",
                        "HTTP_PROXY": "http://corp-proxy:3128",
                        "OTHER": "keep"}}
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(original))

    r = claude_proxy.disable()

    assert r["ok"] is True
    assert json.loads(settings.read_text()) == original, "чужой прокси-ключ не должен удаляться"


def test_disable_after_force_restores_backed_up_foreign_value(monkeypatch, tmp_path):
    """Provenance-цикл: force-enable перезаписал чужое -> disable() восстанавливает ЧУЖОЕ
    значение из backup (а не просто удаляет наш ключ)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))
    assert claude_proxy.enable(force=True)["ok"] is True

    assert claude_proxy.disable()["ok"] is True

    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"
    assert not claude_proxy._backup_path().exists(), "backup потреблён, не висит сиротой"


def test_disable_without_backup_removes_managed_key(monkeypatch, tmp_path):
    """Обычный цикл (наше значение с нуля): disable удаляет ключ, как и раньше."""
    settings = _setup(monkeypatch, tmp_path)
    claude_proxy.enable()
    assert claude_proxy.disable()["ok"] is True
    data = json.loads(settings.read_text())
    assert "HTTPS_PROXY" not in data["env"] and "HTTP_PROXY" not in data["env"]


def test_disable_strips_no_proxy_only_when_managed(monkeypatch, tmp_path):
    """NO_PROXY связан с НАШИМ прокси: при чужом HTTPS_PROXY его трогать нельзя."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
        "HTTPS_PROXY": "http://corp-proxy:3128",
        "NO_PROXY": "api.z.ai,other.internal",
    }}))

    claude_proxy.disable()

    env = json.loads(settings.read_text())["env"]
    assert env["NO_PROXY"] == "api.z.ai,other.internal", "чужой NO_PROXY не тронут"


# ============ issue #307 round 2 (Codex cycle-review PR #328): находки 1-3 ============

def test_disable_backup_survives_failed_save(monkeypatch, tmp_path):
    """Codex finding 2: backup удаляется ТОЛЬКО после подтверждённой записи. Если _save()
    падает при restore, единственная копия чужого значения обязана остаться в backup."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}))
    assert claude_proxy.enable(force=True)["ok"] is True

    real_save = claude_proxy._save

    def _failing_save(data):
        return {"ok": False, "err": "simulated disk full"}

    monkeypatch.setattr(claude_proxy, "_save", _failing_save)
    r = claude_proxy.disable()
    monkeypatch.setattr(claude_proxy, "_save", real_save)

    assert r["ok"] is False
    backup = claude_proxy._backup_path()
    assert backup.exists(), "backup НЕ удалён при упавшей записи — единственная копия чужого значения"
    assert json.loads(backup.read_text())["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"
    # После "починки" disable доводит restore до конца.
    assert claude_proxy.disable()["ok"] is True
    assert json.loads(settings.read_text())["env"]["HTTPS_PROXY"] == "http://corp-proxy:3128"
    assert not backup.exists()


def test_status_and_enable_report_unknown_on_unreadable_settings(monkeypatch, tmp_path):
    """Codex finding 3: malformed JSON — НЕ «не настроено» и НЕ повод затирать файл.
    status -> state=unknown, enable/disable -> отказ без мутации (fail-closed)."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    broken = "{ not valid json"
    settings.write_text(broken)

    s = claude_proxy.status()
    assert s["state"] == "unknown", s
    assert s["enabled"] is False

    r = claude_proxy.enable(force=True)
    assert r["ok"] is False
    assert settings.read_text() == broken, "битый файл не перезаписан"

    r = claude_proxy.disable()
    assert r["ok"] is False
    assert settings.read_text() == broken


def test_enable_refuses_non_dict_json(monkeypatch, tmp_path):
    """Валидный JSON не-object (список/строка) — чужой документ: не заменяем на наш dict."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text('["some", "list"]')
    r = claude_proxy.enable(force=True)
    assert r["ok"] is False
    assert json.loads(settings.read_text()) == ["some", "list"], "чужой документ не тронут"


def test_enable_rechecks_disk_state_before_save(monkeypatch, tmp_path):
    """Codex finding 4 (TOCTOU): state может измениться МЕЖДУ gate и записью. enable обязан
    перечитать файл непосредственно перед _save и отказаться, если решение устарело."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("{}")

    real_load = claude_proxy._load
    calls = {"n": 0}

    def _racing_load():
        # 1-е чтение (gate): absent; последующие (pre-save re-check): уже чужое.
        calls["n"] += 1
        data = real_load()
        if calls["n"] > 1:
            return {"env": {"HTTPS_PROXY": "http://corp-proxy:3128"}}
        return data

    monkeypatch.setattr(claude_proxy, "_load", _racing_load)
    r = claude_proxy.enable()
    monkeypatch.setattr(claude_proxy, "_load", real_load)

    assert r["ok"] is False, "устаревшее решение -> отказ, не тихая перезапись"
    # _load замокан, запись не состоялась: файл на диске остался в исходном виде (наш
    # managed-прокси НЕ записан поверх чужого значения из гонки).
    assert json.loads(settings.read_text()) == {}, "запись не должна была состояться"


def test_enable_recheck_distinguishes_absent_from_json_null(monkeypatch, tmp_path):
    """AO review round 3: absent и JSON-null — РАЗНЫЕ состояния. Конкурентная вставка
    HTTPS_PROXY: null после gate не должна сравняться с absent и быть затёрта."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("{}")

    real_load = claude_proxy._load
    calls = {"n": 0}

    def _racing_load():
        calls["n"] += 1
        if calls["n"] > 1:
            # Другой писатель вставил ключ со значением null ПОСЛЕ gate (absent -> present-null).
            return {"env": {"HTTPS_PROXY": None}}
        return real_load()

    monkeypatch.setattr(claude_proxy, "_load", _racing_load)
    r = claude_proxy.enable()
    monkeypatch.setattr(claude_proxy, "_load", real_load)

    assert r["ok"] is False, "absent -> present-null в гонке: решение устарело, отказ"
    assert json.loads(settings.read_text()) == {}, "запись не должна была состояться"


def test_enable_toctou_abort_does_not_leave_stale_backup(monkeypatch, tmp_path):
    """Review #338 follow-up: sidecar-backup пишется только ПОСЛЕ пройденного TOCTOU re-check.
    При отказе на гонке sidecar не появляется: записанный до re-check, он хранит снапшот
    устаревших чужих значений, который следующий disable() восстановил бы поверх более
    свежих, поставленных конкурентным писателем."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp:3128"}}))

    real_load = claude_proxy._load
    calls = {"n": 0}

    def _racing_load():
        calls["n"] += 1
        if calls["n"] > 1:
            # Другой писатель поменял значение ПОСЛЕ gate.
            return {"env": {"HTTPS_PROXY": "http://corp-2:3128"}}
        return real_load()

    monkeypatch.setattr(claude_proxy, "_load", _racing_load)
    r = claude_proxy.enable(force=True)
    monkeypatch.setattr(claude_proxy, "_load", real_load)

    assert r["ok"] is False, "устаревшее решение -> отказ"
    assert not claude_proxy._backup_path().exists(), \
        "при отказе sidecar с устаревшим снапшотом не должен остаться на диске"
    # Конкурентный писатель симулирован только возвратом _load (диск он не писал):
    # инвариант «enable ничего не записал» = файл в исходном виде.
    assert json.loads(settings.read_text())["env"]["HTTPS_PROXY"] == "http://corp:3128"


# --- AO review 5110553545: пост-recheck гонка — валидация+backup+save под одним lock ---
#
# Re-check перед записью сам по себе не атомарен с записью: кооперативный писатель может
# вклиниться между re-check и _save — его значение затирается, а disable() потом
# восстанавливает устаревший sidecar поверх него. enable/disable сериализуются эксклюзивным
# flock на выделенном lockfile (CAS: под lock валидируется decision-snapshot, затем атомарно
# backup+save). Lockfile — не settings.json: _save подменяет inode (tmp+replace), flock на
# settings.json пережил бы rename и разъехался бы с актуальным файлом.

def test_enable_revalidates_under_lock_before_backup_and_save(monkeypatch, tmp_path):
    """AO review 5110553545: писатель, закоммитивший ДО нашего lock, обязан быть виден
    under-lock валидации — иначе его затирает _save, а следующий disable() восстанавливает
    устаревший sidecar поверх его значения."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp:3128"}}))

    @contextlib.contextmanager
    def _racing_lock():
        # Другой srouter-писатель успел закоммитить до нашего lock.
        settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-new:3128"}}))
        yield

    monkeypatch.setattr(claude_proxy, "_settings_lock", _racing_lock)
    r = claude_proxy.enable(force=True)

    assert r["ok"] is False, "писатель до lock -> snapshot устарел -> отказ"
    assert not claude_proxy._backup_path().exists(), "backup не пишется при отказе"
    assert json.loads(settings.read_text())["env"]["HTTPS_PROXY"] == "http://corp-new:3128", \
        "чужое новое значение не затёрто"


def test_disable_reads_and_consumes_backup_under_lock(monkeypatch, tmp_path):
    """AO review 5110553545: disable() — второй read-modify-write коммитер (и потребитель
    sidecar), его чтение/value-match/запись тоже под lock. Писатель, затёрший managed-значение
    своим до нашего lock, не снимается по устаревшему снапшоту, и sidecar при этом не
    потребляется."""
    settings = _setup(monkeypatch, tmp_path)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": claude_proxy._PROXY}}))
    claude_proxy._backup_path().write_text(json.dumps(
        {"env": {"all_proxy": "socks5h://old:1080"}}))

    @contextlib.contextmanager
    def _racing_lock():
        # Другой писатель успел до нашего lock: затёр managed-значение своим.
        settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp-new:3128"}}))
        yield

    monkeypatch.setattr(claude_proxy, "_settings_lock", _racing_lock)
    r = claude_proxy.disable()

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["HTTPS_PROXY"] == "http://corp-new:3128", "чужое новое значение не тронуто"
    assert "all_proxy" not in data["env"], "restore нет: managed-ключей под lock не видно"
    assert claude_proxy._backup_path().exists(), "backup не потребляется без подтверждённого restore"


def test_settings_lock_is_real_exclusive_flock(monkeypatch, tmp_path):
    """Lock — настоящий межпроцессный flock, а не no-op: пока он удерживается, второй
    эксклюзивный захват (LOCK_NB, отдельный fd) обязан блокироваться."""
    _setup(monkeypatch, tmp_path)
    with claude_proxy._settings_lock():
        fd = os.open(claude_proxy._lock_path(), os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


# ============ issue #331: нейтрализация all_proxy/ALL_PROXY (SOCKS-плечо xray) ============
#
# launchctl gui-домен (srouter-codex-env.sh) ставит ALL_PROXY/all_proxy=socks5h://...:10808
# во ВСЕ GUI-процессы; в сессиях Claude Code это протекает в pip/requests → select_proxy
# маппит 'all' на все схемы → SOCKSProxyManager → TypeError PoolKey key_proxy_ssl_context.
# Для CC единственное плечо = privoxy 8118 → enable() нейтрализует all_proxy пустой строкой
# (канон #199 «снять env-прокси ОБА регистра» — нейтрализация там, где задумана, не прокси).

def test_enable_neutralizes_all_proxy(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    r = claude_proxy.enable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["ALL_PROXY"] == ""
    assert data["env"]["all_proxy"] == ""


def test_disable_removes_empty_neutral_keys(monkeypatch, tmp_path):
    """disable() снимает нейтрализацию (наши пустые значения), как и managed proxy-ключи."""
    settings = _setup(monkeypatch, tmp_path)
    claude_proxy.enable()
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert "ALL_PROXY" not in data["env"]
    assert "all_proxy" not in data["env"]


def test_enable_conflict_on_foreign_all_proxy(monkeypatch, tmp_path):
    """Чужое НЕпустое all_proxy (ручная SOCKS-настройка) — отказ без мутации (#307 канон),
    перезапись только force."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"all_proxy": "socks5h://10.0.0.1:1080"}}
    settings.write_text(json.dumps(original))
    r = claude_proxy.enable()
    assert r["ok"] is False
    assert r.get("conflict") is True
    assert json.loads(settings.read_text()) == original, "мутации быть не должно"


def test_enable_conflict_aggregates_proxy_and_neutral_causes(monkeypatch, tmp_path):
    """Review #338 (UX): чужие ENV_KEYS и чужой all_proxy одновременно — ОДИН конфликт-ответ
    с обоими поводами, а не два захода (needs_force gate отрабатывает раньше и молчал про
    neutral; пользователь чинил один конфликт, чтобы упереться во второй)."""
    settings = _setup(monkeypatch, tmp_path)
    original = {"env": {"HTTPS_PROXY": "http://corp-proxy:3128",
                        "all_proxy": "socks5h://10.0.0.1:1080"}}
    settings.write_text(json.dumps(original))
    r = claude_proxy.enable()
    assert r["ok"] is False
    assert r["conflict"] is True
    assert r["state"] == "foreign"
    assert "all_proxy" in r["err"], "нейтральный конфликт назван в ТОМ ЖЕ ответе"
    assert json.loads(settings.read_text()) == original, "мутации быть не должно"


def test_enable_force_overwrites_foreign_all_proxy(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"all_proxy": "socks5h://10.0.0.1:1080"}}))
    r = claude_proxy.enable(force=True)
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["all_proxy"] == ""


def test_disable_keeps_foreign_all_proxy(monkeypatch, tmp_path):
    """value-match provenance (#112/#307): чужое непустое all_proxy disable() не трогает."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"all_proxy": "socks5h://10.0.0.1:1080"}}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    assert json.loads(settings.read_text())["env"]["all_proxy"] == "socks5h://10.0.0.1:1080"


def test_disable_after_force_restores_backed_up_foreign_all_proxy(monkeypatch, tmp_path):
    """Codex cycle-review #338 finding 1: force-перезапись чужого all_proxy бэкапит его в
    sidecar — disable() обязан восстановить SYMMETRICНО (как ENV_KEYS), иначе чужая SOCKS-
    настройка теряется, а backup становится сиротой."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"all_proxy": "socks5h://10.0.0.1:1080"}}))
    assert claude_proxy.enable(force=True)["ok"] is True
    assert json.loads(settings.read_text())["env"]["all_proxy"] == ""

    r = claude_proxy.disable()

    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["all_proxy"] == "socks5h://10.0.0.1:1080", "чужое значение восстановлено"
    assert not claude_proxy._backup_path().exists(), "backup потреблён, не сирота"


def test_disable_keeps_preexisting_empty_neutral_without_managed_keys(monkeypatch, tmp_path):
    """Codex cycle-review #338 finding 2 (сужение): disable() удаляет нейтрализацию ТОЛЬКО
    когда srouter управлял этим конфигом (были managed proxy-ключи). Пре-существующие
    пустые all_proxy/ALL_PROXY без наших ключей — чужая настройка, не трогаем: у нас нет
    provenance-маркеров (канон #307 «не оставляем маркеров»), значит единственный честный
    сигнал «нашего» — собственно managed ENV_KEYS, написанные той же рукой enable()'а."""
    settings = _setup(monkeypatch, tmp_path)
    settings.write_text(json.dumps({"env": {"ALL_PROXY": "", "all_proxy": ""}}))
    r = claude_proxy.disable()
    assert r["ok"] is True
    data = json.loads(settings.read_text())
    assert data["env"]["ALL_PROXY"] == ""
    assert data["env"]["all_proxy"] == ""


def test_status_reports_socks_neutralized(monkeypatch, tmp_path):
    settings = _setup(monkeypatch, tmp_path)
    assert claude_proxy.status()["socks_neutralized"] is False
    claude_proxy.enable()
    assert claude_proxy.status()["socks_neutralized"] is True
    claude_proxy.disable()
    assert claude_proxy.status()["socks_neutralized"] is False
