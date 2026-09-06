"""PR-3 #339: doctor-грань «бэкап-слоты консистентны» (контракт v2 §6, warn-уровень).

Образец — persists-across-boot #330: info-only чек в health.check_all (не driver —
канал в моменте работает), каждая находка — читаемая пара «нашёл/ожидал». Пять чеков
контракта: сирота-sidecar, stale-pointer, orphaned backup, накопление поколений,
смешение generation/lease слотов у одного target.
"""
import json

import backup_lib
import health_backups

import claude_proxy


def _write_state(tmp_path, detected):
    state_path = tmp_path / "srouter.local.json"
    state_path.write_text(json.dumps({"schema_version": 1,
                                      "detected_environment": detected}), encoding="utf-8")
    return state_path


def _gen(config_path, stamp):
    p = config_path.with_name(config_path.name + backup_lib.BACKUP_INFIX + stamp)
    p.write_text(f"gen {stamp}\n", encoding="utf-8")
    return p


# ============================ чистота молчит ============================
def test_clean_slots_silent_ok(tmp_path):
    """Нет находок → status ok, пустые findings (silent при чистоте — канон doctor-граней)."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    backup = _gen(cfg, "2026-06-29T000000Z")
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg), "backup": str(backup),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "ok"
    assert result["findings"] == []


def test_unreadable_state_is_unknown_not_warn(tmp_path):
    """Битый state → unknown (не угадываем), не warn и не ok."""
    state = tmp_path / "srouter.local.json"
    state.write_text("{broken", encoding="utf-8")

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "unknown"


# ============================ чек 2: stale-pointer ============================
def test_stale_state_pointer_warns(tmp_path):
    """state называет backup, файла на диске нет → warn state_backup_missing
    (P1a #293: оригинал невосстановим — оператор обязан видеть)."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg),
        "backup": str(tmp_path / "config.srouter-backup-2020-01-01T000000Z"),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "warn"
    assert any("state_backup_missing" in f for f in result["findings"])


# ============================ чек 3: orphaned backup ============================
def test_orphaned_generation_warns(tmp_path):
    """Валидное поколение рядом с config, state о нём молчит (нет ни backup, ни
    restored_from_backup) → warn orphaned_backup (crash-окно A4, P1-3 #124)."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    _gen(cfg, "2026-06-29T000000Z")
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "warn"
    assert any("orphaned_backup" in f for f in result["findings"])


def test_restored_entry_does_not_warn_for_retained_backup(tmp_path):
    """После restore бэкап остаётся НАМЕРЕННО (user_data_retained): state знает о нём
    (restored_from_backup) — это НЕ orphan, warn нет (retained ≠ сирота)."""
    cfg = tmp_path / "config"
    cfg.write_text("foreign restored\n", encoding="utf-8")
    backup = _gen(cfg, "2026-06-29T000000Z")
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg),
        "restored_from_backup": str(backup),
        "management": {"mode": "restored", "managed": False}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["findings"] == [], f"retained после restore — не сирота: {result['findings']}"


# ============================ чек 4: накопление ============================
def test_generation_accumulation_warns(tmp_path):
    """>K поколений у одного target → warn: сигнал, что rotation не работала (#339 §6-4)."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    stamps = ["2026-0%d-01T000000Z" % m for m in range(1, 7)]  # 6 поколений
    for s in stamps:
        _gen(cfg, s)
    newest = cfg.with_name(cfg.name + backup_lib.BACKUP_INFIX + stamps[-1])
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg), "backup": str(newest),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "warn"
    assert any("накопление" in f for f in result["findings"])


# ============================ чек 3, частичное молчание (review #351) ============================
def test_partial_silence_relics_beyond_window_warn(tmp_path):
    """Review #351: свежий pointer + реликты СВЕРХ окна ротации (crash между двумя
    install'ами) — раньше это молчало (4 поколения < порога накопления 5). Теперь —
    отдельная формулировка orphaned_backup «не учтены сверх окна»."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    stamps = ["2026-0%d-01T000000Z" % m for m in range(1, 6)]  # 5 поколений
    for s in stamps:
        _gen(cfg, s)
    newest = cfg.with_name(cfg.name + backup_lib.BACKUP_INFIX + stamps[-1])
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg), "backup": str(newest),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["status"] == "warn"
    assert any("сверх окна" in f for f in result["findings"]), result["findings"]


def test_pointer_with_window_sized_relics_stays_silent(tmp_path):
    """Здоровая машина при окне 3 легально держит 2 неучтённых реликта (окно хранит
    новейшие, поинтер — новейший) — частично-молчаливый чек НЕ должен ложно срабатывать
    на каждом штатном install'е (допуск keep-1, review #351)."""
    cfg = tmp_path / "config"
    cfg.write_text("managed\n", encoding="utf-8")
    stamps = ["2026-0%d-01T000000Z" % m for m in range(1, 4)]  # 3 поколения = окно
    for s in stamps:
        _gen(cfg, s)
    newest = cfg.with_name(cfg.name + backup_lib.BACKUP_INFIX + stamps[-1])
    state = _write_state(tmp_path, {"privoxy": {
        "config_path": str(cfg), "backup": str(newest),
        "management": {"mode": "managed", "managed": True}}})

    result = health_backups.check_backup_slots(state_path=state)

    assert result["findings"] == [], result["findings"]


# ============================ чек 1: сирота-sidecar ============================
def test_orphan_sidecar_warns(tmp_path, monkeypatch):
    """Sidecar-lease существует, а managed-ключа в settings нет → warn «сиротский
    sidecar» (crash-окно A2: backup записан, restore/settings-save упал). Не удалять молча!"""
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {}}), encoding="utf-8")
    sidecar = backup_lib.sidecar_path(settings)
    sidecar.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp:1"}}),
                       encoding="utf-8")
    monkeypatch.setattr(claude_proxy, "SETTINGS", settings)

    result = health_backups.check_backup_slots(state_path=_write_state(tmp_path, {}))

    assert result["status"] == "warn"
    assert any("sidecar" in f and "сирот" in f for f in result["findings"])


def test_sidecar_with_managed_key_is_fine(tmp_path, monkeypatch):
    """Sidecar + живой managed-ключ — легальное состояние force-enable → молчим."""
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://127.0.0.1:8118"}}),
                        encoding="utf-8")
    sidecar = backup_lib.sidecar_path(settings)
    sidecar.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://corp:1"}}),
                       encoding="utf-8")
    monkeypatch.setattr(claude_proxy, "SETTINGS", settings)

    result = health_backups.check_backup_slots(state_path=_write_state(tmp_path, {}))

    assert result["findings"] == []


# ============================ чек 5: смешение слотов ============================
def test_generation_and_lease_slot_mixing_warns(tmp_path, monkeypatch):
    """У одного target одновременно generation-имена и lease-sidecar — ошибка уровня
    контракта (два класса записи для одного носителя, §6-5)."""
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"env": {"HTTPS_PROXY": "http://127.0.0.1:8118"}}),
                        encoding="utf-8")
    backup_lib.sidecar_path(settings).write_text("{}", encoding="utf-8")
    _gen(settings, "2026-06-29T000000Z")
    monkeypatch.setattr(claude_proxy, "SETTINGS", settings)

    result = health_backups.check_backup_slots(state_path=_write_state(tmp_path, {}))

    assert result["status"] == "warn"
    assert any("смешение" in f for f in result["findings"])


# ============================ override-ручки целей sidecar-чеков (review #351) ============================
def test_claude_settings_env_override(tmp_path, monkeypatch):
    """SROUTER_CLAUDE_SETTINGS (канон more-options-better): детерминированная интеграция
    без monkeypatch по claude_proxy.SETTINGS."""
    settings = tmp_path / "claude-settings.json"
    settings.write_text(json.dumps({"env": {}}), encoding="utf-8")
    backup_lib.sidecar_path(settings).write_text("{}", encoding="utf-8")
    monkeypatch.setenv("SROUTER_CLAUDE_SETTINGS", str(settings))

    result = health_backups.check_backup_slots(state_path=_write_state(tmp_path, {}))

    assert any("сиротский sidecar" in f and str(settings) in f
               for f in result["findings"]), result["findings"]


def test_explicit_settings_params_override(tmp_path):
    """Явные параметры claude_settings/vscode_settings — прямая ручка для тестов/кастома,
    приоритетнее env и прод-дефолтов."""
    settings = tmp_path / "claude-settings.json"
    settings.write_text(json.dumps({"env": {}}), encoding="utf-8")
    backup_lib.sidecar_path(settings).write_text("{}", encoding="utf-8")

    result = health_backups.check_backup_slots(
        state_path=_write_state(tmp_path, {}),
        claude_settings=settings, vscode_settings=[tmp_path / "absent-settings.json"])

    assert any("сиротский sidecar" in f and str(settings) in f
               for f in result["findings"]), result["findings"]


# ============================ интеграция в health.check_all ============================
def test_check_all_includes_backup_slots_check(monkeypatch, tmp_path):
    """Грань встроена в doctor-отчёт как info-only чек (не driver — образец
    persists-across-boot #330): warn не роняет вердикт, но виден оператору."""
    import health

    def fake_probe():
        return {"status": "warn", "detail": "state_backup_missing: /x", "findings": ["x"]}

    monkeypatch.setattr(health, "_backup_slots_probe", fake_probe)

    result = health.check_all(active_claude=False)

    names = [c["name"] for c in result["checks"]]
    assert any("бэкап-слоты" in n for n in names), names
    slot = next(c for c in result["checks"] if "бэкап-слоты" in c["name"])
    assert slot["ok"] is False and slot.get("info") is True
