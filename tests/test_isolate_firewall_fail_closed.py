"""Гвард fail-closed контракта isolate_firewall.py (issue #260).

Рефакторинг #240 (`except Exception` → конкретные типы) сузил обработчики так, что
публичные функции стали ВЫБРАСЫВАТЬ наружу вместо возврата структурированного
`{ok: False}` — хотя docstring'и обещают «Не бросает».

Почему это регрессия безопасности, а не косметика:
  - `enable_strict` зовётся launchd при буте (RunAtLoad) — падение = PF-изоляция не
    поднялась, трафик идёт мимо, вызывающий не получает шанса обработать.
  - `dashboard_routes.api_isolate_enable` зовёт движок БЕЗ try/except — исключение
    вылетает в Flask как 500, при этом `pfctl -E` мог уже захватить token, а код
    персиста lease ниже по функции не выполнится → повисший pf enable-ref.

Контракт, который здесь фиксируется: функция, чей docstring обещает «не бросает»,
не выпускает НИКАКОЕ исключение — включая типы, которых автор не предвидел.
Именно непредвиденный тип (`RuntimeError` из sys_probe.run) и проехал в #240.

Каноны: always-tdd, fail-closed-proxy-down, verify-dont-guess,
privileged-boundary-fail-closed, srouter-critical-infra-24-7.
"""
import subprocess

import pytest

import isolate_firewall


# ============================ helpers ============================
# Набор типов, которые НЕ входят в суженные except-списки #240. Именно они и текли.
# RuntimeError — реальный кандидат: sys_probe.run оборачивает subprocess и может
# поднять его же; KeyError/AttributeError — типовые сбои разбора чужого вывода.
UNEXPECTED_EXCEPTIONS = [
    RuntimeError("pfctl взорвался"),
    KeyError("token"),
    AttributeError("'NoneType' object has no attribute 'get'"),
    MemoryError("dscl вывалился"),
]

# Типы из суженных списков #240 — они ловились и до фикса. Держим в гварде,
# чтобы фикс не сузил обработку обратно в другую сторону.
EXPECTED_EXCEPTIONS = [
    OSError("permission denied"),
    subprocess.TimeoutExpired("pfctl -E", 60),
    subprocess.CalledProcessError(1, "pfctl"),
    ValueError("invalid ports spec"),
]

ALL_EXCEPTIONS = UNEXPECTED_EXCEPTIONS + EXPECTED_EXCEPTIONS


def _ids(excs):
    return [type(e).__name__ for e in excs]


@pytest.fixture
def boom(monkeypatch):
    """Фабрика: подменяет sys_probe.run на бросающий заданное исключение.

    sys_probe.run — единственная точка выхода наружу во всех этих функциях
    (osascript-мост, dig, dscl). Подмена именно её воспроизводит реальный сбой,
    а не искусственный.
    """
    def _install(exc):
        def _raise(*args, **kwargs):
            raise exc
        monkeypatch.setattr(isolate_firewall.sys_probe, "run", _raise)
    return _install


@pytest.fixture(autouse=True)
def _no_real_resolve(monkeypatch):
    """resolve_domain_ips не должен ходить в сеть: детерминированный резолв."""
    monkeypatch.setattr(isolate_firewall, "resolve_domain_ips",
                        lambda domains, dns_servers=None: {d: ["1.2.3.4"] for d in (domains or [])})


# Публичные функции, чей docstring обещает dict с ok=False (не бросает).
# (имя, вызов) — вызов подобран так, чтобы дойти до sys_probe.run.
OK_FALSE_FUNCS = [
    ("enable_strict", lambda: isolate_firewall.enable_strict()),
    ("disable_strict", lambda: isolate_firewall.disable_strict(token="7")),
    ("enable_isolation", lambda: isolate_firewall.enable_isolation(["api.anthropic.com"], ports=[80, 443])),
    ("refresh_isolation_ips", lambda: isolate_firewall.refresh_isolation_ips(["api.anthropic.com"])),
    ("disable_isolation", lambda: isolate_firewall.disable_isolation(token="7")),
    ("enable_codex_isolation", lambda: isolate_firewall.enable_codex_isolation()),
    ("disable_codex_isolation", lambda: isolate_firewall.disable_codex_isolation(token="7")),
    ("provision_codex_user", lambda: isolate_firewall.provision_codex_user()),
    ("deprovision_codex_user", lambda: isolate_firewall.deprovision_codex_user()),
]


# ============================ 1. функции, возвращающие {ok: False} ============================
@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
@pytest.mark.parametrize("name,call", OK_FALSE_FUNCS, ids=[n for n, _ in OK_FALSE_FUNCS])
def test_returns_ok_false_instead_of_raising(name, call, exc, boom, monkeypatch):
    """Любое исключение из sys_probe.run → структурированный {ok: False}, не проброс.

    Fail-closed: вызывающий (launchd, Flask-роут, codex-wrapper) обязан получить
    результат, который можно обработать, а не пробитый стек.
    """
    # provision/deprovision сначала зовут probe_codex_user — фиксируем его,
    # чтобы исключение прилетело из целевой функции, а не из пробы.
    monkeypatch.setattr(isolate_firewall, "probe_codex_user",
                        lambda: {"provisioned": name == "deprovision_codex_user",
                                 "uid": "503", "name": "_srouter_codex", "gid": "503"})
    monkeypatch.setattr(isolate_firewall, "_uid_in_use", lambda uid: False)
    boom(exc)

    result = call()

    assert isinstance(result, dict), f"{name} должна вернуть dict, вернула {type(result).__name__}"
    assert result.get("ok") is False, f"{name} должна вернуть ok=False при {type(exc).__name__}: {result}"
    assert result.get("err"), f"{name} должна объяснить причину в err: {result}"


@pytest.mark.parametrize("exc", UNEXPECTED_EXCEPTIONS, ids=_ids(UNEXPECTED_EXCEPTIONS))
@pytest.mark.parametrize("name,call", [
    ("enable_strict", lambda: isolate_firewall.enable_strict()),
    ("enable_isolation", lambda: isolate_firewall.enable_isolation(["api.anthropic.com"])),
    ("enable_codex_isolation", lambda: isolate_firewall.enable_codex_isolation()),
], ids=["enable_strict", "enable_isolation", "enable_codex_isolation"])
def test_enable_funcs_report_token_none_on_failure(name, call, exc, boom):
    """enable-функции при сбое обязаны отдать token=None.

    Вызывающий персистит lease по token. Отсутствие ключа заставило бы его
    считать, что токена нет, но и не позволило бы отличить «не захвачен» от
    «не сообщён» — контракт требует явный None.
    """
    boom(exc)
    result = call()
    assert result.get("token", "MISSING") is None, f"{name}: ожидали token=None, получили {result!r}"


@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_enable_isolation_keeps_shape_on_failure(exc, boom):
    """enable_isolation обязана сохранить форму ответа даже при сбое.

    Роут `api_isolate_enable` читает result["domains"]/["unresolved"]/["ports"]
    безусловно — отсутствие ключей превратило бы обработанный сбой в KeyError.
    """
    boom(exc)
    result = isolate_firewall.enable_isolation(["api.anthropic.com"], ports=[80, 443])
    assert isinstance(result.get("domains"), dict), f"нет domains: {result}"
    assert isinstance(result.get("unresolved"), list), f"нет unresolved: {result}"
    assert result.get("ports") == [80, 443], f"ports не сохранены: {result}"


@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_refresh_isolation_ips_keeps_shape_on_failure(exc, boom):
    """refresh_isolation_ips: та же форма — роут читает domains/unresolved безусловно."""
    boom(exc)
    result = isolate_firewall.refresh_isolation_ips(["api.anthropic.com"], ports=[80, 443])
    assert result.get("ok") is False, f"ожидали ok=False: {result}"
    assert isinstance(result.get("domains"), dict), f"нет domains: {result}"
    assert isinstance(result.get("unresolved"), list), f"нет unresolved: {result}"
    assert result.get("ports") == [80, 443], f"ports не сохранены: {result}"


# ============================ 2. probe-функции: status/provisioned ============================
@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_probe_isolation_returns_unknown(exc, monkeypatch):
    """probe_isolation: сбой чтения state → status=unknown, не проброс.

    probe-канон: всегда dict со status. unknown, а не down/ok — не предполагаем
    успех и не предполагаем выключенность (fail-closed на неизвестности).
    """
    def _raise(*args, **kwargs):
        raise exc
    monkeypatch.setattr(isolate_firewall.local_state, "load_active_isolate", _raise)
    result = isolate_firewall.probe_isolation()
    assert result.get("status") == "unknown", f"ожидали status=unknown: {result}"
    assert result.get("error"), f"ожидали error-ключ: {result}"


@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_probe_codex_isolation_returns_unknown(exc, monkeypatch):
    """probe_codex_isolation: сбой чтения codex-lease → status=unknown."""
    def _raise(*args, **kwargs):
        raise exc
    monkeypatch.setattr(isolate_firewall.local_state, "load_active_codex_isolate", _raise)
    result = isolate_firewall.probe_codex_isolation()
    assert result.get("status") == "unknown", f"ожидали status=unknown: {result}"
    assert result.get("error"), f"ожидали error-ключ: {result}"


@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_probe_codex_user_returns_not_provisioned(exc, boom):
    """probe_codex_user: сбой dscl → provisioned=False (fail-closed).

    provisioned=True при неопределённости заставило бы provision_codex_user
    решить, что пользователь уже есть, и пропустить создание — PF kill-switch
    остался бы неактивным.
    """
    boom(exc)
    result = isolate_firewall.probe_codex_user()
    assert result.get("provisioned") is False, f"ожидали provisioned=False: {result}"
    assert result.get("uid") is None, f"ожидали uid=None: {result}"


@pytest.mark.parametrize("exc", ALL_EXCEPTIONS, ids=_ids(ALL_EXCEPTIONS))
def test_uid_in_use_returns_true(exc, boom):
    """_uid_in_use: сбой dscl → True (fail-closed: не создаём поверх неизвестного).

    Единственная функция, пережившая #240 с `except Exception`. Гвард держит её
    такой — противоположное (False) означало бы перезапись чужого UID.
    """
    boom(exc)
    assert isolate_firewall._uid_in_use("503") is True, "ожидали True (uid считается занятым)"


# ============================ 3. позитивные пути (фикс не должен глушить успех) ============================
def _ok_run(token="5"):
    def fake(cmd_list, timeout=None):
        return {"rc": 0, "out": f"Token : {token}", "err": "", "timeout": False}
    return fake


def test_enable_strict_ok(monkeypatch):
    """Успешный путь enable_strict: token распознан, ok=True."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run("3"))
    result = isolate_firewall.enable_strict()
    assert result["ok"] is True, f"ожидали успех: {result}"
    assert result["token"] == "3", f"ожидали token=3: {result}"


def test_enable_isolation_ok(monkeypatch):
    """Успешный путь enable_isolation: домены зарезолвлены, token захвачен."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run("7"))
    monkeypatch.setattr(isolate_firewall, "resolve_domain_ips",
                        lambda domains, dns_servers=None: {"api.anthropic.com": ["1.2.3.4", "5.6.7.8"]})
    result = isolate_firewall.enable_isolation(["api.anthropic.com"], ports=[80, 443])
    assert result["ok"] is True, f"ожидали успех: {result}"
    assert result["token"] == "7", f"ожидали token=7: {result}"
    assert result["domains"]["api.anthropic.com"] == ["1.2.3.4", "5.6.7.8"], f"domains: {result}"


def test_enable_codex_isolation_ok(monkeypatch):
    """Успешный путь enable_codex_isolation."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run("11"))
    result = isolate_firewall.enable_codex_isolation()
    assert result["ok"] is True, f"ожидали успех: {result}"
    assert result["token"] == "11", f"ожидали token=11: {result}"


def test_enable_isolation_rejects_invalid_ports(monkeypatch):
    """Валидация портов происходит ДО привилегированного вызова (ранний return)."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run())
    result = isolate_firewall.enable_isolation(["api.anthropic.com"], ports=[99999])
    assert result["ok"] is False, f"невалидный порт → fail: {result}"
    assert result.get("token") is None, f"token=None: {result}"


def test_enable_isolation_rejects_empty_domains(monkeypatch):
    """Пустой список доменов → ранний return без привилегированного вызова."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run())
    result = isolate_firewall.enable_isolation([])
    assert result["ok"] is False, f"пустой domains → fail: {result}"


def test_provision_codex_user_noop_when_already_provisioned(monkeypatch):
    """Идемпотентность: уже provisioned → ok=True без dscl-вызова."""
    monkeypatch.setattr(isolate_firewall, "probe_codex_user",
                        lambda: {"provisioned": True, "uid": "503", "name": "_srouter_codex", "gid": "503"})
    result = isolate_firewall.provision_codex_user()
    assert result["ok"] is True, f"ожидали no-op success: {result}"


# ============================ 4. CLI-граница: launchd получает exit-code, не стек ============================
# main() — вторая привилегированная граница наряду с Flask-роутом: её вызывает launchd
# (com.srouter.isolate.plist → enable-strict, com.srouter.isolate-refresh.plist → refresh,
# com.srouter.isolate-escape.plist → disable-strict). Движок теперь fail-closed, но main()
# читает local_state ДО вызова движка — и этот участок обязан держать тот же контракт,
# иначе повреждённый lease валит job стеком вместо честного exit-кода.
# Мутирующие команды: сбой обязан дать ненулевой код (launchd-jobs enable-strict/refresh/
# disable-strict живут здесь — им нужен честный fail, а не тихий успех).
CLI_MUTATING_COMMANDS = ["enable", "disable", "refresh", "enable-codex", "disable-codex",
                         "enable-strict", "disable-strict"]

# Диагностические read-only команды: контракт probe-слоя — ВСЕГДА напечатать статус,
# включая "unknown" при нечитаемом state. Ненулевой код здесь был бы неверен: отсутствие
# ответа и ответ «не знаю» — разные вещи, и launchd их не запускает (см. plists).
CLI_STATUS_COMMANDS = ["status", "status-codex", "status-codex-user"]


@pytest.mark.parametrize("exc", UNEXPECTED_EXCEPTIONS, ids=_ids(UNEXPECTED_EXCEPTIONS))
@pytest.mark.parametrize("cmd", CLI_MUTATING_COMMANDS)
def test_cli_returns_exit_code_on_state_failure(cmd, exc, monkeypatch, boom):
    """Сбой чтения state → ненулевой exit-code, не проброс исключения в launchd.

    launchd не различает «упало со стеком» и «вернуло 2» иначе как по коду возврата;
    непойманное исключение = job помечен crashed, а причина видна только в логе.
    Контракт CLI: всегда int, как у любой main()-обёртки.
    """
    def _raise(*args, **kwargs):
        raise exc
    for fn in ("load_active_isolate", "load_active_codex_isolate", "load_state"):
        monkeypatch.setattr(isolate_firewall.local_state, fn, _raise)
    boom(exc)

    rc = isolate_firewall.main([cmd])

    assert isinstance(rc, int), f"{cmd}: main() обязана вернуть int, вернула {type(rc).__name__}"
    assert rc != 0, f"{cmd}: сбой обязан дать ненулевой exit-code, получили {rc}"


@pytest.mark.parametrize("exc", UNEXPECTED_EXCEPTIONS, ids=_ids(UNEXPECTED_EXCEPTIONS))
@pytest.mark.parametrize("cmd", CLI_STATUS_COMMANDS)
def test_cli_status_never_raises_on_state_failure(cmd, exc, monkeypatch, boom):
    """status-команды при нечитаемом state печатают статус и возвращают int, не бросают.

    Контракт probe-слоя (unknown вместо ok/down) уже держит движок; здесь фиксируется,
    что CLI-обёртка его не ломает и что диагностика остаётся доступной именно тогда,
    когда что-то сломано — иначе оператор теряет инструмент в самый нужный момент.
    """
    def _raise(*args, **kwargs):
        raise exc
    for fn in ("load_active_isolate", "load_active_codex_isolate", "load_state"):
        monkeypatch.setattr(isolate_firewall.local_state, fn, _raise)
    boom(exc)

    rc = isolate_firewall.main([cmd])

    assert isinstance(rc, int), f"{cmd}: main() обязана вернуть int, вернула {type(rc).__name__}"


def test_cli_returns_zero_on_success(monkeypatch):
    """Позитивный путь CLI: успешный enable-strict → exit 0 (фикс не ломает happy-path)."""
    monkeypatch.setattr(isolate_firewall.sys_probe, "run", _ok_run("3"))
    assert isolate_firewall.main(["enable-strict"]) == 0


# ============================ 5. граница роута: 500 структурированный, не пробитый стек ============================
def test_isolate_enable_route_reports_structured_error(monkeypatch):
    """Сбой движка на границе Flask → JSON-ответ 500, а не необработанное исключение.

    `api_isolate_enable` зовёт `isolate_firewall.enable_isolation` БЕЗ try/except
    (глобального errorhandler у приложения тоже нет). Пока движок держит контракт
    «не бросает», отдельный guard в роуте не нужен — но именно это здесь и
    закрепляется: регрессия в движке немедленно проявится как падение этого теста,
    а не как тихий 500 в проде (канон privileged-boundary-fail-closed).
    """
    import dashboard

    monkeypatch.setattr(dashboard.local_state, "load_state", lambda *a, **k: {})
    monkeypatch.setattr(dashboard.local_state, "load_active_isolate", lambda *a, **k: None)
    monkeypatch.setattr(dashboard.local_state, "preflight_state_write", lambda *a, **k: True)

    def _raise(*args, **kwargs):
        raise RuntimeError("pfctl взорвался")
    monkeypatch.setattr(dashboard.isolate_firewall.sys_probe, "run", _raise)
    monkeypatch.setattr(dashboard.isolate_firewall, "resolve_domain_ips",
                        lambda domains, dns_servers=None: {d: ["1.2.3.4"] for d in (domains or [])})

    response = dashboard.app.test_client().post(
        "/api/isolate/enable", json={"domains": ["api.anthropic.com"], "ports": [80, 443]})

    assert response.status_code == 500, f"ожидали структурированный 500: {response.status_code}"
    body = response.get_json()
    assert body is not None, "ответ обязан быть JSON, а не HTML-страницей необработанного исключения"
    assert body.get("ok") is False, f"ожидали ok=False: {body}"
    assert body.get("err"), f"ожидали объяснение в err: {body}"


def test_provision_codex_user_refuses_foreign_uid(monkeypatch):
    """UID занят чужим именем → fail-closed reject, dscl не зовётся."""
    monkeypatch.setattr(isolate_firewall, "probe_codex_user",
                        lambda: {"provisioned": False, "uid": None, "name": None, "gid": None})
    monkeypatch.setattr(isolate_firewall, "_uid_in_use", lambda uid: True)
    result = isolate_firewall.provision_codex_user()
    assert result["ok"] is False, f"занятый UID → reject: {result}"
