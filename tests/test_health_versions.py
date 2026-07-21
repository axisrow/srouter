"""ТДД-тесты health._installed_versions_check: doctor видит ВСЕ установленные на диске
codex/claude-code binary + их версии + «обёрнут ли wrapper'ом srouter» (issue #145).

В отличие от _claude_proxy_probe / _codex_proxy_probe (живые процессы, lsof), этот чек смотрит
на ДИСК: well-known места установки codex (which -a, /opt/homebrew/bin, /usr/local/bin, ~/bin,
npm global root, brew-cask) и claude-code (CLI, GUI app, versions/*). Несколько версий — ранний
сигнал конфликта (#135, desktop-proxy-vs-managed-codex-socks5-conflict), но НЕ сбой стека →
info-only (status не роняет, как claude-proxy когда CC не запущен).

Возвращает {status, detail, codex:[...], claude_code:[...]}:
  status="ok"      — что-то установлено (картина показана);
  status="unknown" — ничего не найдено (info-only «не установлено»).
Каждый найденный binary: {path, provenance, version, wrapped}.
"""
from pathlib import Path

import pytest

import health


# ============================ helpers: mock filesystem + sys_probe.run ============================

def _fs_probe(files, *, codex_versions=None, claude_versions=None,
              which_codex=(), which_claude=(), npm_root=None, brew_cask=()):
    """Построить fake для sys_probe.run + Path.exists/is_file/is_dir по заданному множеству файлов.

    `files` — dict {abs_path: file_content_or_None}. None = каталог (is_dir True).
    `*_versions` — {path: version_string} ответ `--version` для соответствующего binary.
    `which_*` — список путей, которые вернёт `which -a <name>` (в порядке).
    `npm_root` — путь, возвращаемый `npm root -g` (или None → не найдено).
    `brew_cask` — вывод `brew list --cask` (строка).
    """
    files = {str(k): v for k, v in files.items()}
    codex_versions = {str(k): v for k, v in (codex_versions or {}).items()}
    claude_versions = {str(k): v for k, v in (claude_versions or {}).items()}
    which_codex = [str(p) for p in which_codex]
    which_claude = [str(p) for p in which_claude]
    brew_cask_str = "\n".join(brew_cask) if brew_cask else ""

    def fake_run(cmd, timeout):
        argv = cmd or []
        # which -a <name>
        if argv and argv[0] == "/usr/bin/which" and "-a" in argv:
            name = argv[-1]
            out = "\n".join(which_codex if name == "codex" else which_claude)
            return {"rc": 0, "out": out, "err": "", "timeout": False}
        # npm root -g
        if argv and argv[0].endswith("npm") and "root" in argv:
            if npm_root is None:
                return {"rc": 1, "out": "", "err": "no npm", "timeout": False}
            return {"rc": 0, "out": npm_root, "err": "", "timeout": False}
        # brew list --cask
        if argv and argv[0].endswith("brew") and "--cask" in argv:
            return {"rc": 0, "out": brew_cask_str, "err": "", "timeout": False}
        # <binary> --version
        if argv and "--version" in argv:
            binary = argv[0]
            if binary in codex_versions:
                return {"rc": 0, "out": codex_versions[binary], "err": "", "timeout": False}
            if binary in claude_versions:
                return {"rc": 0, "out": claude_versions[binary], "err": "", "timeout": False}
            return {"rc": 0, "out": "", "err": "", "timeout": False}
        return {"rc": 0, "out": "", "err": "", "timeout": False}

    def fake_exists(self):
        return str(self) in files

    def fake_is_file(self):
        return str(self) in files and files[str(self)] is not None

    def fake_is_dir(self):
        return str(self) in files and files[str(self)] is None

    def fake_read_text(self, *a, **kw):
        return files.get(str(self), "")

    def fake_resolve(self, *a, **kw):
        # НЕ резолвить симлинки через реальную FS (на dev-машине /opt/homebrew/bin/codex — реальный
        # symlink, который сломал бы дедуп в тесте). Дедуп по стабильному строковому ключу.
        return Path(str(self))

    def fake_iterdir(self):
        # Дочерние элементы каталога: пути, чей parent == self (по строковому префиксу каталога).
        me = str(self)
        children = set()
        for key in files:
            parent = str(Path(key).parent)
            if parent == me and key != me:
                children.add(Path(key))
        return sorted(children)

    return fake_run, fake_exists, fake_is_file, fake_is_dir, fake_read_text, fake_resolve, fake_iterdir


@pytest.fixture
def _versions_monkey(monkeypatch, tmp_path):
    """Применить fake fs/sys_probe к health. Возвращает dict для настройки содержимого."""
    monkeypatch.setattr(health.Path, "home", classmethod(lambda cls: tmp_path))

    def apply(files, **probe_kw):
        probe = _fs_probe(files, **probe_kw)
        monkeypatch.setattr(health.sys_probe, "run", probe[0])
        monkeypatch.setattr(health.Path, "exists", probe[1])
        monkeypatch.setattr(health.Path, "is_file", probe[2])
        monkeypatch.setattr(health.Path, "is_dir", probe[3])
        monkeypatch.setattr(health.Path, "read_text", probe[4])
        monkeypatch.setattr(health.Path, "resolve", probe[5])
        monkeypatch.setattr(health.Path, "iterdir", probe[6])
        return probe

    return apply


# ============================ (1) два codex-binary разного provenance → оба в выводе ============================

def test_codex_two_binaries_different_provenance_both_shown(_versions_monkey, tmp_path):
    """ДЫРА #145: doctor видел только ЖИВЫЕ процессы. Два codex-binary на диске разного provenance
    (npm + homebrew-dir) → чек показывает ОБА."""
    brew_codex = "/opt/homebrew/bin/codex"
    local_codex = "/usr/local/bin/codex"
    files = {
        brew_codex: "#!/usr/bin/env node\n",   # real npm binary (Apple-Silicon не важно)
        local_codex: "#!/usr/bin/env node\n",  # второй real binary (ручная установка)
        str(tmp_path / "bin" / "codex"): None,  # нет wrapper'а (каталог bin есть, codex там — ниже)
    }
    # НЕТ wrapper'а в ~/bin/codex (удаляем запись — каталог bin без файла)
    files = {brew_codex: files[brew_codex], local_codex: files[local_codex]}
    apply = _versions_monkey
    apply(files,
          which_codex=[brew_codex, local_codex],
          codex_versions={brew_codex: "codex-cli 0.144.6",
                          local_codex: "codex-cli 0.144.5"})

    res = health._installed_versions_check()
    assert res["status"] == "ok", "что-то установлено → ok (info-only, не роняет)"
    paths = {b["path"] for b in res["codex"]}
    assert brew_codex in paths and local_codex in paths, \
        f"оба codex-binary должны детектиться, got {paths}"
    provs = {b["path"]: b["provenance"] for b in res["codex"]}
    assert provs[brew_codex] != provs[local_codex], \
        "разные provenance (homebrew vs usr/local) — не должны склеиваться"


# ============================ (2) wrapper + real → оба детектятся, wrapper помечен «обёрнут» ============================

def test_codex_wrapper_and_real_both_detected_wrapper_marked(_versions_monkey, tmp_path):
    """~/bin/codex (srouter-wrapper) + /opt/homebrew/bin/codex (real) → оба в выводе, wrapper
    помечен wrapped=True, real — wrapped=False. Маркер srouter: '# srouter: codex CLI wrapper (managed)'.
    """
    wrapper = str(tmp_path / "bin" / "codex")
    real = "/opt/homebrew/bin/codex"
    files = {
        wrapper: "#!/bin/sh\n# srouter: codex CLI wrapper (managed)\nexec /usr/bin/env\n",
        real: "#!/usr/bin/env node\nconsole.log('codex')\n",
    }
    _versions_monkey(files,
                     which_codex=[real, wrapper],
                     codex_versions={real: "codex-cli 0.144.6",
                                     wrapper: "codex-cli 0.144.6"})

    res = health._installed_versions_check()
    by_path = {b["path"]: b for b in res["codex"]}
    assert wrapper in by_path and real in by_path, \
        f"и wrapper, и real должны детектиться, got {set(by_path)}"
    assert by_path[wrapper]["wrapped"] is True, "wrapper в ~/bin/codex — обёрнут srouter"
    assert by_path[real]["wrapped"] is False, "real binary НЕ обёрнут"


def test_codex_wrapper_not_srouter_marked_unwrapped(_versions_monkey, tmp_path):
    """~/bin/codex БЕЗ srouter-маркера (чужой wrapper) → wrapped=False (мы его не ставили).
    Regression: naive «файл существует в ~/bin → wrapped» принимает чужой wrapper за свой.
    """
    foreign = str(tmp_path / "bin" / "codex")
    real = "/opt/homebrew/bin/codex"
    files = {
        foreign: "#!/bin/sh\n# my custom codex wrapper\nexec /somewhere/codex\n",
        real: "#!/usr/bin/env node\n",
    }
    _versions_monkey(files,
                     which_codex=[real, foreign],
                     codex_versions={real: "codex-cli 0.144.6",
                                     foreign: "codex-cli 0.144.6"})

    res = health._installed_versions_check()
    by_path = {b["path"]: b for b in res["codex"]}
    assert by_path[foreign]["wrapped"] is False, "чужой wrapper (без маркера srouter) — НЕ обёрнут"


# ============================ (3) ничего не установлено → info «не установлено», status не падает ============================

def test_nothing_installed_info_unknown(_versions_monkey, tmp_path):
    """Ни codex, ни claude-code на диске нет → status=unknown (info-only «не установлено»).
    check_all НЕ роняет вердикт (status ok если стек жив).
    """
    _versions_monkey({})  # пустой диск

    res = health._installed_versions_check()
    assert res["status"] == "unknown", "ничего не установлено → unknown (info-only)"
    assert res["codex"] == [] and res["claude_code"] == [], "пустые списки"
    assert "не установлен" in res["detail"].lower() or "не найден" in res["detail"].lower()


def test_check_all_status_ok_when_nothing_installed(monkeypatch, tmp_path):
    """Порты+туннель живы, ничего из codex/claude не установлено → status=ok (info-чек не роняет)."""
    monkeypatch.setattr(health, "_port_up", lambda port: True)
    monkeypatch.setattr(health, "_tunnel_up", lambda: (True, "HTTP 200"))
    monkeypatch.setattr(health, "_claude_proxy_probe",
                        lambda: {"status": "unknown", "source": "n/a", "detail": "CC не запущен"})
    monkeypatch.setattr(health, "_codex_proxy_probe",
                        lambda: {"status": "unknown", "source": "n/a", "detail": "codex не запущен"})
    monkeypatch.setattr(health, "_endpoint_override_check",
                        lambda: {"status": "ok", "detail": "стандартный"})
    monkeypatch.setattr(health, "_desktop_proxy_check",
                        lambda: {"status": "unknown", "detail": "нет launchctl"})
    monkeypatch.setattr(health, "_installed_versions_check",
                        lambda: {"status": "unknown", "detail": "не установлено",
                                 "codex": [], "claude_code": []})
    result = health.check_all()
    assert result["status"] == "ok", "info-чек версий НЕ роняет вердикт"
    names = [c["name"] for c in result["checks"]]
    assert any("верс" in n.lower() or "codex" in n.lower() and "claude" in n.lower()
               for n in names), f"должен быть versions-check, got {names}"
    vcheck = [c for c in result["checks"] if c.get("info") and "не установлен" in (c.get("detail") or "").lower()]
    assert vcheck, "versions-check должен быть info-only с detail «не установлено»"


# ============================ (4) CC не запущен → чек работает с диска ============================

def test_claude_code_disk_detection_without_running_processes(_versions_monkey, tmp_path):
    """CC НЕ запущен → versions-check всё равно видит CLI/GUI/versions на диске (диск, не процессы).
    Это ключевая разница с _claude_proxy_probe (живые proc через lsof).
    """
    cli = str(tmp_path / ".local" / "bin" / "claude")
    app = str(tmp_path / ".local" / "share" / "claude" / "ClaudeCode.app")
    ver_dir = str(tmp_path / ".local" / "share" / "claude" / "versions")
    ver_216 = str(Path(ver_dir) / "2.1.216")
    files = {
        cli: "#!/usr/bin/env node\n",
        app: None,        # каталог .app
        ver_dir: None,    # каталог versions
        ver_216: "#!/usr/bin/env node\n",  # version-runner binary
    }
    _versions_monkey(files,
                     which_claude=[cli],
                     claude_versions={cli: "2.1.216 (Claude Code)",
                                      ver_216: ""})

    res = health._installed_versions_check()
    assert res["status"] == "ok"
    paths = {b["path"] for b in res["claude_code"]}
    assert cli in paths, f"CLI claude должен детектиться с диска, got {paths}"
    # versions/* детектятся (version-runner binary) — основной движок CC
    assert any("versions" in p for p in paths), \
        f"version-runner в versions/* должен детектиться с диска, got {paths}"


def test_codex_detected_from_npm_global_root(_versions_monkey, tmp_path):
    """codex из npm global root (@openai/codex/bin/codex.js) → детектится, provenance=npm.
    which -a может не показать npm-binary (если не в PATH) → scan npm root как отдельный источник.
    """
    npm_root = "/opt/homebrew/lib/node_modules"
    npm_codex = str(Path(npm_root) / "@openai" / "codex" / "bin" / "codex.js")
    brew_codex = "/opt/homebrew/bin/codex"
    files = {
        npm_codex: "#!/usr/bin/env node\n",
        brew_codex: "#!/usr/bin/env node\n",
    }
    _versions_monkey(files,
                     which_codex=[brew_codex],
                     npm_root=npm_root,
                     codex_versions={npm_codex: "codex-cli 0.144.6",
                                     brew_codex: "codex-cli 0.144.6"})

    res = health._installed_versions_check()
    paths = {b["path"] for b in res["codex"]}
    assert npm_codex in paths, "npm-global codex должен детектиться через npm root -g"
    provs = {b["path"]: b["provenance"] for b in res["codex"]}
    assert provs[npm_codex] == "npm", f"npm-binary provenance=npm, got {provs[npm_codex]}"


def test_codex_dedup_when_which_and_npm_point_to_same_resolve(_versions_monkey, tmp_path):
    """which -a /opt/homebrew/bin/codex и npm root → /opt/.../@openai/codex/bin/codex.js — РАЗНЫЕ пути,
    РАЗНЫЕ provenance, НЕ дедуплицируются (это разные файлы: symlink-wrapper vs real .js).
    Дедуп только по нормализованному пути (один и тот же файл через два имени)."""
    brew_codex = "/opt/homebrew/bin/codex"
    files = {brew_codex: "#!/usr/bin/env node\n"}
    # npm root указывает на тот же realpath (symink) → дедуп по пути не нужен, но по содержимому не сравниваем
    _versions_monkey(files, which_codex=[brew_codex], npm_root="/nonexistent")
    res = health._installed_versions_check()
    paths = {b["path"] for b in res["codex"]}
    assert brew_codex in paths
    # /nonexistent/@openai/codex не существует → не детектируется (нет ложного дубликата)
    assert all("/nonexistent" not in p for p in paths)


# ============================ формат detail (буллеты provenance + version + wrapped-бейдж) ============================

def test_detail_includes_provenance_version_and_wrapped_badge(_versions_monkey, tmp_path):
    """detail (для doctor-отчёта) содержит для каждого binary: provenance + version + бейдж обёрнут/нет.
    Формат — см. пример в issue #145 (буллеты).
    """
    wrapper = str(tmp_path / "bin" / "codex")
    real = "/opt/homebrew/bin/codex"
    files = {
        wrapper: "#!/bin/sh\n# srouter: codex CLI wrapper (managed)\n",
        real: "#!/usr/bin/env node\n",
    }
    _versions_monkey(files,
                     which_codex=[real, wrapper],
                     codex_versions={real: "codex-cli 0.144.6",
                                     wrapper: "codex-cli 0.144.6"})

    res = health._installed_versions_check()
    detail = res["detail"].lower()
    assert "0.144.6" in detail, "detail должен содержать версию"
    assert "обёрнут" in detail, "detail должен показывать бейдж «обёрнут» для wrapper"
    assert wrapper in res["detail"] or "wrapper" in detail, "detail упоминает wrapper-путь/роль"
