"""Regress-гвард экстракции srouter.py → srouter_cli/srouter_launchd/codex_wrappers (#228).

Экстракция — перенос, не редизайн. Прошлая попытка (PR #232) прошла hasattr-гвард и
при этом уронила 50 тестов: тела команд были заменены на `print("TODO")`, а build_parser()
пересобран с нуля и потерял флаги (--state/--xray-config/--adopt/--json/...).
`hasattr(srouter, "cmd_sync")` одинаково доволен и заглушкой, и реализацией.

Поэтому гвард ПОВЕДЕНЧЕСКИЙ и снимает поверхность CLI с самого парсера рекурсивно
(включая вложенные sub-subcommands routing/privoxy/privoxy audit), а не перечисляет
её руками — иначе гвард фиксирует представление автора о CLI, а не сам CLI.

Проверяется то, что реально ломалось в #232:
1. Полная рекурсивная поверхность парсера: пути подкоманд + флаги + type/default.
2. Диспетчеризация set_defaults(func=...) ведёт в реальные команды.
3. Команды — не заглушки (нет TODO, тело не вырождено).
4. Идентичность объектов при re-export (ловит двустороннюю делегацию srouter ↔ srouter_cli).

Полный `pytest tests/` (1560 passed на 894eb40) — внешний гвард поверх этого.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import textwrap

import pytest

import srouter


COMMAND_FUNCS = [
    "cmd_install",
    "cmd_uninstall",
    "cmd_start",
    "cmd_stop",
    "cmd_restart",
    "cmd_status",
    "cmd_doctor",
    "cmd_sync",
    "cmd_privoxy",
    "cmd_routing",
]


def _subparsers_action(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _walk(parser, path=()):
    """Рекурсивно обойти парсер: (путь_подкоманд, парсер)."""
    yield path, parser
    sub = _subparsers_action(parser)
    if sub is None:
        return
    for name, subparser in sub.choices.items():
        yield from _walk(subparser, path + (name,))


def _surface(parser):
    """Снимок поверхности CLI: путь -> {dest: (option_strings, type, default, required)}.

    Это и есть контракт экстракции: перенос обязан сохранить его целиком.
    """
    snap = {}
    for path, p in _walk(parser):
        opts = {}
        for a in p._actions:
            if isinstance(a, (argparse._HelpAction, argparse._SubParsersAction)):
                continue
            opts[a.dest] = (
                tuple(sorted(a.option_strings)),
                getattr(a.type, "__name__", None),
                a.default,
                a.required,
            )
        snap[path] = opts
    return snap


@pytest.fixture(scope="module")
def parser():
    return srouter.build_parser()


@pytest.fixture(scope="module")
def surface(parser):
    return _surface(parser)


class TestParserSurface:
    """Поверхность парсера переносится целиком, а не пересобирается."""

    def test_top_level_subcommands(self, surface):
        top = {p[0] for p in surface if len(p) == 1}
        assert top == {
            "install", "uninstall", "start", "stop", "restart",
            "status", "doctor", "sync", "routing", "privoxy",
        }

    def test_nested_subcommand_paths_preserved(self, surface):
        """routing/privoxy имеют вложенные sub-subcommands — они тоже часть контракта."""
        paths = set(surface)
        for expected in (
            ("routing", "add-domain"),
            ("routing", "remove-domain"),
            ("routing", "list"),
            ("privoxy", "status"),
            ("privoxy", "protect"),
            ("privoxy", "start"),
            ("privoxy", "stop"),
            ("privoxy", "restart"),
            ("privoxy", "unprotect"),
            ("privoxy", "audit"),
            ("privoxy", "audit", "install"),
            ("privoxy", "audit", "status"),
            ("privoxy", "audit", "report"),
            ("privoxy", "audit", "uninstall"),
        ):
            assert expected in paths, f"Потеряна подкоманда {'/'.join(expected)}"

    @pytest.mark.parametrize(
        "path,dest",
        [
            (("install",), "state"),
            (("install",), "prefix"),
            (("install",), "launchagents_dir"),
            (("install",), "python"),
            (("install",), "yes"),
            (("install",), "force_endpoint_overwrite"),
            (("uninstall",), "yes"),
            (("status",), "state"),
            (("doctor",), "state"),
            (("sync",), "state"),
            (("sync",), "xray_config"),
            (("routing", "list"), "outbound"),
            (("routing", "list"), "xray_config"),
            (("routing", "add-domain"), "host"),
            (("routing", "add-domain"), "adopt"),
            (("privoxy", "protect"), "strict"),
            (("privoxy", "protect"), "prefix"),
            (("privoxy", "audit", "report"), "limit"),
            (("privoxy", "audit", "report"), "json"),
            (("privoxy", "audit", "uninstall"), "purge_log"),
        ],
    )
    def test_flag_present_on_its_subcommand(self, surface, path, dest):
        """Флаги висят именно на своих подкомандах (в #232 они исчезли/переехали)."""
        assert path in surface, f"Нет подкоманды {'/'.join(path)}"
        assert dest in surface[path], f"Потерян флаг {dest} у {'/'.join(path) or 'root'}"

    def test_report_limit_keeps_int_type(self, surface):
        """--limit имеет type=int: потеря типа тихо ломает валидацию 1..1000."""
        assert surface[("privoxy", "audit", "report")]["limit"][1] == "int"

    @pytest.mark.parametrize(
        "argv",
        [
            ["install", "--state", "/tmp/s", "--prefix", "/tmp/p"],
            ["install", "--python", "/usr/bin/python3", "-y"],
            ["install", "--force-endpoint-overwrite"],
            ["status", "--launchagents-dir", "/tmp/la"],
            ["sync", "--xray-config", "/tmp/c"],
            ["routing", "list", "--outbound", "reality-out"],
            ["routing", "add-domain", "example.com", "--adopt"],
            ["privoxy", "protect", "--strict"],
            ["privoxy", "audit", "report", "--limit", "10", "--json"],
            ["privoxy", "audit", "uninstall", "--purge-log"],
        ],
    )
    def test_real_invocations_parse(self, parser, argv):
        """Реальные вызовы CLI. В #232 такие падали с SystemExit 2."""
        parser.parse_args(argv)


class TestDispatchContract:
    """Диспетчеризация идёт через set_defaults(func=...) и ведёт в живые команды."""

    @pytest.mark.parametrize(
        "argv,expected",
        [
            (["install"], "cmd_install"),
            (["uninstall"], "cmd_uninstall"),
            (["start"], "cmd_start"),
            (["stop"], "cmd_stop"),
            (["restart"], "cmd_restart"),
            (["status"], "cmd_status"),
            (["doctor"], "cmd_doctor"),
            (["sync"], "cmd_sync"),
            (["routing", "list"], "cmd_routing"),
            (["privoxy", "status"], "cmd_privoxy"),
            (["privoxy", "audit", "status"], "cmd_privoxy"),
        ],
    )
    def test_func_default_points_at_command(self, parser, argv, expected):
        args = parser.parse_args(argv)
        assert getattr(args, "func", None) is getattr(srouter, expected), (
            f"{'/'.join(argv)} не диспетчеризуется в {expected}"
        )

    def test_routing_reads_dests_the_parser_provides(self, parser):
        """В #232 парсер давал action/domain, а cmd_routing читал routing_subcommand/host."""
        args = parser.parse_args(["routing", "add-domain", "example.com"])
        src = inspect.getsource(srouter.cmd_routing)
        for attr in ("routing_subcommand", "host", "xray_config", "outbound", "adopt"):
            if f"args.{attr}" in src or f'"{attr}"' in src:
                assert hasattr(args, attr), (
                    f"cmd_routing читает {attr}, но парсер его не создаёт"
                )


class TestCommandsAreNotStubs:
    """Тела команд перенесены, а не заменены на print(TODO)."""

    @pytest.mark.parametrize("name", COMMAND_FUNCS)
    def test_no_todo_placeholder(self, name):
        src = inspect.getsource(getattr(srouter, name))
        assert "TODO" not in src, f"{name} — заглушка с TODO, тело не перенесено"

    @pytest.mark.parametrize("name", COMMAND_FUNCS)
    def test_body_does_real_work(self, name):
        """Заглушка отличается не длиной, а тем, что ничего не делает.

        Порог по числу строк был бы домыслом (живой cmd_doctor — всего 4 строки тела).
        Признак заглушки из #232: тело сводится к print+return, без единого вызова
        в доменную логику. Требуем, чтобы команда что-то ВЫЗЫВАЛА помимо print.
        """
        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(srouter, name))))
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and not (isinstance(n.func, ast.Name) and n.func.id == "print")
        ]
        assert calls, (
            f"{name}: тело состоит из print/return — заглушка, реализация не перенесена"
        )


class TestReexportIdentity:
    """re-export отдаёт ТОТ ЖЕ объект, что и модуль-владелец.

    Ловит двустороннюю делегацию: в #232 srouter импортировал cmd_* из srouter_cli
    и тут же определял свои cmd_*, а srouter_cli звал обратно srouter.__dict__[name].
    """

    @pytest.mark.parametrize("name", COMMAND_FUNCS + ["build_parser", "main"])
    def test_no_shadowing(self, name):
        srouter_cli = pytest.importorskip("srouter_cli")
        if not hasattr(srouter_cli, name):
            pytest.skip(f"{name} не в srouter_cli")
        assert getattr(srouter, name) is getattr(srouter_cli, name), (
            f"srouter.{name} и srouter_cli.{name} — разные объекты (затенение/делегация)"
        )

    def test_no_delegation_back_into_srouter(self):
        srouter_cli = pytest.importorskip("srouter_cli")
        src = inspect.getsource(srouter_cli)
        assert "from srouter import __dict__" not in src, (
            "srouter_cli делегирует обратно в srouter — циклическая зависимость"
        )
