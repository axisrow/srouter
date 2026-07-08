"""Извлечь конкретные JS-функции из static/index.html для node-тестов.

Без DOM/фреймворка: находим `function <name>(` и берём тело до сбалансированной `}`.
Достаточно для чистых render-функций (t/renderFlow/flowNode/dnsCardStatus и т.п.).
"""
from pathlib import Path

_HTML_PATH = Path(__file__).resolve().parent.parent / "static" / "index.html"
HTML = _HTML_PATH.read_text(encoding="utf-8")


def _extract_one(src, name):
    marker = "function " + name + "("
    i = src.find(marker)
    if i == -1:
        raise AssertionError(f"функция {name}() не найдена в static/index.html")
    # найти '{' начала тела
    brace = src.find("{", i)
    if brace == -1:
        raise AssertionError(f"тело {name}() не найдено")
    depth = 0
    in_str = None      # активная кавычка ' " `
    in_comment = None  # 'line' | 'block'
    escaped = False
    j = brace
    while j < len(src):
        ch = src[j]
        nxt = src[j + 1] if j + 1 < len(src) else ""
        if in_comment == "line":
            if ch == "\n":
                in_comment = None
        elif in_comment == "block":
            if ch == "*" and nxt == "/":
                in_comment = None
                j += 1
        elif in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_str:
                in_str = None
        else:
            # Комментарии (могут содержать `, {, } — их нельзя считать кодом).
            if ch == "/" and nxt == "/":
                in_comment = "line"
                j += 1
            elif ch == "/" and nxt == "*":
                in_comment = "block"
                j += 1
            elif ch in ("'", '"', "`"):
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return src[i:j + 1]
        j += 1
    raise AssertionError(f"несбалансированные скобки в {name}()")


def extract_functions(src, names):
    """Вернуть склеенный JS-исходник перечисленных функций (в порядке names)."""
    return "\n".join(_extract_one(src, n) for n in names)
