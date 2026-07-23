"""ТДД-тесты централизованного marker-парсера (issue #176).

PR #175 (rename codex→codex-srouter) прошёл 4 цикла cycle-review подряд — каждый находил новую дыру
одного класса: marker-parsing / migration-coherence / ordered-pair. Корень — дублирование ordered-pair
в _install_codex_zsh_function и _remove_codex_zsh_function (две дословные копии count/find/ordered_pair),
каждая со своей неполной валидацией → рассинхрон → non-convergence (memory best-effort-layer-cycle-review-
never-converges).

Решение (этот issue): ВЕСЬ marker-parsing уходит в один чистый модуль marker_block.py с замкнутым
инвариантом. Любой count/find/ordered_pair ВНЕ marker_block.py = регрессия.

Канон: always-tdd (тесты на дыры ПЕРВЫМИ), no-hidden-magic-follow-canon. Покрытие класса разом —
property-based таблицей декартова произведения begins×ends×order (не по одной дыре за цикл).

Охват PR (остальное — другой формат, follow-up):
  - zsh-func begin/end парсер (find/replace/remove_managed_block)
  - classification по содержимому (is_managed_artifact, memory issue-144: wrapper ≠ binary)
  - target-gate (validate_target_installed)
PATH-marker (одиночный) и wrapper-migration оставлены вне scope.
"""
import os

import pytest

from marker_block import (
    ManagedBlock,
    find_managed_block,
    is_managed_artifact,
    remove_managed_block,
    replace_managed_block,
    validate_target_installed,
)

# Реальные маркеры из srouter.py — единый источник правды (memory no-hidden-magic-follow-canon).
# Дублируем строковые литералы здесь намеренно: тест не должен зависеть от импорта srouter (тяжёлый,
# тянет install_lib/dashboard_common), и должен ловить смену маркера в srouter как отдельный сигнал.
BEG = "# >>> srouter-managed-codex-function-v1 >>>"
END = "# <<< srouter-managed-codex-function-v1 <<<"
ARTIFACT_MARKER = "# srouter: codex CLI wrapper (managed)"

INNER = (
    'if (( ! ${+aliases[codex]} )); then\n'
    '  function codex {\n'
    '    "$HOME/bin/codex-srouter" "$@"\n'
    '  }\n'
    "fi\n"
)


def _block_text(begin: str = BEG, end: str = END, inner: str = INNER) -> str:
    """Готовый валидный managed-блок begin…end."""
    return f"{begin}\n{inner}{end}"


# ============================ find_managed_block: property-based таблица ============================
# Декартово произведение begins×ends×order — покрывает ВЕСЬ класс ordered-pair дыр разом, не по одной
# за cycle-review (cycle-3 reversed, cycle-4 duplicated, cycle-1 unpaired). Ожидание: ровно одна
# упорядоченная пара (begins==1 AND ends==1 AND begin_idx<end_idx) → ManagedBlock, иначе None.
@pytest.mark.parametrize("begins,ends,order,expect_found", [
    (0, 0, "fwd", False),   # нет блока
    (1, 1, "fwd", True),    # норма — единственная упорядоченная пара
    (1, 1, "rev", False),   # cycle-3/cycle-4: END перед BEGIN (count==1 each) → повреждено
    (2, 1, "fwd", False),   # duplicated BEGIN
    (1, 2, "fwd", False),   # duplicated END
    (2, 2, "fwd", False),   # дублированы оба
    (2, 0, "fwd", False),   # только BEGIN×2
    (0, 2, "fwd", False),   # только END×2
    (1, 0, "fwd", False),   # только BEGIN
    (0, 1, "fwd", False),   # только END
    (3, 1, "fwd", False),   # тройной BEGIN
    (1, 3, "fwd", False),   # тройной END
    (3, 3, "fwd", False),   # всё кратно
])
def test_find_managed_block_combinations(begins, ends, order, expect_found):
    """ВСЕ комбинации begins×ends×order → ровно одна упорядоченная пара или None (fail-closed)."""
    # Конструируем content: begins копий BEGIN + ends копий END, порядок fwd/rev влияет только при
    # count==1 каждого (проверяем реверс). При count>1 порядок не спасает — всё равно None.
    if begins == 1 and ends == 1:
        if order == "fwd":
            content = "header line\n" + _block_text() + "\ntrailer line\n"
        else:  # rev: END перед BEGIN
            content = "header line\n" + f"{END}\nbody\n{BEG}\n" + "\ntrailer line\n"
    else:
        parts = ["header line\n"]
        if order == "fwd":
            parts.extend([BEG] * begins + ["MID\n"] + [END] * ends)
        else:
            parts.extend([END] * ends + ["MID\n"] + [BEG] * begins)
        parts.append("\ntrailer line\n")
        content = "\n".join(parts)

    result = find_managed_block(content, BEG, END)

    if expect_found:
        assert result is not None, f"begins={begins},ends={ends},order={order}: ожидался блок"
        assert isinstance(result, ManagedBlock)
    else:
        assert result is None, (
            f"begins={begins},ends={ends},order={order}: повреждённое состояние должно дать None "
            f"(fail-closed), получил блок")


def test_find_managed_block_empty_content():
    """Пустой content → None (нет маркеров)."""
    assert find_managed_block("", BEG, END) is None


def test_find_managed_block_only_foreign_content():
    """content без маркеров → None (fresh path в caller)."""
    content = "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\n"
    assert find_managed_block(content, BEG, END) is None


def test_find_managed_block_indices_and_span():
    """Валидный блок: поля-индексы и span_text корректны и согласованы."""
    content = "pre\n" + _block_text() + "\npost\n"
    result = find_managed_block(content, BEG, END)
    assert result is not None

    # begin_idx указывает на BEGIN.
    assert content[result.begin_idx:].startswith(BEG)
    # end_idx указывает на END.
    assert content[result.end_idx:].startswith(END)
    # Упорядоченность.
    assert result.begin_idx < result.end_idx
    # end_idx_inclusive = end_idx + len(END).
    assert result.end_idx_inclusive == result.end_idx + len(END)
    # span_text — точная подстрока [begin_idx:end_idx_inclusive].
    assert content[result.begin_idx:result.end_idx_inclusive] == result.span_text
    # span_text обрамлён маркерами.
    assert result.span_text.startswith(BEG)
    assert result.span_text.endswith(END)


def test_find_managed_block_span_contains_inner():
    """span_text включает внутреннее содержимое блока (для target-gate инспекции в caller)."""
    content = _block_text()
    result = find_managed_block(content, BEG, END)
    assert result is not None
    assert '"$HOME/bin/codex-srouter" "$@"' in result.span_text


def test_find_managed_block_rejects_equal_markers():
    """Контракт: парные маркеры обязаны различаться (вырожденный begin==end → assert)."""
    with pytest.raises(AssertionError):
        find_managed_block("same\nsame\n", "same", "same")


# ============================ line-boundary invariant (cycle-review cycle-2 FIX, codex 0.99) ============================
# Маркеры — shell-комментарии (# ...). Если контент ПРИКЛЕЕН к маркеру в той же строке (без newline),
# он инертен (часть комментария). Парсер ОБЯЗАН считать это malformed-boundary → None (fail-closed):
# иначе remove_managed_block срежет блок по байтам END-маркера, оставив glued-суффикс standalone
# ИСПОЛНЯЕМОЙ строкой .zshrc → uninstall активирует ранее закомментированную команду (fail-open).
# Инвариант: end_marker обязан завершаться newline или EOF; begin_marker — начинаться на line-boundary
# (после newline или в начале content).
def test_find_managed_block_rejects_end_with_glued_trailing_content():
    """END-маркер + glued content без newline (ENDecho ...) → malformed → None.

    Воспроизведение codex critical: END+echo инертен (часть комментария) до remove; без line-boundary
    проверки remove оставил бы standalone исполняемую строку → fail-open активации закомментированного."""
    content = "pre\n" + _block_text() + "echo ACTIVATED\n"  # echo приклеен к END без newline
    assert find_managed_block(content, BEG, END) is None


def test_find_managed_block_rejects_begin_with_glued_leading_content():
    """Glued content перед BEGIN без newline (fooBEGIN ...) → malformed → None.

    Симметрия: BEGIN обязан начинаться на line-boundary (после newline/в начале), иначе slice может
    разрезать чужую строку."""
    content = "prefix-text" + BEG + "\nbody\n" + END + "\n"  # prefix приклеен к BEGIN
    assert find_managed_block(content, BEG, END) is None


def test_find_managed_block_accepts_end_at_eof():
    """END-маркер в самом EOF (без trailing newline) → валиден (EOF — это line-boundary)."""
    content = "pre\n" + _block_text()  # _block_text заканчивается END, без trailing \n
    result = find_managed_block(content, BEG, END)
    assert result is not None  # EOF — допустимая граница для END


def test_find_managed_block_accepts_end_followed_by_newline():
    """END-маркер + newline (обычный install-случай) → валиден."""
    content = "pre\n" + _block_text() + "\npost\n"
    assert find_managed_block(content, BEG, END) is not None


def test_find_managed_block_accepts_begin_at_content_start():
    """BEGIN в самом начале content (без preceding newline) → валиден (старт content — line-boundary)."""
    content = _block_text() + "\n"
    assert find_managed_block(content, BEG, END) is not None


# ============================ replace_managed_block ============================
def test_replace_managed_block_swaps_span():
    """replace_managed_block заменяет блок на new_span, сохраняя окружение."""
    content = "pre\n" + _block_text() + "\npost\n"
    block = find_managed_block(content, BEG, END)
    assert block is not None

    new_span = _block_text().replace('"$HOME/bin/codex-srouter"',
                                     '"$HOME/bin/codex"')  # миграция назад (демо)
    new_content = replace_managed_block(content, block, new_span)

    assert new_content.startswith("pre\n")
    assert new_content.endswith("\npost\n")
    assert '"$HOME/bin/codex"' in new_content
    assert '"$HOME/bin/codex-srouter"' not in new_content


def test_replace_managed_block_roundtrip_parser():
    """Свойство: replace_managed_block на тот же span_text → парсер находит эквивалентный блок."""
    content = "pre\n" + _block_text() + "\npost\n"
    block = find_managed_block(content, BEG, END)
    assert block is not None

    rewritten = replace_managed_block(content, block, block.span_text)
    again = find_managed_block(rewritten, BEG, END)
    assert again is not None
    assert again.span_text == block.span_text
    # Окружение не задето.
    assert rewritten.startswith("pre\n") and rewritten.endswith("\npost\n")


def test_replace_managed_block_none_raises():
    """block is None → ValueError (контракт: caller проверяет None до вызова)."""
    with pytest.raises(ValueError):
        replace_managed_block("content", None, "x")


# ============================ remove_managed_block ============================
def test_remove_managed_block_byte_for_byte_with_surrounding_newlines():
    """remove_managed_block убирает блок + зачищает окружающие \\n (канон srouter L792-795)."""
    # install добавляет "\n\n" + block + "\n"; remove должен дать чистый content без висячих строк.
    original = "export PATH=/usr/local/bin:$PATH\n"
    content = original.rstrip("\n") + "\n\n" + _block_text() + "\n"
    block = find_managed_block(content, BEG, END)
    assert block is not None

    removed = remove_managed_block(content, block)
    # Блок полностью убран.
    assert BEG not in removed and END not in removed
    # Маркеры и внутренности исчезли.
    assert '"$HOME/bin/codex-srouter"' not in removed
    # Окружение сохранено, ровно один trailing newline.
    assert removed.rstrip("\n") == original.rstrip("\n")
    assert removed.endswith("\n") and not removed.endswith("\n\n")


def test_remove_managed_block_preserves_foreign_content():
    """Чужой контент до/после блока — НЕ трогать (правило «чужое не трогаем»)."""
    foreign_before = "alias ll='ls -la'\n# user comment\n"
    foreign_after = "export FOO=bar\n"
    content = foreign_before + _block_text() + "\n" + foreign_after
    block = find_managed_block(content, BEG, END)
    assert block is not None

    removed = remove_managed_block(content, block)
    assert "alias ll='ls -la'" in removed
    assert "# user comment" in removed
    assert "export FOO=bar" in removed
    assert BEG not in removed and END not in removed


def test_remove_managed_block_block_only_content():
    """content = только блок → remove даёт чистую пустую строку (один trailing newline)."""
    content = _block_text() + "\n"
    block = find_managed_block(content, BEG, END)
    assert block is not None
    removed = remove_managed_block(content, block)
    assert removed == "\n"  # before пуст → rstrip → "\n"


def test_remove_managed_block_tight_trailing_is_fail_closed():
    """Tight-trailing (END + glued content без newline) → find_managed_block None → remove НЕ вызывается.

    cycle-review cycle-2 FIX (codex critical 0.99): ранее tight-trailing кодировал unsafe-transform —
    END+echo (инертен, часть комментария) после remove становился standalone исполняемой строкой →
    uninstall активировал закомментированную команду (fail-open). Теперь line-boundary invariant
    считает tight-trailing malformed → find_managed_block возвращает None → consumer оставляет .zshrc
    byte-for-byte нетронутым (fail-closed). Этот тест фиксирует новое безопасное поведение."""
    # pre\n + BLOCK + post (glued к END без newline) — malformed boundary.
    content = "pre\n" + _block_text() + "post\n"
    # find_managed_block обязан отвергнуть: glued-trailing → не валидный line-boundary.
    assert find_managed_block(content, BEG, END) is None
    # remove_managed_block не вызывается (block is None). Если бы caller вызвал — ValueError (контракт).
    # Потребитель (srouter._remove_codex_zsh_function) видит None → возвращает «повреждённый маркер»,
    # .zshrc остаётся нетронутым — это и есть fail-closed.


def test_remove_managed_block_none_raises():
    """block is None → ValueError."""
    with pytest.raises(ValueError):
        remove_managed_block("content", None)


# ============================ is_managed_artifact ============================
def test_is_managed_artifact_marker_present(tmp_path):
    """Файл с маркером в содержимом → True (memory issue-144: классификация по содержимому, не по имени)."""
    p = tmp_path / "codex-srouter"
    p.write_text(f"#!/bin/sh\n{ARTIFACT_MARKER}\nexec codex \"$@\"\n", encoding="utf-8")
    assert is_managed_artifact(p, ARTIFACT_MARKER) is True


def test_is_managed_artifact_marker_absent(tmp_path):
    """Файл БЕЗ маркера (real binary / чужой) → False (wrapper ≠ binary)."""
    p = tmp_path / "codex"
    p.write_text("#!/usr/bin/env node\nconsole.log('real binary');\n", encoding="utf-8")
    assert is_managed_artifact(p, ARTIFACT_MARKER) is False


def test_is_managed_artifact_str_path(tmp_path):
    """Принимает path как str (совместимость с _looks_like_managed_codex_wrapper(path: str))."""
    p = tmp_path / "codex-srouter"
    p.write_text(f"{ARTIFACT_MARKER}\n", encoding="utf-8")
    assert is_managed_artifact(str(p), ARTIFACT_MARKER) is True


def test_is_managed_artifact_missing_file():
    """Несуществующий файл → False (fail-closed, OSError подавлен)."""
    assert is_managed_artifact("/nonexistent/path/codex", ARTIFACT_MARKER) is False


def test_is_managed_artifact_marker_list_any(tmp_path):
    """markers как Iterable → True если есть ЛЮБОЙ из маркеров (расширяемость без API-дробления)."""
    p = tmp_path / "codex-srouter"
    legacy_marker = "# srouter: codex CLI wrapper (legacy)"
    p.write_text(f"{legacy_marker}\n", encoding="utf-8")
    # legacy_marker в файле → [current, legacy] срабатывает на legacy (any).
    assert is_managed_artifact(p, [ARTIFACT_MARKER, legacy_marker]) is True
    # ARTIFACT_MARKER в файле → [current, absent] срабатывает на current.
    p.write_text(f"{ARTIFACT_MARKER}\n", encoding="utf-8")
    assert is_managed_artifact(p, [ARTIFACT_MARKER, "absent-marker"]) is True
    # Ни одного маркера из списка в файле нет → False.
    p.write_text("plain content without markers\n", encoding="utf-8")
    assert is_managed_artifact(p, [ARTIFACT_MARKER, legacy_marker]) is False


def test_is_managed_artifact_empty_marker_list(tmp_path):
    """Пустой список маркеров → False (нечего искать)."""
    p = tmp_path / "codex-srouter"
    p.write_text(f"{ARTIFACT_MARKER}\n", encoding="utf-8")
    assert is_managed_artifact(p, []) is False


# ============================ validate_target_installed ============================
def test_validate_target_installed_ok(tmp_path):
    """is_file + executable + marker в содержимом → True."""
    p = tmp_path / "codex-srouter"
    p.write_text(f"#!/bin/sh\n{ARTIFACT_MARKER}\n", encoding="utf-8")
    p.chmod(0o755)
    assert validate_target_installed(p, ARTIFACT_MARKER) is True


def test_validate_target_installed_missing_file():
    """Файла нет → False."""
    assert validate_target_installed("/nonexistent/codex-srouter", ARTIFACT_MARKER) is False


def test_validate_target_installed_not_executable(tmp_path):
    """is_file + marker, но НЕ executable → False (target-gate требует X_OK)."""
    p = tmp_path / "codex-srouter"
    p.write_text(f"#!/bin/sh\n{ARTIFACT_MARKER}\n", encoding="utf-8")
    p.chmod(0o644)  # не executable
    assert os.access(p, os.X_OK) is False  # precondition
    assert validate_target_installed(p, ARTIFACT_MARKER) is False


def test_validate_target_installed_marker_absent(tmp_path):
    """is_file + executable, но БЕЗ маркера (real binary) → False."""
    p = tmp_path / "codex-srouter"
    p.write_text("#!/usr/bin/env node\nconsole.log('binary');\n", encoding="utf-8")
    p.chmod(0o755)
    assert validate_target_installed(p, ARTIFACT_MARKER) is False


def test_validate_target_installed_directory(tmp_path):
    """Путь — каталог (не файл) → False (is_file False)."""
    assert validate_target_installed(tmp_path, ARTIFACT_MARKER) is False


# ============================ интеграционное свойство: round-trip install→remove ============================
def test_install_remove_roundtrip_clean_content():
    """Свойство end-to-end на уровне парсера: append блока → remove → content без следов блока."""
    original = "export PATH=/usr/local/bin:$PATH\n"
    # install-style append.
    with_block = original.rstrip("\n") + "\n\n" + _block_text() + "\n"
    block = find_managed_block(with_block, BEG, END)
    assert block is not None, "блок найден после install-style append"

    removed = remove_managed_block(with_block, block)
    # Блока нет, окружение цело.
    assert BEG not in removed and END not in removed
    assert "export PATH=/usr/local/bin:$PATH" in removed
