"""Централизованный marker-парсер srouter (issue #176).

Единый источник правды для marker-parsing. Закрывает класс дыр PR #175 (4 цикла cycle-review подряд,
каждый находил новую дыру одного класса — ordered-pair / migration-coherence / resolver-classification).
Корень non-convergence (memory best-effort-layer-cycle-review-never-converges): ordered-pair parsing
дублировался дословно в _install_codex_zsh_function и _remove_codex_zsh_function, каждая со своей
неполной валидацией → рассинхрон. Здесь — ОДИН парсер с замкнутым инвариантом.

Контракт: ЛЮБОЙ marker-parsing (count/find/ordered-pair/span reconstruction) ВНЕ этого модуля = регрессия.

Слой чистый: find/replace/remove_managed_block — чистые string-функции (без I/O, без импортов
install_lib/srouter). I/O только в is_managed_artifact/validate_target_installed. stdlib-only
(dataclasses, os, pathlib, typing) — модуль НЕ зависит от остального srouter → нет цикла, безопасен
для упаковки в wheel (см. test_pyproject_modules).

Канон: no-hidden-magic-follow-canon (повторять принятый паттерн), issue-112-hybrid-uninstall-provenance
(provenance/migration known_markers), issue-144-wrapper-runtime-resolve (wrapper ≠ binary, классификация
по содержимому). Охват: zsh-func begin/end парсер + classification + target-gate. PATH-marker (одиночный)
и wrapper-migration — другой формат, вне scope (follow-up).
"""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union

__all__ = [
    "ManagedBlock",
    "find_managed_block",
    "replace_managed_block",
    "remove_managed_block",
    "is_managed_artifact",
    "validate_target_installed",
]


@dataclass(frozen=True)
class ManagedBlock:
    """Результат find_managed_block — ровно одна упорядоченная пара маркеров.

    Поля — байтовые индексы в исходной строке content (immutable контракт: один find → неизменяемый
    результат, frozen не даёт случайно мутировать begin/end после валидации).

      begin_idx        : индекс первого символа begin_marker в content.
      end_idx          : индекс первого символа end_marker в content.
      end_idx_inclusive: индекс символа СЛЕДУЮЩЕГО за последним символом end_marker
                         (= end_idx + len(end_marker)); content[begin_idx:end_idx_inclusive] == span_text.
      span_text        : подстрока content[begin_idx:end_idx_inclusive] (включая оба маркера),
                         для инспекции target-строк в caller (target-gate, migration codex→codex-srouter).
    """
    begin_idx: int
    end_idx: int
    end_idx_inclusive: int
    span_text: str


def find_managed_block(content: str, begin_marker: str, end_marker: str) -> Optional[ManagedBlock]:
    """Найти в content ровно ОДНУ упорядоченную пару begin_marker...end_marker.

    Инвариант (замыкает cycle-3/cycle-4 FIX ordered-pair, дословно дублированный в 2 местах ранее):
        begins == 1 AND ends == 1 AND 0 <= begin_idx < end_idx
    иначе → None (повреждено/непарно/реверснуто → fail-closed: лучше сломать, чем широкой нарезкой
    дублировать контент .zshrc под видом успеха).

    Returns:
        ManagedBlock — если ровно одна упорядоченная пара целых строк.
        None         — если НЕТ ни одного маркера (begins==0 AND ends==0) ИЛИ если пара повреждена
                       (любой другой count/order ИЛИ маркер не занимает целую строку — partial-line).
                       НЕ различает «нет блока» и «повреждено» в return value — различение для
                       диагностического сообщения оставлено caller'у через один доп. `marker in content`
                       чек (решение = fail-closed в обоих случаях).

    Precondition: begin_marker != end_marker (парные маркеры обязаны различаться) И ни один маркер
    не содержит \\n (whole-line matching). Вырожденные случаи ловятся assert — это баг caller'а,
    не валидный контракт.
    """
    assert begin_marker != end_marker, "парные маркеры обязаны различаться (begin==end — баг caller)"
    # cycle-review cycle-3: маркер обязан быть ОДНОЙ строкой (без \n). Whole-line matching (ниже)
    # с newline-bearing маркером бессмысленен — это невалидный контракт caller'а.
    assert "\n" not in begin_marker and "\n" not in end_marker, \
        "маркер обязан быть одной строкой без \\n (whole-line matching)"
    begins = content.count(begin_marker)
    ends = content.count(end_marker)
    if not (begins == 1 and ends == 1):
        return None
    begin_idx = content.find(begin_marker)
    end_idx = content.find(end_marker)
    if not (0 <= begin_idx < end_idx):  # упорядоченность: begin строго перед end (реверс → None).
        return None
    # cycle-review cycle-2/cycle-3 FIX (codex critical 0.99) — WHOLE-LINE invariant: каждый маркер
    # обязан занимать ЦЕЛУЮ строку целиком (от line-start до \n/EOF с обеих сторон). Маркеры —
    # shell-комментарии (# ...); контент glued к маркеру в той же строке инертен (часть комментария).
    # Cycle-2 закрыл 2 стороны (char-before-BEGIN, char-after-END); cycle-3 закрыл оставшиеся 2
    # (char-after-BEGIN, char-before-END) — иначе partial-line marker заставлял remove_managed_block
    # удалить intervening чужой контент .zshrc (silent data-loss без backup) ИЛИ активировать
    # закомментированную команду (fail-open). Whole-line проверяет все 4 стороны разом:
    #   - строка маркера = ровно marker (ничем не обрамлён в той же строке).
    # Иначе → None (malformed boundary, fail-closed: consumer оставляет .zshrc byte-for-byte нетронутым).
    def _is_whole_line(idx: int, marker: str) -> bool:
        # Левая граница: idx==0 (старт content) ИЛИ content[idx-1]=='\n' (после newline).
        left_ok = (idx == 0) or (content[idx - 1] == "\n")
        # Правая граница: за маркером '\n' ИЛИ EOF (idx+len == len(content)).
        after = idx + len(marker)
        right_ok = (after == len(content)) or (content[after] == "\n")
        return left_ok and right_ok
    if not (_is_whole_line(begin_idx, begin_marker) and _is_whole_line(end_idx, end_marker)):
        return None  # partial-line marker (glued suffix/prefix) → malformed → fail-closed.
    end_idx_inclusive = end_idx + len(end_marker)
    span_text = content[begin_idx:end_idx_inclusive]
    return ManagedBlock(begin_idx=begin_idx, end_idx=end_idx,
                        end_idx_inclusive=end_idx_inclusive, span_text=span_text)


def replace_managed_block(content: str, block: ManagedBlock, new_span: str) -> str:
    """Вернуть новый content, где block заменён на new_span. Чистая, без I/O.

    new_span может содержать маркеры (как migration: span.replace('codex','codex-srouter')) или быть
    совсем другим (апгрейд блока). Окружение content[:begin_idx] и content[end_idx_inclusive:] сохранено.

    block is None → ValueError: контракт требует от caller'а проверить None до вызова (не молчаливый
    возврат content — это поймало бы логическую ошибку «replace без find», оставив повреждённое состояние).
    """
    if block is None:
        raise ValueError("replace_managed_block требует валидный ManagedBlock (получен None)")
    return content[:block.begin_idx] + new_span + content[block.end_idx_inclusive:]


def remove_managed_block(content: str, block: ManagedBlock) -> str:
    """Вернуть новый content без блока + зачистка окружающих \\n. Чистая, без I/O.

    Byte-for-byte совместимо с прежним remove-кодом srouter (L792-795 до #176):
        before = content[:begin_idx].rstrip("\\n")
        out = before + ("\\n" if before else "") + content[end_idx_inclusive:]
        return out.rstrip() + "\\n"
    Зачистка пустых строк нужна: install добавляет "\\n\\n" + block + "\\n" — без rstrip осталось бы
    две висячие пустые строки. block is None → ValueError (контракт, как в replace).
    """
    if block is None:
        raise ValueError("remove_managed_block требует валидный ManagedBlock (получен None)")
    before = content[:block.begin_idx].rstrip("\n")
    out = before + ("\n" if before else "") + content[block.end_idx_inclusive:]
    return out.rstrip() + "\n"


def is_managed_artifact(path: Union[str, Path], markers: Union[str, Iterable[str]]) -> bool:
    """Содержит ли файл ЛЮБОЙ из markers (хотя бы один)?

    Маркер ищем в СОДЕРЖИМОМ файла, НЕ в path/name (memory issue-144: wrapper ≠ binary — один и тот же
    файл может зваться codex как wrapper и как real binary; признак «managed» = маркер внутри, не имя).
    Заменяет _looks_like_managed_codex_wrapper(path) = is_managed_artifact(path, MARKER).

    markers: str → один маркер; Iterable[str] → ЛЮБОЙ из (any, для future legacy-marker migration).
    Пустой Iterable → False. OSError (нет файла/нет прав) → False (fail-closed, как прежняя обёртка).
    """
    marker_list = [markers] if isinstance(markers, str) else list(markers)
    if not marker_list:
        return False
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return False
    return any(m in text for m in marker_list)


def validate_target_installed(path: Union[str, Path], marker: str) -> bool:
    """path: is_file + executable (X_OK) + marker в содержимом? (target-gate).

    Заменяет тело _codex_zsh_target_installed. Единый критерий «target валиден» для ВСЕХ путей install
    (legacy-preservation, zsh-migration, fresh-create) — нет рассинхрона между ними (cycle-2/3/4 FIX).
    OSError → False. marker: str (один — контракт target'а).
    """
    p = Path(path)
    try:
        if not (p.is_file() and os.access(p, os.X_OK)):
            return False
        text = p.read_text(encoding="utf-8")
    except OSError:
        return False
    return marker in text
