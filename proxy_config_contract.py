"""Общий слой классификации состояния прокси-ключа потребителя (issue #307).

Проблема: enable() в git_proxy/claude_proxy/vscode_proxy безусловно перезаписывает чужое/
ручное значение прокси-ключа, а status() рапортует enabled=False — на панели «не настроено»,
клик «Включить» выглядит безопасным, но уничтожает чужую настройку (корпоративная политика,
другой прокси-менеджер).

Канон privileged-boundary-fail-closed (эталон CSRF #58): чужое значение reject'ится
безусловно, молчаливая перезапись недопустима. Перезапись — только через явный force-путь.

Контракт (единый для всех трёх consumer-модулей):

  state ∈ ABSENT | MANAGED_ON | FOREIGN | MIXED | UNKNOWN

  - ABSENT     — ключа нет (включая «наш, но выключенный»: мы не оставляем маркеров в
                 чужом конфиге, и для безопасности различие не нужно — enable на absent
                 безвреден, disable на foreign отказан value-match'ем);
  - MANAGED_ON — ровно наше управляемое значение;
  - FOREIGN    — присутствует чужое значение (включая пустую строку — канон presence !=
                 truthy, issue #222);
  - MIXED      — у потребителя несколько слотов (vscode: settings.json разных редакторов)
                 и состояния неоднородны (напр. managed-on + foreign);
  - UNKNOWN    — конфиг не прочитан (не схлопывается ни в одно перечислимое состояние —
                 verify-dont-guess).

  enable(force=False): state ∈ {FOREIGN, MIXED} и не force -> {ok: False, conflict: True,
  state} БЕЗ мутации. force=True — осознанная перезапись (панель показывает confirm).
  absent/managed-on — идемпотентный ok без force.

  disable(): удаляет/трогает ТОЛЬКО значение == наш managed PROXY (value-match provenance,
  #112); чужое не удаляет никогда.

Почему отдельный модуль, а не re-export через один из трёх: канон
third-module-breaks-reexport-cycle — общий слой, а не делегация; все три модуля импортируют
его снизу, циклов нет (модуль ничего не импортирует из проекта). Это dashboard-модули, НЕ
root-helper (там свой stdlib-only паритет — shared-код туда не тащить).
"""

ABSENT = "absent"
MANAGED_ON = "managed-on"
FOREIGN = "foreign"
MIXED = "mixed"
UNKNOWN = "unknown"

# Состояния, при которых enable() без force — легитимная идемпотентная операция.
_SAFE_FOR_ENABLE = (ABSENT, MANAGED_ON)


def classify(present, value, managed):
    """Состояние ОДНОГО слота (одного ключа/одного файла). Чистая функция.

    present=False -> ABSENT независимо от value; пустое значение при present — FOREIGN
    («ключ есть, но пустой» — валидный чужой override, канон issue #222).
    """
    if not present:
        return ABSENT
    if value == managed:
        return MANAGED_ON
    return FOREIGN


def aggregate(states):
    """Свести состояния нескольких слотов в одно. Чистая функция.

    - любой UNKNOWN -> UNKNOWN (не знаем всего — не утверждаем ничего);
    - ABSENT — «слот не существует» (файл/редактор отсутствует), НЕ участник конфликта:
      [absent, managed-on] -> managed-on, [absent, foreign] -> foreign;
    - однородные -> это состояние;
    - иначе (управляемое вперемешку с чужим) -> MIXED.
    """
    states = list(states)
    if not states:
        return ABSENT
    if any(s == UNKNOWN for s in states):
        return UNKNOWN
    present = [s for s in states if s != ABSENT]
    if not present:
        return ABSENT
    unique = set(present)
    if len(unique) == 1:
        return unique.pop()
    return MIXED


def needs_force(state):
    """enable() на это состояние требует явного force=True (конфликт чужого значения)."""
    return state in (FOREIGN, MIXED)


def conflict_result(state):
    """Стандартизированный отказ enable() на foreign/mixed: ok=False + явный conflict-флаг.
    err — человекочитаемая причина (панель покажет её в toast до confirm-диалога force)."""
    return {
        "ok": False,
        "conflict": True,
        "state": state,
        "err": (f"обнаружено ЧУЖОЕ значение прокси-ключа (state={state}); перезапись "
                "требует явного force=True — молчаливая перезапись чужой настройки "
                "запрещена (issue #307)"),
    }
