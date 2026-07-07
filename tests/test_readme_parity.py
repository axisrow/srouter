"""Docs-parity: README не должен обещать того, чего нет в коде (issue #82, #13/#14).

Это не стилистика — это proof, что «ready»-заявления README отображаются на реальные
команды/API. Каждый тест привязан к первоисточнику в коде:
  • bootstrap srouter_config.py — dashboard_common.py требует его (иначе SystemExit);
  • CHANNEL_TARGETS = ("wifi", "usb") — Bluetooth-канала в коде нет;
  • node_selector: recommendation()+ручной select_node, «Автопереключения здесь нет».
"""
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _sections():
    """Разбить README на RU- и EN-половины по якорю английской версии."""
    marker = "# srouter — smart router (English)"
    idx = README.find(marker)
    assert idx != -1, "не найден якорь английской версии README"
    return README[:idx], README[idx:]


# ---------- #13: bootstrap srouter_config.py в install-разделе (RU и EN) ----------

def test_channel_targets_are_only_wifi_and_usb():
    """Sanity: код действительно даёт только wifi/usb — иначе тесты про Bluetooth неверны."""
    common = (ROOT / "dashboard_common.py").read_text(encoding="utf-8")
    m = re.search(r"CHANNEL_TARGETS\s*=\s*\(([^)]*)\)", common)
    assert m, "не найден CHANNEL_TARGETS в dashboard_common.py"
    targets = {t.strip().strip("'\"") for t in m.group(1).split(",") if t.strip()}
    assert targets == {"wifi", "usb"}, f"targets изменились: {targets}"


def test_readme_ru_install_has_config_bootstrap_step():
    ru, _ = _sections()
    install_idx = ru.find("## Установка")
    assert install_idx != -1, "не найден RU install-раздел"
    # Шаг копирования шаблона должен быть в install-разделе (а не только в PF/прочем).
    install_block = ru[install_idx:]
    assert "cp srouter_config.example.py srouter_config.py" in install_block, (
        "RU install-раздел не показывает bootstrap srouter_config.py — свежий пользователь "
        "по README не создаст конфиг и словит SystemExit из dashboard_common.py"
    )


def test_readme_en_install_has_config_bootstrap_step():
    _, en = _sections()
    install_idx = en.find("## Install")
    assert install_idx != -1, "не найден EN install-раздел"
    install_block = en[install_idx:]
    assert "cp srouter_config.example.py srouter_config.py" in install_block, (
        "EN install section is missing the srouter_config.py bootstrap step"
    )


# ---------- #14: README не переобещает auto-failover и Bluetooth ----------
#
# Находка #14 разрешает два исхода: убрать фичу ИЛИ явно пометить roadmap/experimental.
# Поэтому проверяем построчно: упоминание в roadmap-строке (с явным маркером «в планах» /
# «roadmap» / «no auto‑failover») — допустимо; упоминание в утвердительной строке — overclaim.

# Маркеры «это ещё не готово» — строки с ними НЕ считаются обещанием готовности.
_ROADMAP_MARKERS = (
    "в планах",
    "roadmap",
    "no auto‑failover",
    "no auto-failover",
    "автопереключения в v1 нет",
    "в v1 автопереключения нет",
)

# Фразы-обещания node auto-failover как готовой фичи.
_AUTOFAILOVER_CLAIMS = (
    "авто‑переключение",
    "авто-переключение",
    "автоматически уходит на следующий лучший узел",
    "auto‑failover",
    "auto-failover",
    "traffic shifts to the next best automatically",
)

# Фразы-обещания Bluetooth-канала как готового.
_BLUETOOTH_CLAIMS = (
    "bluetooth‑tethering",
    "bluetooth-tethering",
    "bluetooth tethering",
    "bluetooth-тел",
)


def _offending_lines(claims):
    """Блоки README, где встречается claim и НЕТ roadmap-маркера.

    Разбиваем по пустой строке (абзац / буллет / строка таблицы): claim и его roadmap-пометка
    живут в одной логической единице, даже если markdown перенёс их на разные физические строки.
    """
    offending = []
    # Гранулярность = один markdown-буллет ИЛИ абзац. Разбиваем по пустой строке И по началу
    # буллета ('\n- '): иначе весь список Self-optimization слипается в один блок, и roadmap-маркер
    # из одного буллета замаскировал бы overclaim из соседнего (ложноотрицательный тест).
    blocks = re.split(r"\n\s*\n|\n(?=- )", README)
    for block in blocks:
        # Схлопываем переносы внутри блока: markdown рвёт длинные строки, и claim или его
        # roadmap-маркер могут оказаться разбиты («в\nпланах») — нормализуем перед поиском.
        low = " ".join(block.split()).lower()
        if any(c in low for c in claims) and not any(m in low for m in _ROADMAP_MARKERS):
            offending.append(low[:200])
    return offending


def test_readme_does_not_promise_node_auto_failover():
    """node_selector.py: «Автопереключения здесь нет» — README обещает failover только как roadmap."""
    selector = (ROOT / "node_selector.py").read_text(encoding="utf-8")
    assert "Автопереключения здесь нет" in selector, "изменилась семантика node_selector"

    offending = _offending_lines(_AUTOFAILOVER_CLAIMS)
    assert not offending, (
        "README обещает node auto-failover как готовую фичу (нет roadmap-пометки), "
        f"хотя node_selector даёт recommendation + ручной select_node:\n" + "\n".join(offending)
    )


def test_readme_does_not_present_bluetooth_as_ready_channel():
    """Bluetooth-канала в коде нет (CHANNEL_TARGETS = wifi/usb) — только как roadmap."""
    offending = _offending_lines(_BLUETOOTH_CLAIMS)
    assert not offending, (
        "README подаёт Bluetooth-канал как готовый (нет roadmap-пометки); реальные targets — wifi/usb:\n"
        + "\n".join(offending)
    )
