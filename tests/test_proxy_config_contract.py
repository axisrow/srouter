"""ТДД-тесты proxy_config_contract — общий слой классификации состояния прокси-ключа (issue #307).

Проблема: enable() всех трёх consumer-модулей (git_proxy/claude_proxy/vscode_proxy) безусловно
перезаписывает чужое/ручное значение прокси-ключа, а status() рапортует configured=false, что
на панели выглядит как «не настроено» — клик «Включить» выглядит безопасным, но уничтожает
чужую настройку (корпоративная политика, другой прокси-менеджер).

Канон privileged-boundary-fail-closed (эталон CSRF #58): чужое значение reject'ится безусловно,
молчаливая перезапись недопустима. Классификация — общий слой (канон
third-module-breaks-reexport-cycle), НЕ re-export через один из модулей.
"""
import proxy_config_contract as pcc


class TestClassify:
    def test_absent_when_key_not_present(self):
        assert pcc.classify(present=False, value="", managed="socks5://x") == pcc.ABSENT

    def test_managed_on_when_value_equals_managed(self):
        assert pcc.classify(present=True, value="socks5://x", managed="socks5://x") == pcc.MANAGED_ON

    def test_foreign_when_value_differs(self):
        """ЯДРО #307: чужое значение — ОТДЕЛЬНОЕ состояние, не «не настроено»."""
        assert pcc.classify(present=True, value="http://corp:3128", managed="socks5://x") == pcc.FOREIGN

    def test_empty_present_value_is_foreign_not_absent(self):
        """Канон presence != truthy (issue #222): пустая строка при present — валидный чужой
        override («ключ есть, но пустой»), а не отсутствие ключа."""
        assert pcc.classify(present=True, value="", managed="socks5://x") == pcc.FOREIGN


class TestAggregate:
    def test_uniform_states_pass_through(self):
        assert pcc.aggregate([pcc.ABSENT, pcc.ABSENT]) == pcc.ABSENT
        assert pcc.aggregate([pcc.MANAGED_ON]) == pcc.MANAGED_ON
        assert pcc.aggregate([pcc.FOREIGN, pcc.FOREIGN]) == pcc.FOREIGN

    def test_absent_plus_managed_on_is_managed_on(self):
        """Файл отсутствует = редактор не установлен (vscode: Code есть, Cursor нет) —
        это не конфликт и не mixed."""
        assert pcc.aggregate([pcc.ABSENT, pcc.MANAGED_ON]) == pcc.MANAGED_ON

    def test_absent_plus_foreign_is_foreign(self):
        assert pcc.aggregate([pcc.ABSENT, pcc.FOREIGN]) == pcc.FOREIGN

    def test_managed_on_plus_foreign_is_mixed(self):
        """VSCode mixed: в Code — наше значение, в Cursor — чужое."""
        assert pcc.aggregate([pcc.MANAGED_ON, pcc.FOREIGN]) == pcc.MIXED

    def test_managed_off_style_mix_managed_and_absent_variants(self):
        assert pcc.aggregate([pcc.MANAGED_ON, pcc.MANAGED_ON, pcc.ABSENT]) == pcc.MANAGED_ON

    def test_unknown_wins(self):
        """Не смогли прочитать один из файлов — общий state неизвестен (verify-dont-guess:
        неизвестность не схлопывается ни в одно перечислимое состояние)."""
        assert pcc.aggregate([pcc.MANAGED_ON, pcc.UNKNOWN]) == pcc.UNKNOWN


class TestConflictContract:
    def test_conflict_states(self):
        assert pcc.needs_force(pcc.FOREIGN) is True
        assert pcc.needs_force(pcc.MIXED) is True
        assert pcc.needs_force(pcc.ABSENT) is False
        assert pcc.needs_force(pcc.MANAGED_ON) is False
        assert pcc.needs_force(pcc.UNKNOWN) is False
