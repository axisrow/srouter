"""StateManager: группировка функций управления local state для явного state-менеджмента.

Класс инкапсулирует операции над srouter.local.json — чтение, запись, валидация, синхронизация.
Сохраняет обратную совместимость через module-level функции-делегаты.

Создан для issue #160 (refactor: ввести классы ProbeManager/StateManager/PrivilegedOps).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class StateManager:
    """Менеджер local state — группирует операции над srouter.local.json.

    Все методы defensive: не бросают исключения при невалидном вводе, деградируют в empty/default.
    Path по умолчанию — рядом с модулем (не cwd), чтобы работал под launchd.
    """

    # Путь к локальному state по умолчанию — рядом с этим модулем, не cwd.
    _DEFAULT_PATH = Path(__file__).resolve().parent / "srouter.local.json"

    # D2: валидация хоста — только безопасные символы, shell-метасимволы запрещены.
    _HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]+\Z")
    _TRAFFIC_GUARD_MODES = {"on", "off", "auto"}
    _TRAFFIC_GUARD_POLICIES = {"block", "allow"}
    _TRAFFIC_GUARD_CHANNELS = {"wifi", "usb_tether", "metered"}
    _TRAFFIC_GUARD_AUTO_DOMAINS_ERROR = "traffic_guard.domains must define channel policies for auto mode"

    # Default state structure
    _DEFAULT_STATE: Dict[str, Any] = {
        "schema_version": 1,
        "nodes": [],
        "active_node": {"name": None, "pending": None},
        "probes": {},
        "network": {},
        "traffic_guard": {"mode": "off", "domains": {}},
        "detected_environment": {},
        "runtime": {"last_apply": None, "last_error": None},
    }

    def __init__(self, default_path: Optional[Path] = None):
        """Инициализировать StateManager.

        Args:
            default_path: Путь к srouter.local.json по умолчанию. Если None, используется путь рядом с модулем.
        """
        self.default_path = default_path or self._DEFAULT_PATH

    def _is_valid_host(self, host: Any) -> bool:
        """True если строка содержит только безопасные для shell символы."""
        return bool(isinstance(host, str) and self._HOST_RE.match(host))

    def _normalize_traffic_guard_domain(self, domain: Any) -> str:
        """Нормализовать domain-rule для exact+subdomain match; пустая строка значит reject."""
        if not isinstance(domain, str):
            return ""
        normalized = domain.strip().lower().rstrip(".")
        if not normalized or normalized.startswith(".") or ".." in normalized:
            return ""
        if ":" in normalized or not self._is_valid_host(normalized):
            return ""
        return normalized

    def _traffic_guard_domain_matches(self, candidate: Any, rule_domain: Any) -> bool:
        """Xray `domain:example.com` матчится на example.com и любые *.example.com."""
        candidate_norm = self._normalize_traffic_guard_domain(candidate)
        rule_norm = self._normalize_traffic_guard_domain(rule_domain)
        if not candidate_norm or not rule_norm:
            return False
        return candidate_norm == rule_norm or candidate_norm.endswith("." + rule_norm)

    def _normalize_traffic_guard_channel(self, channel: Any) -> str:
        """Нормализовать канал из #10/#11; пустая строка значит reject/unknown."""
        if not isinstance(channel, str):
            return ""
        normalized = channel.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in {"wifi", "wi_fi"}:
            return "wifi"
        if normalized in {"usb", "usb_tether", "usbtether"}:
            return "usb_tether"
        if normalized == "metered":
            return "metered"
        return ""

    def _validate_traffic_guard_domain_map(self, domains: Any, errors: List[str], context: str) -> Dict[str, str]:
        """Валидировать карту domain -> policy для Traffic Guard."""
        if domains is None:
            return {}
        if not isinstance(domains, dict):
            errors.append(f"{context} must be an object")
            return {}

        normalized = {}
        for domain, policy in domains.items():
            domain_norm = self._normalize_traffic_guard_domain(domain)
            if not domain_norm:
                errors.append(f"{context} domain is invalid: {domain!r}")
                continue
            if policy == "throttle":
                errors.append(f'{context} policy "throttle" is not supported in v1: {domain_norm}')
                continue
            if not isinstance(policy, str) or policy not in self._TRAFFIC_GUARD_POLICIES:
                errors.append(f'{context} policy must be "block" or "allow": {domain_norm}')
                continue
            previous = normalized.get(domain_norm)
            if previous is not None and previous != policy:
                errors.append(f"conflicting {context} policies for {domain_norm}: {previous} vs {policy}")
                continue
            normalized[domain_norm] = policy

        ordered = sorted(normalized.items(), key=lambda item: item[0].count("."))
        for index, (parent, parent_policy) in enumerate(ordered):
            for child, child_policy in ordered[index + 1 :]:
                if parent_policy != child_policy and self._traffic_guard_domain_matches(child, parent):
                    errors.append(f"conflicting {context} policies: {parent}={parent_policy} vs {child}={child_policy}")
        return normalized

    def validate_traffic_guard(self, guard: Any) -> List[str]:
        """Вернуть список явных ошибок Traffic Guard v1. Не бросает.

        mode:auto opt-in: domains становится картой channel -> domain policies.
        throttle по-прежнему отклоняется валидацией, а не молча приводится к другой семантике.
        """
        errors = []
        if guard is None or guard is False:
            return errors
        if not isinstance(guard, dict):
            return ["traffic_guard must be an object"]

        mode = guard.get("mode", "off")
        if not isinstance(mode, str) or mode not in self._TRAFFIC_GUARD_MODES:
            errors.append('traffic_guard.mode must be "on", "off", or "auto"')

        if mode == "auto":
            domains = guard.get("domains")
            self._validate_traffic_guard_channel_domains(domains, errors)
        else:
            domains = guard.get("domains")
            if domains is not None:
                self._validate_traffic_guard_domain_map(domains, errors, "traffic_guard.domains")
        return errors

    def _validate_traffic_guard_channel_domains(self, domains: Any, errors: List[str]) -> Dict[str, Dict[str, str]]:
        """Валидировать channel -> domain policies для mode:auto."""
        if domains is None:
            return {}
        if not isinstance(domains, dict):
            errors.append("traffic_guard.domains must be an object")
            return {}

        normalized = {}
        for channel, channel_domains in domains.items():
            channel_norm = self._normalize_traffic_guard_channel(channel)
            if not channel_norm:
                errors.append(f"traffic_guard channel is invalid: {channel!r}")
                continue
            if channel_norm in normalized:
                errors.append(f"duplicate traffic_guard channel: {channel_norm}")
                continue
            context = f"traffic_guard.domains.{channel_norm}"
            if not isinstance(channel_domains, dict):
                errors.append(f"{context} must be an object")
                continue
            before_error_count = len(errors)
            channel_map = self._validate_traffic_guard_domain_map(channel_domains, errors, context)
            if not channel_map and len(errors) == before_error_count:
                errors.append(f"{context} must define at least one policy")
                continue
            normalized[channel_norm] = channel_map
        return normalized

    def load_state(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Загрузить state из файла. Деградирует в default при ошибках, не бросает."""
        target_path = path or self.default_path
        try:
            if not target_path.exists():
                return dict(self._DEFAULT_STATE)
            text = target_path.read_text(encoding="utf-8")
            if not text:
                return dict(self._DEFAULT_STATE)
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return dict(self._DEFAULT_STATE)

    def load_state_checked(self, path: Optional[Path] = None) -> Tuple[Dict[str, Any], bool]:
        """Загрузить state с индикацией успешного чтения.

        Возвращает (state, readable). readable=False значит файл был сломан.
        """
        target_path = path or self.default_path
        try:
            if not target_path.exists():
                return dict(self._DEFAULT_STATE), True
            text = target_path.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                return data, True
        except (OSError, json.JSONDecodeError):
            pass
        return dict(self._DEFAULT_STATE), False

    def save_state(self, state: Dict[str, Any], path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Сохранить state в файл атомарно. Возвращает state при успехе, None при ошибке."""
        target_path = path or self.default_path
        try:
            text = json.dumps(state, indent=2, ensure_ascii=False)
            self._atomic_write_text(target_path, text)
            return state
        except (OSError, TypeError):
            return None

    def _atomic_write_text(self, path: Path, text: str) -> None:
        """Атомарно записать текст в файл через temp + rename."""
        import tempfile
        import shutil

        temp_path = None
        try:
            # Создаём temp файл рядом с целевым (той же файловой системой)
            fd, temp_path = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
            try:
                os.write(fd, text.encode("utf-8"))
            finally:
                os.close(fd)
                # fsync для гарантии записи на диск
                try:
                    os.fsync(fd)
                except OSError:
                    pass  # fsync не на всех filesystem'ах поддерживается

            # Атомарный rename поверх существующего
            shutil.move(temp_path, path)
        except (OSError, TypeError):
            if temp_path and Path(temp_path).exists():
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

    def load_nodes(self, path: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Загрузить список nodes из state."""
        state = self.load_state(path)
        return state.get("nodes", []) if isinstance(state, dict) else []

    def get_node(self, name: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Получить node по имени."""
        nodes = self.load_nodes(path)
        for node in nodes:
            if isinstance(node, dict) and node.get("name") == name:
                return node
        return None

    def enabled_nodes(self, path: Optional[Path] = None) -> List[str]:
        """Получить список имён включенных nodes."""
        nodes = self.load_nodes(path)
        result: List[str] = []
        for node in nodes:
            if isinstance(node, dict):
                name = node.get("name")
                if isinstance(name, str) and name:
                    result.append(name)
        return result

    def preflight_state_write(self, path: Optional[Path] = None) -> bool:
        """Проверить, что state можно записать (пробная запись). Issue #68."""
        target_path = path or self.default_path
        try:
            state = self.load_state(target_path)
            return self.save_state(state, target_path) is not None
        except (OSError, TypeError):
            return False


# ============================ Обратная совместимость ============================
# Module-level функции делегируют глобальному экземпляру StateManager.

_default_manager = StateManager()


def validate_traffic_guard(guard: Any) -> List[str]:
    """Вернуть список явных ошибок Traffic Guard v1. Не бросает."""
    return _default_manager.validate_traffic_guard(guard)


def load_state(path: Optional[Path] = None) -> Dict[str, Any]:
    """Загрузить state из файла. Деградирует в default при ошибках, не бросает."""
    return _default_manager.load_state(path)


def load_state_checked(path: Optional[Path] = None) -> Tuple[Dict[str, Any], bool]:
    """Загрузить state с индикацией успешного чтения."""
    return _default_manager.load_state_checked(path)


def save_state(state: Dict[str, Any], path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Сохранить state в файл атомарно. Возвращает state при успехе, None при ошибке."""
    return _default_manager.save_state(state, path)


def load_nodes(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Загрузить список nodes из state."""
    return _default_manager.load_nodes(path)


def get_node(name: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Получить node по имени."""
    return _default_manager.get_node(name, path)


def enabled_nodes(path: Optional[Path] = None) -> List[str]:
    """Получить список имён включенных nodes."""
    return _default_manager.enabled_nodes(path)


def preflight_state_write(path: Optional[Path] = None) -> bool:
    """Проверить, что state можно записать (пробная запись)."""
    return _default_manager.preflight_state_write(path)


# Константы для обратной совместимости (экспортируются для использования в других модулях)
_DEFAULT_STATE = _default_manager._DEFAULT_STATE
_DEFAULT_PATH = _default_manager.default_path