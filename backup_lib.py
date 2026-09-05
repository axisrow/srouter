"""Единый примитивный слой бэкапов — контракт #339 v2, PR-1 (примитивы).

Что здесь: naming-контракт (единый источник суффиксов), атомарный create_backup,
discover (disk-доказательство существования поколений), каталог бэкапов собственных
артефактов srouter. Что здесь НЕТ: политика (когда бэкапить/восстанавливать/ротировать —
в потребителях; ротация — PR-2). root-helper этот модуль НЕ импортирует
(stdlib-only parity-гвард, канон root-helper-stdlib-only).

Типология (контракт v2, issue #339):
- generation — immutable копия ЧУЖОГО значения перед перезаписью; живёт рядом с целью,
  В ПАПКЕ ПРОЕКТА-ВЛАДЕЛЬЦА: `<target><BACKUP_INFIX><stamp>` (install-слой, ~/.zshrc);
- single-slot lease — sidecar `<target><SIDECAR_SUFFIX>` (claude/vscode, #328);
- собственные артефакты srouter — centralized: user → USER_BACKUPS_DIR, root →
  privoxy_system.AuditLayout.backup_root (двухуровневая симметрия user/root).

Поколение живёт в ИМЕНИ (stamp), не в manifest: backup обязан оставаться
самоописывающимся на диске (прецедент state-отрыва #124 — state-указатель оптимизация
адресации, не источник истины). Stamp-формат задаёт backup_stamp/env.now; разбор —
СТРОГО обратной операцией (probe-semantics-from-primary-source): не парсится — файл
создан не нами.
"""
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import local_state  # _fsync_parent_dir: канон fsync каталога после rename

# ---- naming-контракт: единый источник (PR-1 #339; прежде — дубли в install_config/claude/vscode) ----
BACKUP_INFIX = ".srouter-backup-"           # generation: <target><INFIX><stamp>
SIDECAR_SUFFIX = ".srouter-proxy-backup.json"  # single-slot lease (claude/vscode, #328)

# Каталог бэкапов СОБСТВЕННЫХ артефактов srouter, user-уровень (контракт v2 #339).
# Root-зеркало — privoxy_system.AuditLayout.backup_root
# (/Library/Application Support/srouter/backups/privoxy). Слоты под будущие нужды
# (pre-migration копия state при schema-bump, поколение собственного xray-конфига);
# потребители приходят со schema-bump (PR-план #339), константа — единый источник путей
# (канон #155/#165: никаких вторых источников тех же путей).
USER_BACKUPS_DIR = Path.home() / "Library" / "Application Support" / "srouter" / "backups"


def backup_stamp(now):
    """Timestamp-часть имени backup: env.now (ISO-8601 UTC-Z) без ':' ('/' → '-').

    Единственный источник формата stamp; парсинг — parse_stamp, строго обратной операцией."""
    return now.replace(":", "").replace("/", "-")


def parse_stamp(name):
    """'2026-06-29T000000Z' → datetime(UTC), иначе None.

    Разбор ОБРАТНОЙ операцией к backup_stamp (не «почти-regex» вроде \\d+): не парсится —
    значит файл создан не нами (loose-validator-recurring-leak)."""
    try:
        return datetime.strptime(name, "%Y-%m-%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_iso_utc(value):
    """Необрезанный ISO-8601 UTC-Z из state-полей (created_at) → datetime, иначе None.

    Отдельно от parse_stamp: state-поля хранят полный ISO (с ':') как обычные временные
    метки; обрезка нужна только в ИМЕНИ файла. Не парсится — поле повреждено/чужеродно,
    границу не применяем (fail-closed в сторону «не сужать» — отсутствие валидной границы
    не должно ложно отбрасывать настоящих кандидатов)."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def backup_path(target, now):
    """Путь generation-бэкапа для target со stamp от now (рядом с целью — контракт v2)."""
    target = Path(target)
    return target.with_name(target.name + BACKUP_INFIX + backup_stamp(now))


def sidecar_path(target):
    """Путь single-slot lease-бэкапа для target (рядом с целью; суффикс #328)."""
    target = Path(target)
    return target.parent / (target.name + SIDECAR_SUFFIX)


def create_backup(path, env):
    """Атомарная generation-копия path рядом с целью. str(путь) при успехе, "" при сбое.

    Канон atomic-save (local_state._atomic_write_text): НИКОГДА не пишем в финальное имя
    напрямую — copy2 во временный файл (tmp-хвост отсекается discover-парсером), fsync,
    затем os.replace + fsync каталога. Прежний shutil.copy2(path, <финальное имя>) в
    install_config._backup при обрыве посреди копии оставлял ЧАСТИЧНЫЙ файл под ВАЛИДНЫМ
    backup-именем — discover_backups засчитывала его как поколение (дыра PR-1 #339).
    copy2 сохраняет режим/время оригинала (семантика прежнего _backup).
    """
    p = Path(path)
    if not p.exists():
        return ""
    backup = backup_path(p, env.now)
    tmp = backup.with_name(backup.name + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, tmp)
        fd = os.open(tmp, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, backup)
        local_state._fsync_parent_dir(backup)
        return str(backup)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return ""


def discover(target):
    """Валидные generation-бэкапы target, лежащие рядом с ним, от старых к новым (#124).

    Disk-доказательство («какие бэкапы этого файла существуют»), не память state —
    перенос install_config.discover_backups без изменения семантики.

    FAIL-CLOSED: похожее имя ещё не делает файл нашим:
      - суффикс после BACKUP_INFIX обязан парситься parse_stamp (fullmatch по формату,
        не glob — отсекает хвостовой '.tmp' атомарной записи и вложенный двойной суффикс);
      - только regular file: симлинк с валидным именем — вектор подмены, директория — не бэкап.
    Сортировка по stamp детерминирована для воспроизводимых сообщений оператору, но НЕ
    для автовыбора «самого свежего»: при обрыве второго install свежий бэкап — копия
    srouter-конфига, а оригинал пользователя в самом старом (канон _resolve_backup)."""
    path = Path(target)
    try:
        candidates = list(path.parent.iterdir())
    except OSError:
        return []
    prefix = path.name + BACKUP_INFIX
    found = []
    for candidate in candidates:
        if not candidate.name.startswith(prefix):
            continue
        stamp = parse_stamp(candidate.name[len(prefix):])
        if stamp is None:
            continue
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
        except OSError:
            continue
        found.append((stamp, candidate))
    return [candidate for _stamp, candidate in sorted(found, key=lambda pair: (pair[0], pair[1].name))]
