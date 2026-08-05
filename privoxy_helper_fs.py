"""Fd-pinning файловые примитивы root-helper'а (issue #287, tree-copy redesign).

АРХИТЕКТУРНЫЙ ИНВАРИАНТ: этот модуль — часть root-owned helper-дерева, копируется
tree-copy install'ом в /Library/PrivilegedHelperTools рядом с privoxy_system.py
(entrypoint) и исполняется изолированно через sudo. Как и privoxy_system.py, он
использует ТОЛЬКО stdlib (каноны root-helper-stdlib-only-no-shared-imports,
helper-stdlib-only-no-dashboard-common) — НЕ импортирует dashboard_common/
srouter_config/local_state и т.п. Helper-модули МОГУТ импортировать друг друга
(этот файл — листовой, без helper-side зависимостей), но не любой модуль основного
процесса srouter.

Все функции здесь — TOCTOU-свободные fd-pinning примитивы: atomic write,
race-free чтение regular-файлов, fd-relative рекурсивное копирование дерева,
symlink-rejection. Полная история инвариантов (почему path-based chmod/chown
после fdopen-close небезопасен, почему lstat-then-copy оставляет TOCTOU-окно,
почему openat через уже открытый dir_fd закрывает повторное path-resolution)
описана в docstring каждой функции — перенесена без изменений из privoxy_system.py
при декомпозиции (issue #287), логика идентична.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile


def _fchown_if_privileged(fd, uid, gid):
    """fchown по fd ТОЛЬКО под root. fd-pinning (#148): метаданные выставляются по fd,
    а не по пути — закрывает TOCTOU arbitrary-chown (path-based chown следует symlink).

    Под non-root (тесты без sudo) fchown(0,0) дал бы EPERM и пропускается: реальный
    chown невозможен без привилегий, security-инвариант не нарушается (production
    helper всегда работает под root через sudo — там fchown обязателен и выполнится).
    """
    if os.geteuid() != 0:
        return
    os.fchown(fd, uid, gid)


def _atomic_write(path, data, *, mode, uid=0, gid=0, chown=os.chown):
    """Race-free atomic write: непредсказуемое temp-имя + O_EXCL + fchmod/fchown по fd.

    Прежний temp `.name.tmp-PID` был предсказуем и жил в user-writable директории (при restore
    user_plist это ~/Library/LaunchAgents) — атакующий подкладывал symlink с этим именем на
    произвольный root-path, и open(temp, "wb") + chmod + chown, следуя symlink, писали/меняли
    владельца цели (arbitrary root file write). tempfile.mkstemp даёт криптографически
    случайное имя и создаёт файл атомарно с O_EXCL. КРИТИЧНО (#148): fchmod/fchown работают
    по fd, а НЕ по пути. Прежний код закрывал fd через fdopen и затем звал os.chmod(temp)/
    chown(temp) по пути — между fd-close и chmod/chown владелец parent-каталога мог
    переименовать temp и поставить symlink с тем же именем на произвольную цель, и
    os.chmod/chown (по умолчанию следующие symlink) меняли владельца цели (arbitrary chown).
    Теперь fd держится открытым до конца и метаданные выставляются по fd (TOCTOU-окна нет).
    os.replace(temp, path) безопасен по имени: temp-имя непредсказуемо, атакующий не может
    его подменить; path — финальная цель, переименование атомарно и не даёт arbitrary chown.

    Параметр `chown` сохранён в сигнатуре для обратной совместимости вызовов; fd-pinning
    делает его избыточным (используется os.fchown). Под non-root (тесты без sudo) fchown(0,0)
    дал бы EPERM и пропускается — под root (production) chown обязателен.
    """
    del chown  # fd-pinning: chown делается через os.fchown(fd), path-based хук более не нужен.
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temp = Path(tmp_name)
    try:
        # НЕ передаём closefd=True — fd должен жить для fchmod/fchown после flush.
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Метаданные — по fd, а не по пути. fchmod/fchown не следуют symlink и не
        # делают path-resolution: даже если temp-путь подменён symlink'ом на чужую
        # цель, fd всё ещё указывает на оригинальный regular-файл mkstemp (#148).
        os.fchmod(fd, mode)
        _fchown_if_privileged(fd, uid, gid)
        # Переименование по имени безопасно: temp-имя непредсказуемо (атакующий не
        # знает его), path — финальная цель; rename атомарен и не открывает
        # TOCTOU-окно для arbitrary chown.
        os.replace(temp, path)
        temp = None  # успех — не удалять в finally.
        return True
    except OSError:
        if temp is not None:
            try:
                os.unlink(temp)
            except OSError:
                pass
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _read_regular_nofollow(path, *, max_size=8 * 1024 * 1024):
    """Race-free чтение: O_NOFOLLOW делает check (не symlink) и use (чтение) одним syscall.

    lstat()-затем-copy2() (прежний подход) оставляет TOCTOU-окно: атакующий меняет
    regular-file на symlink к root-only секрету МЕЖДУ проверкой и копированием. open(O_NOFOLLOW)
    атомарно проваливается с ELOOP, если путь уже symlink — окна для подмены не существует,
    т.к. это единственный syscall, который и проверяет, и открывает.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise RuntimeError(f"backup_source_open_failed:{path}:{exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"backup_source_not_regular:{path}")
        if info.st_size > max_size:
            raise RuntimeError(f"backup_source_too_large:{path}")
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = -1  # fdopen приняла владение fd; не закрывать повторно в finally.
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _copy_file_nofollow(src, dst, *, mode, chown=os.chown, max_size=64 * 1024 * 1024):
    """Race-free копирование regular-файла без разыменования symlink.

    Единый примитив для копирования user-controlled файлов в защищаемую root-зону (templates,
    Privoxy binary/dylib). Чтение source — через _read_regular_nofollow (open(O_NOFOLLOW)+fstat:
    symlink отвергается атомарно, содержимое root-only цели не читается), запись dst — через
    _atomic_write (непредсказуемое temp-имя, O_EXCL). Прежний copy2(follow_symlinks=True) /
    copytree(symlinks=False) разыменовывали symlink и копировали содержимое цели — arbitrary
    root-readable-file-disclosure (templates → 0644; binary/dylib → 0755 executable).
    Возвращает True при успехе, False при отказе (symlink/non-regular/нет файла).
    """
    src = Path(src)
    dst = Path(dst)
    try:
        data = _read_regular_nofollow(src, max_size=max_size)
    except RuntimeError:
        return False
    return _atomic_write(dst, data, mode=mode, uid=0, gid=0, chown=chown)


def _read_fd_regular(fd, *, max_size=8 * 1024 * 1024):
    """Прочитать regular-файл по fd (TOCTOU-свободно: fd уже открыт).

    fstat по fd не делает path-resolution. Размер/тип проверяются по fstat того же fd,
    что и читается — окна для подмены нет (используется в fd-tree-traversal, #148).
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"fd_not_regular:mode={oct(info.st_mode)}")
    if info.st_size > max_size:
        raise RuntimeError(f"fd_too_large:{info.st_size}")
    return _read_all_fd(fd, info.st_size)


def _read_all_fd(fd, expected_size):
    """Прочитать всё содержимое fd чанками (fd уже past-stat, контент мог измениться —
    читаем до EOF, но отсекаем runaway-рост после fstat)."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > expected_size + (1 << 20):
            # Файл вырос после fstat (гонка записи) — не копировать растущий объект.
            raise RuntimeError(f"fd_grew_after_stat:{total}>{expected_size}")
    return b"".join(chunks)


def _copy_tree_fd(src_fd, dst, *, dir_mode, file_mode):
    """fd-relative рекурсивное копирование дерева (TOCTOU-свободно, #148).

    src_fd — уже открытый O_NOFOLLOW|O_DIRECTORY дескриптор корня. Каждый элемент
    открывается через openat (os.open с dir_fd=src_fd) с O_NOFOLLOW: путь `name`
    разрешается относительно зафиксированного src_fd, а НЕ повторным разрешением
    полного src/name. Даже если атакующий атомарно подменит src-каталог на symlink
    между lstat-root и перечислением — openat берёт name из уже открытого src_fd,
    повторного path-resolution нет. symlink/non-regular child отвергается O_NOFOLLOW.

    dst (root-owned protected зона) НЕ user-controlled: path-based mkdir/chmod/chown
    на dst безопасны и не открывают TOCTOU (атакующий не контролирует dst-путь).
    """
    dst.mkdir(parents=True, exist_ok=True)
    os.chmod(dst, dir_mode)
    if os.geteuid() == 0:
        os.chown(dst, 0, 0)
    for name in sorted(os.listdir(src_fd)):
        child_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=src_fd,
        )
        try:
            info = os.fstat(child_fd)
            dst_child = dst / name
            if stat.S_ISDIR(info.st_mode):
                if not _copy_tree_fd(child_fd, dst_child, dir_mode=dir_mode,
                                     file_mode=file_mode):
                    return False
            elif stat.S_ISREG(info.st_mode):
                try:
                    data = _read_fd_regular(child_fd)
                except RuntimeError:
                    return False
                if not _atomic_write(dst_child, data, mode=file_mode):
                    return False
            else:
                return False  # non-regular (symlink уже отсечён O_NOFOLLOW; fifo/socket/device) — отказ.
        finally:
            os.close(child_fd)
    return True


def _copy_tree_nofollow(src, dst, *, dir_mode=0o755, file_mode=0o644, chown=os.chown):
    """Race-free копирование дерева без разыменования symlink (полный fd-pinning, #148).

    Прежний _copy_templates звал _reject_symlinks_in_tree (отдельный lstat-проход) и затем
    copytree — между ними TOCTOU-окно. Дальнейшая fd-relative версия делала src.lstat()
    корня и затем os.listdir(src)/src_entry.lstat() ПО ПУТИ — между lstat(root) и listdir
    атакующий атомарно подменял src на symlink к root-only дереву, и listdir по пути шёл
    по symlink, читая чужое содержимое как 0644 world-readable.

    Теперь: root открывается ОДНИМ syscall os.open(O_NOFOLLOW|O_DIRECTORY) (отказ, если
    root сам symlink), перечисление — os.listdir(dir_fd), каждый child — через openat
    (os.open с dir_fd=root_fd, O_NOFOLLOW). Повторного path-resolution полного src-пути
    нет нигде — TOCTOU-окно между проверкой и travers'ом закрыто.
    """
    del chown  # fd-pinning: владельца dst выставляет _copy_tree_fd (inline os.chown под root), path-based хук не нужен.
    src = Path(src)
    dst = Path(dst)
    try:
        root_fd = os.open(
            str(src),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        return False  # root — symlink/не-каталог/нет файла (O_NOFOLLOW|O_DIRECTORY отвергает одним syscall).
    try:
        return _copy_tree_fd(root_fd, dst, dir_mode=dir_mode, file_mode=file_mode)
    finally:
        os.close(root_fd)


def _reject_symlinks_in_tree(root):
    """lstat каждого элемента дерева ДО копирования — ни один symlink не должен быть скопирован.

    `copytree(symlinks=False)` разыменовывает symlink внутри дерева и материализует содержимое
    его цели как обычный файл (задокументированное поведение shutil, не баг) — для user-writable
    дерева (Homebrew templates) это arbitrary-root-readable-file-disclosure: подложи symlink на
    root-only секрет внутри templates/ → root-хелпер скопирует его содержимое как root-owned
    world-readable файл. Валидация всего дерева ДО copytree закрывает это до чтения содержимого.
    """
    root = Path(root)
    top_info = root.lstat()
    if stat.S_ISLNK(top_info.st_mode):
        raise RuntimeError(f"tree_root_is_symlink:{root}")
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in dirs:
            info = (current_path / name).lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"tree_contains_symlink_dir:{current_path / name}")
        for name in files:
            info = (current_path / name).lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError(f"tree_contains_symlink_file:{current_path / name}")
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"tree_contains_non_regular_file:{current_path / name}")


def _restore_file(backup, target, *, uid, gid, mode, chown=os.chown):
    if not backup:
        return False
    try:
        data = _read_regular_nofollow(backup)
    except RuntimeError:
        return False
    return _atomic_write(target, data, mode=mode, uid=uid, gid=gid, chown=chown)


def _backup_existing(path, backup_dir, name, *, chown=os.chown):
    """Backup только regular-файла/директории, НЕ symlink (race-free через fd).

    `path` (например user_plist в ~/Library/LaunchAgents) до sudo-подтверждения полностью
    под контролем непривилегированного пользователя. root-процесс не должен читать/копировать
    содержимое ПО symlink — иначе backup (и позже restore) превращается в arbitrary-root-file-read
    примитив: подмени plist на symlink к root-only секрету → protect скопирует его в backup_dir →
    unprotect --restore запишет его содержимое обратно пользователю с 0644 (#122 privileged boundary).
    """
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return ""
    if stat.S_ISDIR(info.st_mode):
        _reject_symlinks_in_tree(path)
        target = Path(backup_dir) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(path, target, symlinks=False)
        return str(target)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"backup_source_not_regular:{path}")
    data = _read_regular_nofollow(path)
    target = Path(backup_dir) / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _atomic_write(target, data, mode=0o600, uid=0, gid=0, chown=chown):
        raise RuntimeError(f"backup_write_failed:{path}")
    return str(target)
