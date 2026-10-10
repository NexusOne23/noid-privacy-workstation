#!/usr/bin/python3
"""Symlink- and mount-safe GNOME tracking/cache cleanup at session shutdown."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass


AT_FDCWD = -100
SYS_OPENAT2 = 437

RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
ROOT_RESOLVE = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
CHILD_RESOLVE = (
    RESOLVE_BENEATH
    | RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
)
QUARANTINE_PREFIX = ".noid-thumbnails-delete-"


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


class CleanupError(RuntimeError):
    """A safety precondition or exact cleanup postcondition failed."""


@dataclass
class TreePlan:
    parent_fd: int
    name: str
    tree_fd: int | None
    identity: tuple[int, int] | None


def _openat2(dir_fd: int, path: str, flags: int, resolve: int) -> int:
    raw_path = os.fsencode(path)
    how = OpenHow(flags=flags, mode=0, resolve=resolve)
    fd = LIBC.syscall(
        SYS_OPENAT2,
        dir_fd,
        ctypes.c_char_p(raw_path),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if fd < 0:
        saved_errno = ctypes.get_errno()
        raise OSError(saved_errno, os.strerror(saved_errno), path)
    return int(fd)


def _owned_absolute_root(path: str, label: str) -> int | None:
    if not os.path.isabs(path) or os.path.normpath(path) == os.sep:
        raise CleanupError(f"{label} must be an absolute non-root path")
    try:
        fd = _openat2(AT_FDCWD, os.path.normpath(path), DIR_FLAGS, ROOT_RESOLVE)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CleanupError(f"unsafe or inaccessible {label}: {exc}") from exc
    metadata = os.fstat(fd)
    if metadata.st_uid != os.getuid():
        os.close(fd)
        raise CleanupError(f"{label} is not owned by uid {os.getuid()}")
    return fd


def _open_child_dir(parent_fd: int, name: str, label: str) -> int:
    try:
        return _openat2(parent_fd, name, DIR_FLAGS, CHILD_RESOLVE)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            raise CleanupError(f"mount boundary refused at {label}") from exc
        raise CleanupError(f"unsafe directory refused at {label}: {exc}") from exc


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _lstat(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _preflight_tree(tree_fd: int, label: str) -> None:
    """Prove that every directory is beneath this tree and on its mount."""
    with os.scandir(tree_fd) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            child_fd = _open_child_dir(tree_fd, entry.name, f"{label}/{entry.name}")
            try:
                if _identity(os.fstat(child_fd)) != _identity(metadata):
                    raise CleanupError(f"directory raced during preflight: {label}/{entry.name}")
                _preflight_tree(child_fd, f"{label}/{entry.name}")
            finally:
                os.close(child_fd)


def _prepare_tree(parent_fd: int, name: str, label: str) -> TreePlan | None:
    metadata = _lstat(parent_fd, name)
    if metadata is None:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        return TreePlan(parent_fd, name, None, None)

    tree_fd = _open_child_dir(parent_fd, name, label)
    if _identity(os.fstat(tree_fd)) != _identity(metadata):
        os.close(tree_fd)
        raise CleanupError(f"directory raced while opening: {label}")
    try:
        _preflight_tree(tree_fd, label)
    except Exception:
        os.close(tree_fd)
        raise
    return TreePlan(parent_fd, name, tree_fd, _identity(metadata))


def _remove_contents(tree_fd: int, label: str) -> int:
    removed = 0
    while True:
        with os.scandir(tree_fd) as entries:
            names = [entry.name for entry in entries]
        if not names:
            return removed
        for name in names:
            metadata = _lstat(tree_fd, name)
            if metadata is None:
                continue
            child_label = f"{label}/{name}"
            if not stat.S_ISDIR(metadata.st_mode):
                os.unlink(name, dir_fd=tree_fd)
                removed += 1
                continue

            child_fd = _open_child_dir(tree_fd, name, child_label)
            try:
                child_identity = _identity(os.fstat(child_fd))
                if child_identity != _identity(metadata):
                    raise CleanupError(f"directory raced while deleting: {child_label}")
                removed += _remove_contents(child_fd, child_label)
            finally:
                os.close(child_fd)
            current = _lstat(tree_fd, name)
            if current is None:
                continue
            if _identity(current) != child_identity or not stat.S_ISDIR(current.st_mode):
                raise CleanupError(f"directory identity changed before removal: {child_label}")
            os.rmdir(name, dir_fd=tree_fd)
            removed += 1


def _execute_tree(plan: TreePlan, label: str) -> int:
    if plan.tree_fd is None:
        current = _lstat(plan.parent_fd, plan.name)
        if current is None:
            return 0
        if stat.S_ISDIR(current.st_mode):
            raise CleanupError(f"non-directory changed into a directory: {label}")
        os.unlink(plan.name, dir_fd=plan.parent_fd)
        return 1

    quarantine = f"{QUARANTINE_PREFIX}{os.getpid()}-{secrets.token_hex(8)}"
    os.rename(
        plan.name,
        quarantine,
        src_dir_fd=plan.parent_fd,
        dst_dir_fd=plan.parent_fd,
    )
    moved = _lstat(plan.parent_fd, quarantine)
    if moved is None or _identity(moved) != plan.identity or not stat.S_ISDIR(moved.st_mode):
        raise CleanupError(f"directory identity changed during quarantine: {label}")

    removed = _remove_contents(plan.tree_fd, label)
    current = _lstat(plan.parent_fd, quarantine)
    if current is None or _identity(current) != plan.identity or not stat.S_ISDIR(current.st_mode):
        raise CleanupError(f"quarantine identity changed before removal: {label}")
    os.rmdir(quarantine, dir_fd=plan.parent_fd)
    return removed + 1


def _prepare_gnome_data(data_fd: int | None) -> tuple[int | None, list[str]]:
    if data_fd is None:
        return None, []
    try:
        shell_fd = _open_child_dir(data_fd, "gnome-shell", "XDG_DATA_HOME/gnome-shell")
    except CleanupError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
            return None, []
        raise

    names: list[str] = []
    for name in ("application_state", "session-active-history.json"):
        metadata = _lstat(shell_fd, name)
        if metadata is None:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            os.close(shell_fd)
            raise CleanupError(f"refusing directory at XDG_DATA_HOME/gnome-shell/{name}")
        names.append(name)
    return shell_fd, names


def _resolve_xdg_root(variable: str, fallback: str) -> str:
    value = os.environ.get(variable)
    if value:
        if not os.path.isabs(value):
            raise CleanupError(f"{variable} must be absolute when set")
        return value
    return fallback


def cleanup() -> tuple[int, int]:
    home = os.environ.get("HOME")
    if not home or not os.path.isabs(home):
        raise CleanupError("HOME must be set to an absolute path")
    data_home = _resolve_xdg_root("XDG_DATA_HOME", os.path.join(home, ".local/share"))
    cache_home = _resolve_xdg_root("XDG_CACHE_HOME", os.path.join(home, ".cache"))

    with ExitStack() as stack:
        data_fd = _owned_absolute_root(data_home, "XDG_DATA_HOME")
        if data_fd is not None:
            stack.callback(os.close, data_fd)
        cache_fd = _owned_absolute_root(cache_home, "XDG_CACHE_HOME")
        if cache_fd is not None:
            stack.callback(os.close, cache_fd)

        shell_fd, data_names = _prepare_gnome_data(data_fd)
        if shell_fd is not None:
            stack.callback(os.close, shell_fd)
        cache_plans: list[tuple[TreePlan, str]] = []
        if cache_fd is not None:
            with os.scandir(cache_fd) as entries:
                cache_names = sorted(
                    entry.name
                    for entry in entries
                    if entry.name == "thumbnails"
                    or entry.name.startswith(QUARANTINE_PREFIX)
                )
            for name in cache_names:
                label = (
                    "XDG_CACHE_HOME/thumbnails"
                    if name == "thumbnails"
                    else f"XDG_CACHE_HOME/{name}"
                )
                plan = _prepare_tree(cache_fd, name, label)
                if plan is None:
                    continue
                cache_plans.append((plan, label))
                if plan.tree_fd is not None:
                    stack.callback(os.close, plan.tree_fd)

        removed_data = 0
        if shell_fd is not None:
            for name in data_names:
                current = _lstat(shell_fd, name)
                if current is None:
                    continue
                if stat.S_ISDIR(current.st_mode):
                    raise CleanupError(f"tracked file changed into a directory: {name}")
                os.unlink(name, dir_fd=shell_fd)
                removed_data += 1
        removed_cache = sum(
            _execute_tree(plan, label) for plan, label in cache_plans
        )
        return removed_data, removed_cache


def main(argv: list[str]) -> int:
    if argv in (["-h"], ["--help"]):
        print("Usage: noid-gnome-privacy-cleanup")
        return 0
    if argv:
        print("Usage: noid-gnome-privacy-cleanup", file=sys.stderr)
        return 2
    try:
        removed_data, removed_cache = cleanup()
    except (CleanupError, OSError) as exc:
        print(f"noid-gnome-privacy-cleanup: ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "noid-gnome-privacy-cleanup: OK: "
        f"tracking={removed_data} cache_entries={removed_cache}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
