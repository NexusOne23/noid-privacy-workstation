#!/usr/bin/env python3
"""An ERR trap is only inherited by functions when errtrace is enabled.

bash propagates an ERR trap into a function body only under `set -E`
(errtrace). Without it the trap still fires for a top-level command and for a
function that `return`s non-zero, but NOT for a plain command that fails inside
a function -- and that is where rollback and remapping logic almost always
lives. The result is a trap that looks armed, passes review, and silently does
nothing in the one case it was written for.

Both shipped instances had this defect. noid-toggle-gaming armed
`trap 'rollback_state $?' ERR` under `set -euo pipefail`, so a grubby failure
inside set_persistent_mode aborted the shell with `setsebool -P
selinuxuser_execmod on` already made permanent and no rollback -- a persisted
W^X relaxation the transaction exists to prevent. noid-aide-check armed a trap
that remaps any abort to exit 14 precisely because 1-7 is AIDE's difference
bitmask that SuccessExitStatus turns into unit SUCCESS; without errtrace that
remapping did not cover function bodies.

This contract scans every tracked shell source, tracks the most recent `set`
that enabled errexit before each ERR trap, and fails when that `set` did not
also enable errtrace. `trap - ERR` (disarming) is not a trap installation and
is ignored.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

SHORT_SET = re.compile(r"^\s*set\s+([+-])([A-Za-z]+)\b")
LONG_SET = re.compile(r"^\s*set\s+([+-])o\s+(errexit|errtrace)\b")
# `trap 'handler' ERR`, `trap handler ERR`, `trap "handler" ERR INT TERM`
TRAP_LINE = re.compile(
    r"^\s*trap\s+(?P<body>'[^']*'|\"[^\"]*\"|[^\s-]\S*)\s+"
    r"(?P<signals>[A-Za-z0-9 ]+?)\s*(?:#.*)?$"
)
HEREDOC_OPEN = re.compile(
    r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|"
    r"([A-Za-z_][A-Za-z0-9_]*))"
)
SHELL_SUFFIXES = {".sh", ".ks", ".bash"}


@dataclass
class ShellScope:
    """Independent errexit state for one shell or shebang heredoc body."""

    delimiter: str | None = None
    awaiting_first_line: bool = False
    enabled: bool = True
    errexit: bool = False
    errtrace: bool = False
    errexit_line: int = 0


def offenders(path: pathlib.Path) -> list[tuple[int, int, str]]:
    """Return (trap line, governing set line, source) for unprotected traps."""
    found: list[tuple[int, int, str]] = []
    is_kickstart = path.suffix == ".ks"
    # Kickstart syntax outside %pre/%post is not one shell.  Start disabled and
    # create a fresh scope at every script section so state cannot leak from a
    # %pre into the later %post (or across two independent sections).
    scopes = [ShellScope(enabled=not is_kickstart)]
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        scope = scopes[-1]
        if scope.delimiter is not None and line.strip() == scope.delimiter:
            scopes.pop()
            continue
        if is_kickstart and len(scopes) == 1:
            directive = line.lstrip()
            if directive.startswith(("%pre", "%post")):
                scopes = [ShellScope()]
                continue
            if directive.startswith("%end"):
                scopes = [ShellScope(enabled=False)]
                continue
            scope = scopes[-1]
        if scope.awaiting_first_line:
            scope.awaiting_first_line = False
            # <<- strips leading TABs before the command reads the body.
            scope.enabled = line.lstrip("\t").startswith("#!")
        if not scope.enabled:
            continue

        long_options = LONG_SET.match(line)
        if long_options:
            enabled = long_options.group(1) == "-"
            if long_options.group(2) == "errexit":
                scope.errexit = enabled
                if enabled:
                    scope.errexit_line = number
            else:
                scope.errtrace = enabled
        else:
            short_options = SHORT_SET.match(line)
        if not long_options and short_options:
            enabled = short_options.group(1) == "-"
            letters = short_options.group(2)
            if "e" in letters:
                scope.errexit = enabled
                if enabled:
                    scope.errexit_line = number
            if "E" in letters:
                scope.errtrace = enabled
        trap = TRAP_LINE.match(line)
        if trap and "ERR" in trap.group("signals").split():
            # With no errexit in force the trap is advisory, not load-bearing
            # for an abort that would otherwise skip it.
            if scope.errexit and not scope.errtrace:
                found.append((number, scope.errexit_line, line.strip()))

        opener = HEREDOC_OPEN.search(line)
        if opener:
            delimiter = next(group for group in opener.groups() if group is not None)
            scopes.append(
                ShellScope(
                    delimiter=delimiter,
                    awaiting_first_line=True,
                    enabled=False,
                )
            )
    return found


def shell_sources(root: pathlib.Path) -> list[pathlib.Path]:
    """Return tracked shell sources, with a filesystem fallback outside Git."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        return sorted(
            root / item.decode("utf-8", "surrogateescape")
            for item in result.stdout.split(b"\0")
            if item
            and pathlib.Path(
                item.decode("utf-8", "surrogateescape")
            ).suffix in SHELL_SUFFIXES
        )
    return sorted(
        path
        for path in root.rglob("*")
        if path.suffix in SHELL_SUFFIXES
        and path.is_file()
        and ".git" not in path.parts
    )


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    failures = 0
    scanned = 0
    for path in shell_sources(root):
        if not path.is_file():
            continue
        scanned += 1
        for trap_line, set_line, source in offenders(path):
            relative = path.relative_to(root) if path.is_relative_to(root) else path
            print(
                f"{relative}:{trap_line}: ERR trap is not inherited by functions "
                f"-- the governing `set` at line {set_line} lacks -E (errtrace): {source}",
                file=sys.stderr,
            )
            failures += 1
    if failures:
        print(f"errtrace contract: {failures} unprotected ERR trap(s)", file=sys.stderr)
        return 1
    print(f"errtrace contract: {scanned} shell sources, every ERR trap under errtrace")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
