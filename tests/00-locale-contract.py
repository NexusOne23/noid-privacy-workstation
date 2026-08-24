#!/usr/bin/env python3
"""Every deployed helper that parses localized tool output must pin a C locale.

`stat -c %F`, `stat --format=%F` and friends emit a *translated* file-type word.
systemd hands each service the installation's LANG from /etc/locale.conf, and
the image ships twelve langpacks, so a helper that compares that field against
the English literal `directory` passes in the en_US.UTF-8 compose and
fail-closes on every localized installation. That is not a theoretical concern:
it is exactly how the M03 topology guard died within milliseconds on a German
install while the identical payload succeeded in the Live session.

This check walks every `cat > <path> <<'EOF'` heredoc in the Kickstart sources,
finds the ones that read a locale-sensitive field, and requires an effective
top-level locale pin in the same script body.
"""

from __future__ import annotations

import pathlib
import re
import sys

# Tool output whose *content* changes with LC_MESSAGES/LC_ALL and that the
# project compares against English literals.
LOCALE_SENSITIVE = (
    re.compile(r"\bstat\b[^\n]*%F"),
    re.compile(r"\bstat\b[^\n]*--format=[^\n]*%F"),
)
C_LOCALE = re.compile(r"^(?:C|POSIX)(?:\.[A-Za-z0-9-]+)?$")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(\S*)$")
BARE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
COMMAND_PREFIX = re.compile(
    r"(?:^|[;&|(`]\s*|\b(?:if|then|elif|while|until|do)\s+)"
    r"LC_ALL=(?P<value>\S+)"
)
HEREDOC_OPEN = re.compile(r"cat\s+>\s*(\S+)\s*<<-?['\"]?([A-Za-z0-9_]+)['\"]?")
NESTED_HEREDOC_OPEN = re.compile(
    r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|"
    r"([A-Za-z_][A-Za-z0-9_]*))"
)
FUNCTION_OPEN = re.compile(
    r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\(\s*\))?\s*\{"
)
FUNCTION_DECLARATION = re.compile(
    r"^\s*(?:function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?"
    r"|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))\s*$"
)
STANDALONE_OPEN_BRACE = re.compile(r"(?:^|[;\s])\{(?=$|[;\s])")
STANDALONE_CLOSE_BRACE = re.compile(r"(?:^|[;\s])\}(?=$|[;\s])")


def visible_statement_lines(body: list[str]):
    """Yield body lines with top-level scope, skipping nested heredoc data."""
    delimiter: str | None = None
    function_depth = 0
    pending_function = False
    for raw in body:
        if delimiter is not None:
            if raw.strip() == delimiter:
                delimiter = None
            continue

        top_level = function_depth == 0
        yield raw, top_level

        opener = NESTED_HEREDOC_OPEN.search(raw)
        if opener:
            delimiter = next(
                group for group in opener.groups() if group is not None
            )

        # Locale assignments inside a function are not effective until that
        # function is called.  Keep them out of the top-level pin state.  The
        # contract still audits sensitive commands inside the function because
        # an earlier exported top-level pin does reach them.
        code = raw.split("#", 1)[0]
        if pending_function and code.strip() == "{":
            function_depth = 1
            pending_function = False
        elif function_depth == 0 and FUNCTION_OPEN.match(code):
            function_depth = 1
            pending_function = False
        elif function_depth == 0 and FUNCTION_DECLARATION.match(code):
            pending_function = True
        elif function_depth:
            function_depth += len(STANDALONE_OPEN_BRACE.findall(code))
            function_depth -= len(STANDALONE_CLOSE_BRACE.findall(code))
            function_depth = max(0, function_depth)
        elif code.strip():
            pending_function = False


def locale_is_pinned(body: list[str]) -> bool:
    """True only when LC_ALL is set to a C locale *and* reaches child processes.

    A standalone `LC_ALL=C` is only a shell variable, so a later `stat` child
    still answers in the user's language unless the name is exported. A POSIX
    command-prefix assignment (`LC_ALL=C stat ...`) is narrower and valid for
    that command, so accept it when every sensitive command carries the pin.
    """
    assigned = exported = False
    sensitive_count = 0
    for raw, top_level in visible_statement_lines(body):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if any(pattern.search(raw) for pattern in LOCALE_SENSITIVE):
            sensitive_count += 1
            command_pinned = False
            for prefix in COMMAND_PREFIX.finditer(raw):
                if not C_LOCALE.match(prefix.group("value").strip("'\"")):
                    continue
                suffix = raw[prefix.end():]
                if any(pattern.search(suffix) for pattern in LOCALE_SENSITIVE):
                    command_pinned = True
                    break
            if not (assigned and exported) and not command_pinned:
                return False

        # Only unconditional statement-level assignments can establish the
        # persistent environment for a later command.  Order matters: a pin
        # after the first localized parse cannot retroactively protect it.
        if not top_level:
            continue
        words = line.split()
        prefixed = words[0] == "export"
        if prefixed:
            words = words[1:]
        for word in words:
            match = ASSIGNMENT.match(word)
            if match and match.group(1) == "LC_ALL":
                if not C_LOCALE.match(match.group(2).strip("'\"")):
                    return False
                assigned = True
                exported = exported or prefixed
            elif prefixed and BARE_NAME.match(word) and word == "LC_ALL":
                exported = True
        if not prefixed and not any(ASSIGNMENT.match(w) for w in words):
            # A non-assignment command line: keep scanning, nothing to learn.
            continue
    return sensitive_count > 0


def helper_bodies(path: pathlib.Path):
    """Yield (deployed_path, first_line_number, body_lines) per heredoc."""
    lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    target = delimiter = None
    start = 0
    for number, line in enumerate(lines):
        if target is None:
            match = HEREDOC_OPEN.search(line)
            if match:
                target, delimiter, start = match.group(1), match.group(2), number
            continue
        if line.strip() == delimiter:
            yield target, start + 2, lines[start + 1:number]
            target = delimiter = None


def main() -> int:
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".")
    sources = sorted((root / "kickstart").rglob("*.ks"))
    if not sources:
        print("locale contract: no Kickstart sources found", file=sys.stderr)
        return 1
    audited = 0
    offenders: list[str] = []
    for source in sources:
        for target, first, body in helper_bodies(source):
            text = "\n".join(body)
            if not any(pattern.search(text) for pattern in LOCALE_SENSITIVE):
                continue
            audited += 1
            if not locale_is_pinned(body):
                offenders.append(
                    f"{source.relative_to(root)}:{first}: {target} parses a "
                    f"localized field without an exported LC_ALL=C pin"
                )
    if offenders:
        print("locale contract failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        return 1
    if audited == 0:
        print("locale contract: no locale-sensitive helper found", file=sys.stderr)
        return 1
    print(f"locale contract exact: {audited} locale-sensitive helper(s) pinned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
