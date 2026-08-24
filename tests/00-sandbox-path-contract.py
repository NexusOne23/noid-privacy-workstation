#!/usr/bin/env python3
"""A sandboxed unit may only open runtime paths its own namespace can write.

`ProtectSystem=strict` remounts the entire hierarchy read-only except /dev,
/proc and /sys, so /run itself is not writable inside such a unit -- only the
subtrees named in `ReadWritePaths=`. A helper that opens a lock file directly
under /run therefore fails with EROFS at the redirection, before its first
argument is even parsed. That is not theoretical: audit-notify.service held its
toggle lock at /run/noid-audit-notify-toggle.lock while allow-listing only
/etc/audit/plugins.d and /run/noid-privacy, so the opt-in could never activate
while `systemctl enable --now` had already written the wants symlink and the
GUI switch kept reporting the feature as on.

This check pairs every deployed helper heredoc with the sandboxed units that
run it and verifies each literal /run path it opens for writing resolves inside
that unit's writable set. Helpers with no sandboxed consumer are out of scope:
they run from an ordinary root context where /run is writable.
"""

from __future__ import annotations

import pathlib
import re
import sys

# Repository writers share one heredoc contract even though the publication
# wrapper differs by trust boundary. Match the maintained writers rather than
# silently limiting coverage to literal `cat >` calls.
HEREDOC = re.compile(
    r"^[ \t]*(?:cat\s+>{1,2}|(?:sudo\s+)?tee|stage_root_file|write_file|publish_root_file)"
    r"[ \t]+(?:\"(?P<quoted_path>/[^\"]+)\"|(?P<bare_path>/\S+))"
    r"(?:(?:[^\n]*\\\n[ \t]*)?[^\n]*)"
    r"<<-?[ \t]*['\"]?(?P<marker>[A-Za-z_][A-Za-z0-9_]*)['\"]?[ \t]*\n"
    r"(?P<body>.*?)\n(?P=marker)[ \t]*$",
    re.M | re.S,
)
READ_WRITE_PATHS = re.compile(r"^ReadWritePaths=(.*)$", re.M)
RUNTIME_DIRECTORY = re.compile(r"^RuntimeDirectory=(.*)$", re.M)
EXEC_LINE = re.compile(
    r"^Exec(?:Start|StartPre|StartPost|Stop|StopPost|Condition)=(.*)$", re.M
)
ASSIGNMENT = re.compile(
    r"^[ \t]*(?:(?:local|readonly|export)[ \t]+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\n#]+)",
    re.M,
)
RUN_LITERAL = re.compile(r"/run(?:/[A-Za-z0-9._@%+=,-]+)+")
VARIABLE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
WRITE_REDIRECT = re.compile(
    r"(?:^|[;&|()\s])(?:exec[ \t]+)?(?:\d+[ \t]*)?"
    r"(?:<>|>>|>)[ \t]*(?P<target>\"[^\"]+\"|'[^']+'|[^\s;&|]+)",
    re.M,
)
LOCAL_BIN_PREFIXES = ("/usr/local/bin/", "/usr/local/sbin/")
FUNCTION = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*\n"
    r"(?P<body>.*?)^\}",
    re.M | re.S,
)
CASE_ARM = re.compile(
    r"^[ \t]*(?P<labels>[^\n()]+)\)[ \t]*\n"
    r"(?P<body>.*?)[ \t]*;;[ \t]*$",
    re.M | re.S,
)


def heredocs(text: str):
    for match in HEREDOC.finditer(text):
        path = match.group("quoted_path") or match.group("bare_path")
        body = match.group("body")
        yield path, body
        # M19 and the shipped documentation generate reviewed units from an
        # outer helper/doc heredoc. A non-overlapping regex scan of the parent
        # text cannot see those openers, so recurse into every captured body.
        yield from heredocs(body)


def writable_prefixes(body: str) -> list[str]:
    """Every /run subtree the unit may write, normalised without trailing slash."""
    prefixes: list[str] = []
    for line in READ_WRITE_PATHS.findall(body):
        for raw in line.split():
            prefixes.append(raw.lstrip("-+!").rstrip("/"))
    for line in RUNTIME_DIRECTORY.findall(body):
        for raw in line.split():
            prefixes.append("/run/" + raw.strip("/"))
    return prefixes


def collect_units(sources: list[pathlib.Path]) -> dict[str, tuple[str, list[str], list[str]]]:
    units: dict[str, tuple[str, list[str], list[str]]] = {}
    for source in sources:
        text = source.read_text(encoding="utf-8", errors="strict")
        for unit, body in heredocs(text):
            if not unit.endswith((".service", ".path", ".timer", ".socket", ".mount")):
                continue
            if not re.search(r"^ProtectSystem=strict$", body, re.M):
                continue
            units[unit] = (unit.rsplit("/", 1)[-1],
                           writable_prefixes(body),
                           EXEC_LINE.findall(body))
    return units


def assignment_paths(body: str) -> dict[str, set[str]]:
    """Resolve simple shell assignments that carry literal /run defaults."""
    assignments: dict[str, set[str]] = {}
    raw_values: dict[str, list[str]] = {}
    for match in ASSIGNMENT.finditer(body):
        name, value = match.group("name"), match.group("value").strip()
        raw_values.setdefault(name, []).append(value)
        for literal in RUN_LITERAL.findall(value):
            assignments.setdefault(name, set()).add(literal.rstrip("/"))

    # Resolve house-style DIR=/run/...; LOCK="$DIR/name" chains. Five passes
    # exceed the longest chain in the source tree while remaining bounded.
    for _ in range(5):
        changed = False
        for name, values in raw_values.items():
            for value in values:
                for reference in VARIABLE.finditer(value):
                    referenced = reference.group("braced") or reference.group("plain")
                    suffix = value[reference.end():].strip("\"',")
                    if "$" in suffix or "${" in suffix:
                        suffix = suffix.split("$", 1)[0]
                    suffix_parts = suffix.split(None, 1)
                    suffix = suffix_parts[0].rstrip(";)") if suffix_parts else ""
                    for prefix in assignments.get(referenced, set()):
                        candidate = (prefix.rstrip("/") + "/" + suffix.lstrip("/")) \
                            if suffix else prefix
                        target_set = assignments.setdefault(name, set())
                        if candidate not in target_set:
                            target_set.add(candidate)
                            changed = True
        if not changed:
            break
    return assignments


def runtime_writes(body: str, assignments: dict[str, set[str]] | None = None) -> list[str]:
    if assignments is None:
        assignments = assignment_paths(body)
    writes: set[str] = set()
    for match in WRITE_REDIRECT.finditer(body):
        target = match.group("target").strip('"\'')
        if target.startswith("/run/"):
            literal = RUN_LITERAL.match(target)
            if literal:
                writes.add(literal.group(0).rstrip("/"))
            continue
        reference = VARIABLE.match(target)
        if not reference:
            continue
        name = reference.group("braced") or reference.group("plain")
        writes.update(assignments.get(name, set()))
    return sorted(writes)


def selected_mode(command: str, helper: str) -> str | None:
    """Return a literal first helper argument from a systemd Exec line."""
    basename = helper.rsplit("/", 1)[-1]
    match = re.search(
        rf"(?:^|/)({re.escape(basename)})[ \t]+(['\"]?)([A-Za-z0-9_-]+)\2",
        command,
    )
    return match.group(3) if match else None


def mode_arm(body: str, mode: str) -> str | None:
    for match in CASE_ARM.finditer(body):
        labels = {
            label.strip().strip('"\'')
            for label in match.group("labels").split("|")
        }
        if mode in labels:
            return match.group("body")
    return None


def command_runtime_writes(body: str, helper: str, command: str) -> list[str]:
    """Restrict case-dispatched helpers to the mode named by the unit."""
    mode = selected_mode(command, helper)
    selected = mode_arm(body, mode) if mode else None
    if selected is None:
        return runtime_writes(body)

    assignments = assignment_paths(body)
    functions = {
        match.group("name"): match.group("body") for match in FUNCTION.finditer(body)
    }
    writes = set(runtime_writes(selected, assignments))
    pending = [
        name for name in functions
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", selected)
    ]
    visited: set[str] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        function_body = functions[name]
        writes.update(runtime_writes(function_body, assignments))
        for called in functions:
            if called not in visited and re.search(
                    rf"(?<![A-Za-z0-9_]){re.escape(called)}(?![A-Za-z0-9_])",
                    function_body):
                pending.append(called)

    # Preserve top-level writes that happen before function/case dispatch.
    first_function = min((match.start() for match in FUNCTION.finditer(body)),
                         default=len(body))
    writes.update(runtime_writes(body[:first_function], assignments))
    return sorted(writes)


def collect_helpers(sources: list[pathlib.Path]) -> dict[str, str]:
    helpers: dict[str, str] = {}
    for source in sources:
        text = source.read_text(encoding="utf-8", errors="strict")
        for path, body in heredocs(text):
            helpers[path] = body
    return helpers


def command_helpers(command: str, helpers: dict[str, str]) -> list[str]:
    matched: set[str] = set()
    for helper in helpers:
        if helper in command:
            matched.add(helper)
            continue
        for prefix in LOCAL_BIN_PREFIXES:
            if helper.startswith(prefix):
                counterpart = next(
                    other + helper.removeprefix(prefix)
                    for other in LOCAL_BIN_PREFIXES if other != prefix
                )
                if counterpart in command:
                    matched.add(helper)
                break
    return sorted(matched)


def main() -> int:
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".")
    sources = sorted((root / "kickstart").rglob("*.ks"))
    if not sources:
        print("sandbox path contract: no Kickstart sources found", file=sys.stderr)
        return 1
    units = collect_units(sources)
    helpers = collect_helpers(sources)
    audited = 0
    offenders: list[str] = []
    for unit, (name, prefixes, execs) in sorted(units.items()):
        for command in execs:
            for executable in command_helpers(command, helpers):
                for lock in command_runtime_writes(
                        helpers[executable], executable, command):
                    audited += 1
                    if not any(lock == prefix or lock.startswith(prefix + "/")
                               for prefix in prefixes):
                        offenders.append(
                            f"{name}: {executable} opens {lock}, which is outside "
                            f"its writable set {prefixes or '[]'}"
                        )
    if offenders:
        print("sandbox path contract failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        return 1
    if audited == 0:
        print("sandbox path contract: no sandboxed runtime lock found", file=sys.stderr)
        return 1
    print(
        f"sandbox path contract exact: {len(units)} strict unit(s), "
        f"{audited} sandboxed runtime write(s) writable"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
