#!/usr/bin/env python3
"""A %post gate may not grep a shipped file for a string that file cannot hold.

Every module ends in a verification block that greps the files it just wrote
for the invariants those files are supposed to carry. The files themselves are
written by quoted heredocs in this same repository, so both halves of that
contract are in the tree and can be checked against each other before a build
ever runs.

They drift silently. A change that moves a function from one shipped script to
another updates the heredocs and usually the sibling assertions in 99-finalize,
while the module's own older verification block keeps greping the file the code
left. Nothing fails until Anaconda runs: the chain goes false, `fail` becomes
non-zero, and `%post --erroronfail` aborts the whole compose with no ISO
produced -- a full build outage from a one-line staleness that was visible
statically the whole time.

Polarity is derived from the failure arm, never guessed from the operators.
Two shapes appear in this repo and they mean opposite things:

    if <a> && <b>; then echo "[OK]" else fail=$((fail + 1)) fi   -- a bare grep
        asserts the string is PRESENT
    if <a> || <b>; then log "FAIL:" fail=$((fail + 1)) fi        -- a bare grep
        asserts the string is ABSENT
    <a> && <b> || { log "FAIL:"; fail=$((fail + 1)); }           -- PRESENT

Reading the consequent decides it; counting `&&` against `||` does not, because
long gates mix both. A `!` in front of the grep flips whichever meaning applies.

Deliberately not checked, because the shipped bytes cannot be resolved
statically: greps whose target comes from an expanding (unquoted) heredoc,
literals containing a shell variable, files rewritten by sed/printf/tee after
creation, greps nested inside another quoted string, and paths this repo never
creates. Every one of those is counted and printed, so shrinking coverage is
visible instead of silent.
"""

from __future__ import annotations

import collections
import pathlib
import re
import sys

SNIPPETS = "kickstart/snippets"

# `cat > /abs/path <<'MARKER'`, `<<"MARKER"`, `<<MARKER`, and `cat >>` appends.
CREATE = re.compile(
    r"""^\s*cat\s+>>?\s*(?P<path>/[^\s"']+)\s*"""
    r"""<<-?\s*(?P<q>['"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)(?P=q)\s*$"""
)
# `grep -qF 'literal' /abs/path`, optionally negated, optionally with `--`.
GREP = re.compile(
    r"""(?P<neg>!\s*)?grep\s+-q(?:x?F|Fx?)\s+(?:--\s+)?"""
    r"""(?P<q>['"])(?P<lit>[^'"]*)(?P=q)\s*(?P<path>/[^\s"';)]+)"""
)
CONDITION = re.compile(r"^\s*(?:if|elif)\s(?P<cond>.*?);\s*then\s*$", re.M | re.S)
# Any later rewrite makes the shipped content unknown to a static reader.
MUTATES = re.compile(r"""(?:sed\s+-i|printf[^\n]*>>?|tee\s+-a?)[^\n]*?(/[A-Za-z0-9_./@-]+)""")
FAILURE = re.compile(r"FAIL|fail=\$\(\(\s*fail\s*\+|exit 1")
SUCCESS = re.compile(r"\[OK\]|OK:")


def heredocs(snippets: list[pathlib.Path]):
    """Map each heredoc-created path to its bodies, purity and later rewrites."""
    bodies: dict[str, list[str]] = collections.defaultdict(list)
    verbatim: dict[str, bool] = {}
    rewritten: set[str] = set()
    for snippet in snippets:
        text = snippet.read_text(encoding="utf-8")
        rewritten.update(match.group(1) for match in MUTATES.finditer(text))
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            made = CREATE.match(lines[index])
            if not made:
                index += 1
                continue
            marker = made.group("marker")
            body: list[str] = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].strip() != marker:
                body.append(lines[cursor])
                cursor += 1
            path = made.group("path")
            bodies[path].append("\n".join(body))
            # One expanding heredoc anywhere makes the whole path unresolvable.
            verbatim[path] = verbatim.get(path, True) and bool(made.group("q"))
            index = cursor
    return bodies, verbatim, rewritten


def consequent_inverts(text: str, start: int) -> bool | None:
    """True when the branch taken on a true condition is the failure arm."""
    body = text[start : start + 400]
    end = min(x for x in (body.find("\nfi"), body.find("\nelse"), len(body)) if x != -1)
    body = body[:end]
    if SUCCESS.search(body):
        return False
    if FAILURE.search(body):
        return True
    return None


def nested_in_quotes(text: str, position: int) -> bool:
    """A grep inside `check "grep ..."` is an argument, not a live condition."""
    line_start = text.rfind("\n", 0, position) + 1
    return text.count('"', line_start, position) % 2 == 1


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    snippets = sorted((root / SNIPPETS).glob("*.ks"))
    if not snippets:
        print(f"gate-literal contract: no snippets under {SNIPPETS}", file=sys.stderr)
        return 1

    bodies, verbatim, rewritten = heredocs(snippets)
    stale: list[tuple[str, str, str]] = []
    checked = 0
    skipped: collections.Counter[str] = collections.Counter()

    for snippet in snippets:
        # Join line continuations so a wrapped `grep -qF 'x' \\\n  /path` reads
        # as the single token sequence bash sees.
        flat = re.sub(r"\\\n\s*", " ", snippet.read_text(encoding="utf-8"))
        regions: list[tuple[int, int, bool | None]] = []
        for condition in CONDITION.finditer(flat):
            cond = condition.group("cond")
            if "\nif " in cond or "\nfi" in cond:
                continue
            regions.append(
                (condition.start(), condition.end(), consequent_inverts(flat, condition.end()))
            )

        for grep in GREP.finditer(flat):
            if nested_in_quotes(flat, grep.start()):
                skipped["nested in a quoted argument"] += 1
                continue
            inverted: bool | None = None
            enclosed = False
            for begin, end, polarity in regions:
                if begin <= grep.start() < end:
                    inverted, enclosed = polarity, True
                    break
            if enclosed and inverted is None:
                skipped["consequent not classifiable"] += 1
                continue
            if not enclosed:
                # A statement-level `<a> && <b> || { FAIL }` chain: each operand
                # asserts its own truth, so the chain is never inverted.
                if "||" not in flat[grep.end() : grep.end() + 400]:
                    skipped["no failure arm found"] += 1
                    continue
                inverted = False

            path, lit = grep.group("path"), grep.group("lit")
            asserts_presence = (grep.group("neg") is not None) ^ (not inverted)
            if not asserts_presence:
                skipped["asserts absence"] += 1
            elif path not in bodies:
                skipped["path not created here"] += 1
            elif not verbatim.get(path):
                skipped["expanding heredoc"] += 1
            elif "$" in lit:
                skipped["variable in literal"] += 1
            elif path in rewritten:
                skipped["rewritten after creation"] += 1
            else:
                checked += 1
                if not any(lit in body for body in bodies[path]):
                    stale.append((snippet.name, path, lit))

    if stale:
        print(
            "gate-literal contract: a %post gate greps a shipped file for a "
            "string that file does not contain. %post --erroronfail aborts the "
            "compose the moment this runs:",
            file=sys.stderr,
        )
        for name, path, lit in stale:
            print(f"  {name}: {path} carries no {lit!r}", file=sys.stderr)
        return 1

    detail = ", ".join(f"{count} {reason}" for reason, count in sorted(skipped.items()))
    print(
        f"gate-literal contract: {checked} build-gate literals match the heredoc "
        f"that ships them (unresolvable statically: {detail})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
