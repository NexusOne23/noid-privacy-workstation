#!/usr/bin/env python3
"""Fail-closed classifier for the canonical KVM Anaconda installer log."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile


TIMESTAMP = r"^[0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} "
HIGH_SIGNAL = (
    re.compile(TIMESTAMP + r"(?:ERR|ERROR|CRITICAL) "),
    re.compile(r"avc:\s+denied\s+", re.IGNORECASE),
    re.compile(r"\bReturn code(?: of [^:]+)?:\s*-?[1-9][0-9]*\b", re.IGNORECASE),
    re.compile(r"\bexited with status\s+[1-9][0-9]*\b", re.IGNORECASE),
    re.compile(r"\bstatus=[1-9][0-9]*/[A-Z_-]+\b"),
    re.compile(r"\bFailed with result\s+'[^']+'", re.IGNORECASE),
    re.compile(r":INFO:program:Failed to "),
    re.compile(r":(?:ERROR|CRITICAL|FATAL):"),
    re.compile(r"(?:\[FAIL\]|\sFAIL:|=== [^=]+ FAILED(?:\s|$))"),
    re.compile(r"Traceback \(most recent call last\):|PayloadInstallationError|\bsegfault\b"),
)
MAX_LOG_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024


class PolicyError(ValueError):
    """The policy is not a closed, unambiguous schema."""


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular_bytes(
    path: pathlib.Path, *, label: str, maximum: int
) -> bytes:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise ValueError(f"{label} is empty or exceeds its {maximum}-byte bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        final_metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise ValueError(f"{label} changed size while it was being read")
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_size != metadata.st_size
        or final_metadata.st_mtime_ns != metadata.st_mtime_ns
        or final_metadata.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise ValueError(f"{label} changed while it was being read")
    return raw


def load_policy(path: pathlib.Path):
    try:
        raw = read_regular_bytes(
            path, label="compose policy", maximum=MAX_POLICY_BYTES
        )
        policy = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc
    required = {
        "schema_version", "policy_id", "scope", "bindings",
        "success_markers", "allowed_events",
    }
    if not isinstance(policy, dict) or set(policy) != required:
        raise PolicyError("policy top-level schema is not exact")
    if policy["schema_version"] != 3:
        raise PolicyError("unsupported policy schema")
    if not isinstance(policy["policy_id"], str) or not policy["policy_id"]:
        raise PolicyError("policy_id must be nonempty text")
    if not isinstance(policy["scope"], str) or not policy["scope"]:
        raise PolicyError("scope must be nonempty text")
    bindings = policy["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
            "fedora_base_release", "anaconda_evr"}:
        raise PolicyError("policy bindings schema is not exact")
    base_release = bindings["fedora_base_release"]
    anaconda_evr = bindings["anaconda_evr"]
    if (not isinstance(base_release, str)
            or not re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", base_release)):
        raise PolicyError("invalid Fedora base release binding")
    if (not isinstance(anaconda_evr, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+-[0-9]+\.fc[0-9]+", anaconda_evr)):
        raise PolicyError("invalid Anaconda EVR binding")
    fedora_release = base_release.split("-", 1)[0]
    anaconda_version = anaconda_evr.split("-", 1)[0]
    expected_id = f"noid-fedora{fedora_release}-anaconda{anaconda_version}-kvm-v1"
    expected_scope = (
        f"Fedora {fedora_release} Server netinst {base_release}, "
        f"Anaconda {anaconda_evr}, canonical KVM compose only"
    )
    if policy["policy_id"] != expected_id or policy["scope"] != expected_scope:
        raise PolicyError("policy identity/scope differs from its exact bindings")

    seen_ids = set()
    correlations = {}
    compiled = {"success_markers": [], "allowed_events": []}
    for section in compiled:
        rows = policy[section]
        if not isinstance(rows, list) or not rows:
            raise PolicyError(f"{section} must be a nonempty list")
        for row in rows:
            base_keys = {"id", "regex", "min_count", "max_count"}
            optional = {
                "rationale",
                "context_before_regex",
                "context_before_lines",
                "context_after_regex",
                "context_after_lines",
                "correlation_id",
                "correlation_key_group",
            }
            if not isinstance(row, dict) or not base_keys <= set(row) or set(row) - base_keys - optional:
                raise PolicyError(f"invalid {section} row schema")
            if "rationale" in row and (
                not isinstance(row["rationale"], str) or not row["rationale"]
            ):
                raise PolicyError(f"invalid rationale for {row.get('id', '<unknown>')}")
            identifier = row["id"]
            if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9_]+", identifier):
                raise PolicyError("invalid rule id")
            if identifier in seen_ids:
                raise PolicyError(f"duplicate rule id: {identifier}")
            seen_ids.add(identifier)
            minimum, maximum = row["min_count"], row["max_count"]
            if (not isinstance(minimum, int) or isinstance(minimum, bool)
                    or not isinstance(maximum, int) or isinstance(maximum, bool)
                    or minimum < 0 or maximum < minimum):
                raise PolicyError(f"invalid budget for {identifier}")
            expression = row["regex"]
            if not isinstance(expression, str) or not expression.startswith("^") or not expression.endswith("$"):
                raise PolicyError(f"rule is not fully anchored: {identifier}")
            try:
                line_regex = re.compile(expression)
            except re.error as exc:
                raise PolicyError(f"invalid regex for {identifier}: {exc}") from exc
            correlation_keys = {"correlation_id", "correlation_key_group"}
            if set(row) & correlation_keys and set(row) & correlation_keys != correlation_keys:
                raise PolicyError(f"incomplete correlation contract for {identifier}")
            correlation_id = None
            correlation_key_group = None
            if correlation_keys <= set(row):
                correlation_id = row["correlation_id"]
                correlation_key_group = row["correlation_key_group"]
                if section != "allowed_events":
                    raise PolicyError(
                        f"correlation is not an allowed-event contract: {identifier}"
                    )
                if (not isinstance(correlation_id, str)
                        or not re.fullmatch(r"[a-z0-9_]+", correlation_id)
                        or not isinstance(correlation_key_group, str)
                        or not re.fullmatch(r"[a-z][a-z0-9_]*", correlation_key_group)
                        or correlation_key_group not in line_regex.groupindex):
                    raise PolicyError(f"invalid correlation contract for {identifier}")
            contexts = {}
            for direction in ("before", "after"):
                regex_key = f"context_{direction}_regex"
                lines_key = f"context_{direction}_lines"
                context_keys = {regex_key, lines_key}
                if set(row) & context_keys and set(row) & context_keys != context_keys:
                    raise PolicyError(f"incomplete {direction} context contract for {identifier}")
                context_regex = None
                context_lines = 0
                if context_keys <= set(row):
                    context_expression = row[regex_key]
                    context_lines = row[lines_key]
                    if (not isinstance(context_expression, str)
                            or not context_expression.startswith("^")
                            or not context_expression.endswith("$")
                            or not isinstance(context_lines, int)
                            or isinstance(context_lines, bool)
                            or not 1 <= context_lines <= 200):
                        raise PolicyError(
                            f"invalid {direction} context contract for {identifier}"
                        )
                    try:
                        context_regex = re.compile(context_expression)
                    except re.error as exc:
                        raise PolicyError(
                            f"invalid {direction} context regex for {identifier}: {exc}"
                        ) from exc
                contexts[direction] = (context_regex, context_lines)
            compiled_rule = {
                "id": identifier,
                "line": line_regex,
                "context_before": contexts["before"][0],
                "context_before_lines": contexts["before"][1],
                "context_after": contexts["after"][0],
                "context_after_lines": contexts["after"][1],
                "min": minimum,
                "max": maximum,
                "correlation_id": correlation_id,
                "correlation_key_group": correlation_key_group,
            }
            compiled[section].append(compiled_rule)
            if correlation_id is not None:
                correlations.setdefault(correlation_id, []).append(compiled_rule)
    for correlation_id, members in correlations.items():
        if len(members) != 2:
            raise PolicyError(
                f"correlation {correlation_id} must have exactly two members"
            )
        budgets = {(member["min"], member["max"]) for member in members}
        if len(budgets) != 1:
            raise PolicyError(
                f"correlation {correlation_id} members must share one budget"
            )
    anaconda_rules = [
        row for row in policy["success_markers"] if row["id"] == "anaconda_version"
    ]
    if len(anaconda_rules) != 1:
        raise PolicyError("anaconda_version marker must be unique")
    literal_evr = re.escape(anaconda_evr).replace(r"\-", "-")
    if literal_evr not in anaconda_rules[0]["regex"]:
        raise PolicyError("anaconda_version marker differs from its exact binding")
    return policy, compiled, correlations, raw


def atomic_report(path: pathlib.Path, report: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_log(path: pathlib.Path):
    raw = read_regular_bytes(
        path, label="installer log", maximum=MAX_LOG_BYTES
    )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"installer log is not strict UTF-8: {exc}") from exc
    lines = text.splitlines()
    if not lines or any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
        raise ValueError("installer log has no lines or an overlong line")
    return raw, lines


def context_line_matches(context, line, line_match):
    context_match = context.fullmatch(line)
    if context_match is None:
        return False
    shared_groups = context.groupindex.keys() & line_match.re.groupindex.keys()
    return all(
        context_match.group(name) == line_match.group(name)
        for name in shared_groups
    )


def context_matches(rule, lines, index, line_match):
    before = rule["context_before"]
    if before is not None:
        start = max(0, index - rule["context_before_lines"])
        if not any(
            context_line_matches(before, line, line_match)
            for line in lines[start:index]
        ):
            return False
    after = rule["context_after"]
    if after is not None:
        stop = min(len(lines), index + rule["context_after_lines"] + 1)
        if not any(
            context_line_matches(after, line, line_match)
            for line in lines[index + 1:stop]
        ):
            return False
    return True


def audit(policy_path: pathlib.Path, log_path: pathlib.Path):
    policy, compiled, correlations, policy_raw = load_policy(policy_path)
    raw, lines = read_log(log_path)
    counts = {rule["id"]: 0 for section in compiled.values() for rule in section}
    correlation_keys = {
        correlation_id: {
            member["id"]: collections.Counter() for member in members
        }
        for correlation_id, members in correlations.items()
    }
    violations = []

    for index, line in enumerate(lines):
        for rule in compiled["success_markers"]:
            line_match = rule["line"].fullmatch(line)
            if line_match and context_matches(rule, lines, index, line_match):
                counts[rule["id"]] += 1

        if not any(detector.search(line) for detector in HIGH_SIGNAL):
            continue
        matches = []
        for rule in compiled["allowed_events"]:
            line_match = rule["line"].fullmatch(line)
            if line_match and context_matches(rule, lines, index, line_match):
                matches.append((rule, line_match))
        if len(matches) != 1:
            violations.append({
                "line": index + 1,
                "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                "reason": "unclassified" if not matches else "ambiguous",
            })
        else:
            rule, line_match = matches[0]
            counts[rule["id"]] += 1
            if rule["correlation_id"] is not None:
                key = line_match.group(rule["correlation_key_group"])
                correlation_keys[rule["correlation_id"]][rule["id"]][key] += 1

    budget_failures = []
    for section in compiled.values():
        for rule in section:
            actual = counts[rule["id"]]
            if not rule["min"] <= actual <= rule["max"]:
                budget_failures.append({
                    "id": rule["id"], "actual": actual,
                    "minimum": rule["min"], "maximum": rule["max"],
                })

    correlation_failures = []
    for correlation_id, members in correlations.items():
        member_counts = correlation_keys[correlation_id]
        baseline = member_counts[members[0]["id"]]
        if any(member_counts[member["id"]] != baseline for member in members[1:]):
            correlation_failures.append({
                "id": correlation_id,
                "members": [
                    {
                        "id": member["id"],
                        "count": sum(member_counts[member["id"]].values()),
                    }
                    for member in members
                ],
            })

    result = (
        "pass"
        if not violations and not budget_failures and not correlation_failures
        else "fail"
    )
    report = {
        "schema_version": 1,
        "result": result,
        "policy_id": policy["policy_id"],
        "bindings": policy["bindings"],
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "log_name": log_path.name,
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "line_count": len(lines),
        "counts": dict(sorted(counts.items())),
        "budget_failures": budget_failures,
        "correlation_failures": correlation_failures,
        "violations": violations[:100],
        "violations_truncated": max(0, len(violations) - 100),
    }
    return result == "pass", report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        passed, report = audit(args.policy, args.log)
    except (OSError, ValueError, PolicyError) as exc:
        report = {"schema_version": 1, "result": "error", "error": str(exc)}
        atomic_report(args.report, report)
        print(f"compose-log-audit: ERROR: {exc}", file=os.sys.stderr)
        return 2
    atomic_report(args.report, report)
    if not passed:
        print(
            "compose-log-audit: FAIL: "
            f"{len(report['violations']) + report['violations_truncated']} unclassified/ambiguous, "
            f"{len(report['budget_failures'])} budget failures, "
            f"{len(report['correlation_failures'])} correlation failures",
            file=os.sys.stderr,
        )
        return 1
    print(f"compose-log-audit: PASS: {report['line_count']} lines classified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
