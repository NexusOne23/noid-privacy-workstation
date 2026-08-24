#!/usr/bin/env python3
"""Closed source/runtime verifier for the M01 kernel-command-line contract."""

from __future__ import annotations

import fnmatch
import hashlib
import pathlib
import re
import stat
import subprocess
import sys
from collections import defaultdict


SCOPES = (
    "base",
    "cpu-intel",
    "cpu-amd",
    "gpu-nvidia",
)
RETIRED_FAMILIES = {
    "acpi_backlight",
    "mem_sleep_default",
    "spectre_v2_user",
}
FORBIDDEN_FAMILIES = RETIRED_FAMILIES | {"slab_debug", "slub_debug"}
FALLBACK_ARG = "noid.initramfs=generic-fallback"
TUNED_BLS_ARG = "$tuned_params"
# Contract tokens Lorax's Live templates emit per menu entry. They belong to the
# installed-system manifest, but `--extra-boot-args` must never repeat them or
# the final GRUB config would carry a duplicate.
LORAX_ENTRY_TOKENS = ("rhgb", "quiet")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:=[^\s|]+)?$")


class ContractError(RuntimeError):
    pass


def family(token: str) -> str:
    return token.split("=", 1)[0]


def tokens(value: str) -> list[str]:
    return value.split()


def validate_unique(label: str, values: list[str]) -> None:
    if len(values) != len(set(values)):
        raise ContractError(f"{label}: duplicate exact token")
    seen: dict[str, str] = {}
    for token in values:
        key = family(token)
        if key in seen:
            raise ContractError(
                f"{label}: conflicting/duplicate family {key}: "
                f"{seen[key]} vs {token}"
            )
        seen[key] = token


def load_manifest(path: pathlib.Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    seen_tokens: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            raise ContractError(f"manifest line {number}: blank/comments are forbidden")
        fields = raw.split("|")
        if len(fields) != 2 or fields[0] not in SCOPES or not TOKEN_RE.fullmatch(fields[1]):
            raise ContractError(f"manifest line {number}: invalid closed record")
        scope, token = fields
        if token in seen_tokens:
            raise ContractError(f"manifest line {number}: duplicate token {token}")
        seen_tokens.add(token)
        result[scope].append(token)
    if tuple(result) != SCOPES:
        raise ContractError(f"manifest scope order/content differs: {tuple(result)}")
    for scope in SCOPES:
        validate_unique(f"manifest {scope}", result[scope])
    if result["gpu-nvidia"] != ["plymouth.use-simpledrm=1"]:
        raise ContractError(
            "gpu-nvidia scope must remain the single non-security framebuffer token"
        )
    if any(family(token) == "kptr_restrict" for token in seen_tokens):
        raise ContractError("kptr_restrict is a sysctl and must not be a kernel argument")
    return dict(result)


def extract_heredoc(source: str, marker: str) -> str:
    lines = source.splitlines()
    openers = [
        index for index, line in enumerate(lines)
        if re.search(rf"<<-?['\"]?{re.escape(marker)}['\"]?", line)
    ]
    if len(openers) != 1:
        raise ContractError(f"{marker}: expected one heredoc opener, found {len(openers)}")
    start = openers[0] + 1
    closers = [index for index in range(start, len(lines)) if lines[index] == marker]
    if len(closers) != 1:
        raise ContractError(f"{marker}: expected one closing delimiter, found {len(closers)}")
    return "\n".join(lines[start:closers[0]]) + "\n"


def one_match(pattern: str, source: str, label: str) -> str:
    matches = re.findall(pattern, source, flags=re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise ContractError(f"{label}: expected one match, found {len(matches)}")
    return matches[0]


def assigned_nonempty(script: str, variable: str) -> list[list[str]]:
    values = re.findall(
        rf'(?<![A-Za-z0-9_]){re.escape(variable)}="([^"]+)"', script
    )
    return [tokens(value) for value in values]


def require_exact(label: str, actual: list[str], expected: list[str]) -> None:
    validate_unique(label, actual)
    if actual != expected:
        missing = [token for token in expected if token not in actual]
        extra = [token for token in actual if token not in expected]
        raise ContractError(
            f"{label}: exact ordered contract differs; missing={missing}, extra={extra}"
        )


def require_exact_set(label: str, actual: list[str], expected: list[str]) -> None:
    validate_unique(label, actual)
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise ContractError(f"{label}: exact set differs; missing={missing}, extra={extra}")


def validate_documented_counts(
    source_path: pathlib.Path, manifest: dict[str, list[str]]
) -> None:
    """Keep current-facing kernel-argument counts derived from the manifest."""
    project_root = source_path.parents[2]
    base_count = len(manifest["base"])
    conditional_count = (
        max(len(manifest["cpu-intel"]), len(manifest["cpu-amd"]))
        + len(manifest["gpu-nvidia"])
        + 1  # one target-derived rd.luks.options=<UUID>=tries=0,discard token
    )
    expected = {
        project_root / "docs/scope.md": (
            f"{base_count} shared kernel-command-line tokens, plus up to "
            f"{conditional_count} conditional tokens"
        ),
        project_root / "docs/comparison.md": (
            f"{base_count} shared kernel-command-line tokens plus up to "
            f"{conditional_count} conditional tokens"
        ),
        project_root / "docs/threat-model.md": (
            f"{base_count} shared kernel-command-line tokens (+ up to "
            f"{conditional_count} hardware-conditional)"
        ),
    }
    for path, phrase in expected.items():
        normalized = " ".join(path.read_text(encoding="utf-8").split())
        if phrase not in normalized:
            raise ContractError(
                f"{path.relative_to(project_root)}: documented kernel-argument "
                f"count differs from manifest-derived {base_count}+{conditional_count}"
            )


def managed_patterns(target_script: str) -> list[str]:
    function = one_match(
        r"^is_noid_managed_arg\(\) \{\n(.*?)^\}",
        target_script,
        "is_noid_managed_arg function",
    )
    groups = re.findall(
        r"^[ \t]*([A-Za-z0-9_.*?=|.-]+)\)\n[ \t]*return 0 ;;",
        function,
        flags=re.MULTILINE,
    )
    patterns = [pattern for group in groups for pattern in group.split("|")]
    if not patterns or len(patterns) != len(set(patterns)):
        raise ContractError("managed-argument filter is empty or has duplicate patterns")
    return patterns


def validate_source_text(source: str, manifest: dict[str, list[str]]) -> None:
    pre_packages = source.split("%packages", 1)[0]
    boot = tokens(one_match(
        r'^bootloader --timeout=3 --append="([^"]+)"$',
        pre_packages,
        "primary bootloader append",
    ))
    interactive_script = extract_heredoc(source, "INTERACTIVE_DEFAULTS_EOF")
    interactive = tokens(one_match(
        r'^bootloader --timeout=3 --append="([^"]+)"$',
        interactive_script,
        "interactive bootloader append",
    ))
    target_script = extract_heredoc(source, "NOID_KARGS_EOF")
    firstboot_script = extract_heredoc(source, "CMDLINE_EOF")
    canonicalizer = extract_heredoc(source, "CMDLINE_CANONICALIZER_EOF")
    rootflags_rebind = extract_heredoc(source, "ROOTFLAGS_REBIND_EOF")
    base = tokens(one_match(
        r'^NOID_BASE_ARGS="([^"]+)"$', target_script, "NOID_BASE_ARGS"
    ))

    expected_boot = manifest["base"] + [manifest["cpu-intel"][0]]
    require_exact_set("primary bootloader append", boot, expected_boot)
    require_exact("interactive/primary bootloader parity", interactive, boot)
    require_exact("target NOID_BASE_ARGS", base, manifest["base"])
    canonical_base = tokens(one_match(
        r'^NOID_BASE_ARGS="([^"]+)"$', canonicalizer,
        "canonicalizer NOID_BASE_ARGS",
    ))
    require_exact("canonicalizer NOID_BASE_ARGS", canonical_base, manifest["base"])

    step4_start = source.index('log "STEP 4: hardware detection..."')
    step4_end = source.index('log "STEP 4b: generating', step4_start)
    compose_detection = source[step4_start:step4_end]
    expected_cpu = [manifest["cpu-intel"], manifest["cpu-amd"]]
    for label, script in (
        ("compose hardware logger", compose_detection),
        ("target post-script", target_script),
        ("firstboot helper", firstboot_script),
        ("firstboot canonicalizer", canonicalizer),
    ):
        actual = assigned_nonempty(script, "CPU_EXTRA")
        if actual != expected_cpu:
            raise ContractError(f"{label}: CPU extras differ: {actual}")
    for label, script in (("target post-script", target_script),
                          ("firstboot helper", firstboot_script),
                          ("firstboot canonicalizer", canonicalizer)):
        gpu = assigned_nonempty(script, "GPU_EXTRA")
        if len(gpu) != 1:
            raise ContractError(f"{label}: expected one NVIDIA GPU extra")
        require_exact(f"{label} NVIDIA GPU", gpu[0], manifest["gpu-nvidia"])

    for label, maximum in (
        ("maximum Intel hardware set", manifest["base"] + manifest["cpu-intel"]
         + manifest["gpu-nvidia"]),
        ("maximum AMD hardware set", manifest["base"] + manifest["cpu-amd"]),
    ):
        validate_unique(label, maximum)

    patterns = managed_patterns(target_script)
    canonical_patterns = managed_patterns(canonicalizer)
    if canonical_patterns != patterns:
        raise ContractError("target and firstboot managed-family filters differ")
    all_contract_tokens = [token for scope in SCOPES for token in manifest[scope]]
    for token in all_contract_tokens:
        matches = [pattern for pattern in patterns if fnmatch.fnmatchcase(token, pattern)]
        if len(matches) != 1:
            raise ContractError(f"managed filter matches {token} {len(matches)} times: {matches}")
    unmatched = {
        pattern for pattern in patterns
        if not any(fnmatch.fnmatchcase(token, pattern) for token in all_contract_tokens)
    }
    expected_unmatched = {f"{name}=*" for name in FORBIDDEN_FAMILIES}
    if unmatched != expected_unmatched:
        raise ContractError(f"unexpected unmatched managed patterns: {sorted(unmatched)}")
    if "target LUKS unlock-retry arg: $LUKS_KARG" not in target_script:
        raise ContractError("target post-script lacks pre-firstboot LUKS publication")
    for label, script in (("target post-script", target_script),
                          ("firstboot canonicalizer", canonicalizer)):
        if '[ "$arg" = "\\$tuned_params" ] && continue' not in script:
            raise ContractError(
                f"{label}: tuned BLS macro is not excluded from semantic kargs"
            )
    if 'expected_bls_options="$merged \\$tuned_params"' not in target_script:
        raise ContractError(
            "target post-script lacks exact Fedora tuned BLS publication"
        )
    if 'bls_options="$merged \\$tuned_params"' not in canonicalizer:
        raise ContractError(
            "canonicalizer lacks exact Fedora tuned BLS publication"
        )
    if "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2" not in firstboot_script:
        raise ContractError("firstboot helper lacks the reboot-required evidence schema")
    if re.search(r"systemctl.*(?:--no-block[ ]+)?reboot", firstboot_script):
        raise ContractError("firstboot helper still forces a reboot")
    for label, script in (("firstboot helper", firstboot_script),
                          ("rootflags evidence handoff", rootflags_rebind)):
        if "noid.initramfs=generic-fallback)" not in script:
            raise ContractError(
                f"{label}: Generic recovery marker is not normalized as transient"
            )
        if "recovery_marker_count=$((recovery_marker_count + 1))" not in script:
            raise ContractError(
                f"{label}: Generic recovery marker cardinality is not tracked"
            )
        if "repeats the Generic recovery marker" not in script:
            raise ContractError(
                f"{label}: duplicate Generic recovery markers do not fail closed"
            )


def source_self_tests(source: str, manifest: dict[str, list[str]]) -> None:
    def mutate_primary(replacement: str) -> str:
        lines = source.splitlines()
        for index, line in enumerate(lines):
            if line.startswith('bootloader --timeout=3 --append="'):
                lines[index] = replacement + '"'
                return "\n".join(lines) + "\n"
        raise ContractError("self-test could not find primary bootloader line")

    primary = one_match(
        r'^bootloader --timeout=3 --append="([^"]+)"$',
        source.split("%packages", 1)[0],
        "self-test primary append",
    )
    missing = " ".join(token for token in tokens(primary) if token != "module.sig_enforce=1")
    missing_with_comment = mutate_primary(f'bootloader --timeout=3 --append="{missing}')
    missing_with_comment += "# module.sig_enforce=1 (comment-only false-green fixture)\n"
    conflict = mutate_primary(
        f'bootloader --timeout=3 --append="{primary} module.sig_enforce=0'
    )
    for label, fixture in (("comment-only token", missing_with_comment),
                           ("duplicate/conflicting family", conflict)):
        try:
            validate_source_text(fixture, manifest)
        except ContractError:
            continue
        raise ContractError(f"self-test false-green: accepted {label} fixture")

    gaming = expected_profile(manifest, gaming=True)
    if "vdso32=1" not in gaming or "ia32_emulation=1" not in gaming:
        raise ContractError("self-test: Gaming profile lacks both compatibility values")
    if "vdso32=0" in gaming or "ia32_emulation=0" in gaming:
        raise ContractError("self-test: Gaming profile retains hardened conflicts")


def expected_profile(
    manifest: dict[str, list[str]], *, gaming: bool
) -> list[str]:
    """Return the closed base profile selected by one exact local receipt."""
    expected = list(manifest["base"])
    replacements = {
        "vdso32": "vdso32=1",
        "ia32_emulation": "ia32_emulation=1",
    }
    if gaming:
        seen: set[str] = set()
        for index, token in enumerate(expected):
            key = family(token)
            if key in replacements:
                expected[index] = replacements[key]
                seen.add(key)
        if seen != set(replacements):
            raise ContractError("manifest lacks the complete Gaming profile families")
    validate_unique("selected runtime base profile", expected)
    return expected


def gaming_profile_enabled() -> bool:
    """Validate the installed Gaming receipt before changing runtime expectations."""
    path = pathlib.Path("/var/lib/noid-privacy/gaming-mode.enabled")
    try:
        receipt_stat = path.lstat()
    except FileNotFoundError:
        return False
    parent_stat = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != 0
        or parent_stat.st_gid != 0
        or stat.S_IMODE(parent_stat.st_mode) != 0o755
        or
        not stat.S_ISREG(receipt_stat.st_mode)
        or receipt_stat.st_uid != 0
        or receipt_stat.st_gid != 0
        or stat.S_IMODE(receipt_stat.st_mode) != 0o644
        or receipt_stat.st_nlink != 1
        or receipt_stat.st_size != 0
    ):
        raise ContractError("Gaming profile receipt or state-directory metadata differs")
    try:
        subprocess.run(
            ["matchpathcon", "-V", str(path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise ContractError("Gaming profile receipt label differs") from exc
    return True


def expected_runtime(manifest: dict[str, list[str]]) -> list[str]:
    expected = expected_profile(manifest, gaming=gaming_profile_enabled())
    cpuinfo = pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    if "GenuineIntel" in cpuinfo:
        expected += manifest["cpu-intel"]
    elif "AuthenticAMD" in cpuinfo:
        expected += manifest["cpu-amd"]

    pci = subprocess.run(
        ["lspci", "-nn"], check=True, text=True, stdout=subprocess.PIPE
    ).stdout
    if re.search(r"(?:VGA.*NVIDIA|3D controller.*NVIDIA|Display controller.*NVIDIA)", pci):
        expected += manifest["gpu-nvidia"]

    validate_unique("runtime expected managed set", expected)
    return expected


def managed_runtime_tokens(values: list[str], manifest: dict[str, list[str]]) -> list[str]:
    families = {family(token) for scope in SCOPES for token in manifest[scope]}
    families.update(FORBIDDEN_FAMILIES)
    return [token for token in values if family(token) in families]


def require_runtime_managed(
    label: str, values: list[str], expected: list[str], manifest: dict[str, list[str]]
) -> None:
    actual = managed_runtime_tokens(values, manifest)
    require_exact(label, actual, expected)


def primary_boot_tokens(source_path: pathlib.Path) -> list[str]:
    source = source_path.read_text(encoding="utf-8")
    return tokens(one_match(
        r'^bootloader --timeout=3 --append="([^"]+)"$',
        source.split("%packages", 1)[0],
        "runtime primary bootloader append",
    ))


def expected_live_managed(
    primary: list[str], manifest: dict[str, list[str]]
) -> list[str]:
    """Return only project-owned Live args; Lorax owns per-entry rhgb/quiet."""
    for vendor_token in LORAX_ENTRY_TOKENS:
        if primary.count(vendor_token) != 1:
            raise ContractError(
                "primary bootloader append must carry one installed-system "
                f"{vendor_token} token"
            )
    expected = [manifest["gpu-nvidia"][0]]
    expected.extend(token for token in primary if token not in LORAX_ENTRY_TOKENS)
    validate_unique("expected Live managed set", expected)
    return expected


def require_live_runtime_managed(
    label: str,
    values: list[str],
    primary: list[str],
    manifest: dict[str, list[str]],
) -> None:
    """Validate Lorax's normal/basic versus media-check argument ownership.

    Lorax's maintained templates append `quiet` to every Live entry and `rhgb`
    to all but the media check. Both are also installed-system contract tokens,
    so `--extra-boot-args` must not repeat them: the project set below carries
    neither, and each entry is required to end with exactly the vendor-owned
    tokens its template emits.
    """
    actual = managed_runtime_tokens(values, manifest)
    expected = expected_live_managed(primary, manifest)
    expected += ["quiet"]
    if "rd.live.check" not in values:
        expected += ["rhgb"]
    require_exact(label, actual, expected)


def validate_live_config(
    config_path: pathlib.Path,
    manifest: dict[str, list[str]],
    source_path: pathlib.Path,
) -> None:
    """Audit every linux command emitted by one final ISO GRUB config."""
    primary = primary_boot_tokens(source_path)
    config_text = config_path.read_text(encoding="utf-8")
    config_lines = config_text.splitlines()
    defaults = [line.strip() for line in config_lines if line.strip().startswith("set default=")]
    timeouts = [line.strip() for line in config_lines if line.strip().startswith("set timeout=")]
    if defaults != ['set default="0"']:
        raise ContractError(
            f"{config_path}: normal Live entry is not the one exact default: {defaults}"
        )
    if timeouts != ["set timeout=3"]:
        raise ContractError(
            f"{config_path}: Live menu does not have the one exact three-second timeout: {timeouts}"
        )
    lines = [
        line.strip()
        for line in config_lines
        if re.match(r"^[ \t]*linux[ \t]+", line)
    ]
    if len(lines) != 3:
        raise ContractError(
            f"{config_path}: expected three Live linux commands, found {len(lines)}"
        )
    media_checks = 0
    for number, line in enumerate(lines, 1):
        fields = tokens(line)
        if len(fields) < 3 or fields[0] != "linux":
            raise ContractError(f"{config_path}: malformed linux command {number}")
        values = fields[2:]
        validate_unique(f"{config_path} linux command {number}", values)
        if not any(
            token == "rd.live.image" or token.startswith("rd.live.image=")
            for token in values
        ):
            raise ContractError(
                f"{config_path}: linux command {number} lacks rd.live.image"
            )
        if "rd.live.check" in values:
            media_checks += 1
        require_live_runtime_managed(
            f"{config_path} linux command {number}",
            values,
            primary,
            manifest,
        )
    if media_checks != 1:
        raise ContractError(
            f"{config_path}: expected one media-check command, found {media_checks}"
        )


def require_luks_activation(label: str, values: list[str]) -> None:
    """Bind every active root-LUKS selector to the reviewed retry policy."""
    prefix = "rd.luks.uuid=luks-"
    uuids = [token[len(prefix):] for token in values if token.startswith(prefix)]
    if len(uuids) != len(set(uuids)):
        raise ContractError(f"{label}: duplicate root-LUKS UUID selector")
    for uuid in uuids:
        required = f"rd.luks.options={uuid}=tries=0,discard"
        if values.count(required) != 1:
            raise ContractError(
                f"{label}: root-LUKS selector lacks one exact active policy: {required}"
            )


def validate_runtime(
    pass_id: str,
    proc_path: pathlib.Path,
    manifest: dict[str, list[str]],
    source_path: pathlib.Path,
) -> None:
    if not proc_path.is_file() or proc_path.is_symlink():
        raise ContractError(f"{proc_path}: active cmdline input is missing/non-regular/symlinked")
    proc = tokens(proc_path.read_text(encoding="utf-8", errors="strict").strip())
    if pass_id == "live":
        if not any(token == "rd.live.image" or token.startswith("rd.live.image=") for token in proc):
            raise ContractError("live pass lacks rd.live.image")
        # --extra-boot-args supplies the reviewed project set. Lorax's maintained
        # templates add rhgb only to the normal/basic entries, while the media
        # check deliberately omits it. Keep that vendor-owned UX distinction
        # without allowing a duplicate or any security-argument drift.
        require_live_runtime_managed(
            "live /proc/cmdline",
            proc,
            primary_boot_tokens(source_path),
            manifest,
        )
        return

    if any(token == "rd.live.image" or token.startswith("rd.live.image=") for token in proc):
        raise ContractError("installed pass retains rd.live.image")
    expected = expected_runtime(manifest)
    kernel_path = pathlib.Path("/etc/kernel/cmdline")
    if not kernel_path.is_file() or kernel_path.is_symlink():
        raise ContractError("/etc/kernel/cmdline missing/non-regular/symlinked")
    kernel = tokens(kernel_path.read_text().strip())
    require_runtime_managed("/etc/kernel/cmdline", kernel, expected, manifest)
    normalized_proc = [
        token for token in proc
        if not token.startswith("BOOT_IMAGE=") and not token.startswith("initrd=")
    ]
    require_luks_activation("/etc/kernel/cmdline", kernel)
    require_luks_activation("/proc/cmdline", normalized_proc)
    expected_hash = hashlib.sha256(
        (" ".join(kernel) + "\n").encode("utf-8")
    ).hexdigest()
    sentinel = pathlib.Path("/var/lib/noid-privacy/.firstboot-cmdline-done")
    reboot_marker = pathlib.Path(
        "/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
    )
    pending = pass_id == "fresh-install" and (
        reboot_marker.exists() or reboot_marker.is_symlink()
    )
    if pending:
        if sentinel.exists() or sentinel.is_symlink():
            raise ContractError("pending firstboot state already carries a success seal")
        if not reboot_marker.is_file() or reboot_marker.is_symlink():
            raise ContractError("firstboot reboot marker is non-regular/symlinked")
        marker_stat = reboot_marker.stat()
        if (marker_stat.st_uid, marker_stat.st_gid,
                stat.S_IMODE(marker_stat.st_mode)) != (0, 0, 0o600):
            raise ContractError("firstboot reboot marker ownership/mode differs")
        marker_lines = reboot_marker.read_text(
            encoding="utf-8", errors="strict"
        ).splitlines()
        normalized_hash = hashlib.sha256(
            (" ".join(normalized_proc) + "\n").encode("utf-8")
        ).hexdigest()
        if len(marker_lines) != 5 or marker_lines[:3] != [
            "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2",
            f"active_sha256={normalized_hash}",
            f"desired_sha256={expected_hash}",
        ] or not re.fullmatch(
            r"prepared_boot_id=[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
            marker_lines[3],
        ) or marker_lines[4] not in {"recovery_attempt=0", "recovery_attempt=1"}:
            raise ContractError("firstboot reboot marker does not bind durable bytes")
        if normalized_proc == kernel:
            raise ContractError("pending marker remains despite active/durable equality")
        cosmetic_families = {family(token) for token in manifest["gpu-nvidia"]}
        active_without_cosmetic = [
            token for token in normalized_proc if family(token) not in cosmetic_families
        ]
        durable_without_cosmetic = [
            token for token in kernel if family(token) not in cosmetic_families
        ]
        active_root_selectors = [
            token for token in active_without_cosmetic
            if token.startswith("rootflags=")
        ]
        durable_root_selectors = [
            token for token in durable_without_cosmetic
            if token.startswith("rootflags=")
        ]
        if any(token not in {"rootflags=subvol=root", "rootflags=subvol=/root"}
               for token in active_root_selectors):
            raise ContractError("pending firstboot state has an unreviewed active root selector")
        if len(active_root_selectors) > 1 or durable_root_selectors:
            raise ContractError("pending firstboot root-selector transition is not exact")
        active_without_cosmetic = [
            token for token in active_without_cosmetic if not token.startswith("rootflags=")
        ]
        durable_without_cosmetic = [
            token for token in durable_without_cosmetic if not token.startswith("rootflags=")
        ]
        if active_without_cosmetic != durable_without_cosmetic:
            raise ContractError(
                "pending firstboot delta exceeds the reviewed root-selector/framebuffer transition"
            )
        security_expected = [
            token for token in expected if family(token) not in cosmetic_families
        ]
        active_security = [
            token for token in managed_runtime_tokens(normalized_proc, manifest)
            if family(token) not in cosmetic_families
        ]
        require_exact(
            "active first-boot security arguments", active_security, security_expected
        )
    else:
        if reboot_marker.exists() or reboot_marker.is_symlink():
            raise ContractError("completed installed pass retains reboot marker")
        if not sentinel.is_file() or sentinel.is_symlink():
            raise ContractError("firstboot cmdline sentinel missing/non-regular/symlinked")
        require_runtime_managed("/proc/cmdline", proc, expected, manifest)
        if normalized_proc != kernel:
            raise ContractError("active /proc/cmdline differs from canonical durable cmdline")
        state_lines = sentinel.read_text(
            encoding="utf-8", errors="strict"
        ).splitlines()
        if len(state_lines) != 3 or state_lines[0] != "NOID_FIRSTBOOT_CMDLINE_V2":
            raise ContractError("firstboot cmdline sentinel schema/version differs")
        if state_lines[1:] != [
            f"desired_sha256={expected_hash}", f"active_sha256={expected_hash}"
        ]:
            raise ContractError(
                "firstboot cmdline sentinel does not bind active/durable bytes"
            )

    m21_state_path = pathlib.Path("/var/lib/noid-privacy/dracut-hostonly.state")
    if not m21_state_path.is_file() or m21_state_path.is_symlink():
        raise ContractError("M21 lifecycle state missing/non-regular/symlinked")
    m21_state_stat = m21_state_path.stat()
    if (
        m21_state_stat.st_uid,
        m21_state_stat.st_gid,
        stat.S_IMODE(m21_state_stat.st_mode),
    ) != (0, 0, 0o600):
        raise ContractError("M21 lifecycle state ownership/mode differs")
    state: dict[str, str] = {}
    for raw in m21_state_path.read_text(encoding="utf-8", errors="strict").splitlines():
        if raw.count("=") != 1:
            raise ContractError("M21 lifecycle state has an invalid record")
        key, value = raw.split("=", 1)
        if not key or key in state:
            raise ContractError("M21 lifecycle state has an invalid/duplicate key")
        state[key] = value
    if set(state) != {
        "policy_version", "phase", "root_class", "target_kernel", "prepared_boot_id"
    } or state["policy_version"] != "2":
        raise ContractError("M21 lifecycle state schema/version differs")
    expected_phase = "pending-reboot" if pass_id == "fresh-install" else "complete"
    if state["phase"] != expected_phase:
        raise ContractError(
            f"M21 lifecycle phase is {state['phase']}, expected {expected_phase}"
        )
    if state["root_class"] not in {
        "simple-single-device-luks2-btrfs",
        "other-hostonly",
    }:
        raise ContractError("M21 lifecycle root class differs")
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", state["target_kernel"]):
        raise ContractError("M21 lifecycle target kernel is malformed")
    if not re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        state["prepared_boot_id"],
    ):
        raise ContractError("M21 lifecycle prepared boot ID is malformed")
    fallback_name = f"noid-generic-fallback-{state['target_kernel']}.conf"

    entries_dir = pathlib.Path("/boot/loader/entries")
    try:
        entries_dir_mode = entries_dir.lstat().st_mode
    except FileNotFoundError as exc:
        raise ContractError("BLS entry directory is missing") from exc
    if not stat.S_ISDIR(entries_dir_mode):
        raise ContractError("BLS entry directory is non-directory/symlinked")
    entries = sorted(entries_dir.glob("*.conf"))
    if not entries:
        raise ContractError("no BLS entries found")
    recovery_entries = 0
    for entry in entries:
        entry_stat = entry.lstat()
        if not stat.S_ISREG(entry_stat.st_mode):
            raise ContractError(f"{entry}: BLS entry is non-regular/symlinked")
        if (
            entry_stat.st_uid,
            entry_stat.st_gid,
            stat.S_IMODE(entry_stat.st_mode),
        ) not in {(0, 0, 0o600), (0, 0, 0o644)}:
            raise ContractError(f"{entry}: BLS entry ownership/mode differs")
        option_lines = [
            line.split(None, 1)[1].strip()
            for line in entry.read_text(encoding="utf-8", errors="strict").splitlines()
            if line.startswith("options ")
        ]
        if len(option_lines) != 1:
            raise ContractError(f"{entry}: expected one options line")
        bls = tokens(option_lines[0])
        if entry.name == fallback_name:
            recovery_entries += 1
            if bls != kernel + [TUNED_BLS_ARG, FALLBACK_ARG]:
                raise ContractError(
                    f"{entry}: recovery options are not semantic cmdline plus tuned macro and marker"
                )
        elif bls != kernel + [TUNED_BLS_ARG]:
            raise ContractError(
                f"{entry}: normal options are not semantic cmdline plus one tuned macro"
            )
        require_runtime_managed(str(entry), bls, expected, manifest)
    expected_recovery_entries = 1 if expected_phase == "pending-reboot" else 0
    if recovery_entries != expected_recovery_entries:
        raise ContractError(
            "M21 recovery BLS cardinality differs: "
            f"{recovery_entries} != {expected_recovery_entries}"
        )


def main() -> int:
    try:
        modes = {"source", "live-config", "live", "fresh-install", "reboot"}
        if len(sys.argv) not in {4, 5} or sys.argv[1] not in modes:
            print(
                f"usage: {sys.argv[0]} source INPUT MANIFEST | "
                f"{sys.argv[0]} live-config INPUT MANIFEST SOURCE | "
                f"{sys.argv[0]} {{live|fresh-install|reboot}} INPUT MANIFEST SOURCE",
                file=sys.stderr,
            )
            return 2
        mode = sys.argv[1]
        input_path = pathlib.Path(sys.argv[2])
        manifest = load_manifest(pathlib.Path(sys.argv[3]))
        if mode == "source":
            if len(sys.argv) != 4:
                raise ContractError("source mode takes INPUT MANIFEST")
            source = input_path.read_text(encoding="utf-8")
            validate_source_text(source, manifest)
            validate_documented_counts(input_path, manifest)
            source_self_tests(source, manifest)
            print("source contract exact; comment-only/conflict fixtures rejected")
        elif mode == "live-config":
            if len(sys.argv) != 5:
                raise ContractError("live-config mode takes INPUT MANIFEST SOURCE")
            validate_live_config(input_path, manifest, pathlib.Path(sys.argv[4]))
            print(f"Live boot config exact: {input_path}")
        else:
            if len(sys.argv) != 5:
                raise ContractError("runtime mode takes INPUT MANIFEST SOURCE")
            validate_runtime(mode, input_path, manifest, pathlib.Path(sys.argv[4]))
            print(f"runtime contract exact for pass {mode}")
        return 0
    except (ContractError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        print(f"kernel-cmdline contract failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
