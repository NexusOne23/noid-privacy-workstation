#!/usr/bin/python3
"""Semantic fixture for NoID Privacy's Lorax Live-size compose override."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: verify-lorax-live-required-space.py PATH/TO/creator.py")

creator_path = Path(sys.argv[1])
if not creator_path.is_file() or creator_path.is_symlink():
    fail("creator module must be a regular, non-symlink file")
try:
    creator_source = creator_path.read_text(encoding="utf-8")
    creator_tree = ast.parse(creator_source, filename=str(creator_path))
    compile(creator_source, str(creator_path), "exec")
except (OSError, SyntaxError, UnicodeError) as error:
    fail(f"creator module does not compile: {error}")

make_runtime_nodes = [
    node
    for node in creator_tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "make_runtime"
]
if len(make_runtime_nodes) != 1:
    fail("creator module has no unique make_runtime function")
make_runtime = make_runtime_nodes[0]
runtime_statements = make_runtime.body
if (
    not runtime_statements
    or not isinstance(runtime_statements[0], ast.Expr)
    or not isinstance(runtime_statements[0].value, ast.Constant)
    or not isinstance(runtime_statements[0].value.value, str)
):
    fail("make_runtime docstring contract differs")
runtime_statements = runtime_statements[1:]
if not runtime_statements or not isinstance(runtime_statements[0], ast.If):
    fail("NoID Privacy manifest preparation is not make_runtime's first operation")
first_operation = ast.unparse(runtime_statements[0])
expected_first_operation = (
    "if opts.project == NOID_LIVE_PROJECT:\n"
    "    _noid_prepare_live_required_space(mount_dir)"
)
if first_operation != expected_first_operation:
    fail("make_runtime's NoID Privacy manifest call is reordered or broadened")

# Execute only the reviewed NoID Privacy constants and helpers. This keeps the fixture
# independent of Mako, pykickstart and the rest of Lorax while the full source
# is still compiled above and the stager separately gates its exact RPM hash.
selected_nodes: list[ast.stmt] = []
for node in creator_tree.body:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if names and all(name.startswith("NOID_") for name in names):
            selected_nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name.startswith("_noid_"):
        selected_nodes.append(node)
if not selected_nodes:
    fail("creator module contains no isolated NoID Privacy manifest implementation")


class FixtureLogger:
    def info(self, *_args, **_kwargs):
        pass


namespace = {
    "os": os,
    "shutil": shutil,
    "subprocess": subprocess,
    "tempfile": tempfile,
    "log": FixtureLogger(),
}
selected_module = ast.Module(body=selected_nodes, type_ignores=[])
ast.fix_missing_locations(selected_module)
exec(compile(selected_module, str(creator_path), "exec"), namespace)

required_names = {
    "NOID_REQUIRED_SPACE_PARTS",
    "NOID_LIVEINST_UPDATE_PARTS",
    "NOID_REQUIRED_SPACE_MAGIC",
    "NOID_REQUIRED_SPACE_HEADROOM",
    "NOID_REQUIRED_SPACE_MINIMUM",
    "NOID_REQUIRED_UID",
    "NOID_REQUIRED_GID",
    "NOID_ROOTFS_ABSENT_PARTS",
    "NOID_ROOTFS_EMPTY_DIRECTORY_PARTS",
    "NOID_ANACONDA_BASE_SHA256",
    "_noid_scrub_live_rootfs",
    "_noid_prepare_live_required_space",
}
missing_names = sorted(required_names - namespace.keys())
if missing_names:
    fail(f"creator module is missing NoID Privacy manifest symbols: {missing_names}")
if namespace["NOID_REQUIRED_UID"] != 0 or namespace["NOID_REQUIRED_GID"] != 0:
    fail("compose ownership constants are not root")
namespace["NOID_REQUIRED_UID"] = os.getuid()
namespace["NOID_REQUIRED_GID"] = os.getgid()


def make_source_tree(base: Path) -> tuple[Path, Path]:
    root = base / "source"
    update_parent = root / "boot/loader/noid-privacy"
    update_parent.mkdir(parents=True)
    for relative_directory in (
        "etc/NetworkManager/system-connections",
        "etc/nvme",
        "root",
        "var/lib/NetworkManager",
        "var/lib/chrony",
        "var/lib/noid-privacy",
        "var/lib/systemd",
        "var/log/anaconda",
        "var/log/journal/build-machine-id",
    ):
        (root / relative_directory).mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    for parent in root.rglob("*"):
        if parent.is_dir():
            parent.chmod(0o755)
    for parent in (root / "boot", root / "boot/loader", update_parent):
        parent.chmod(0o755)
    update_image = update_parent / "liveinst-updates.img"
    update_image.write_bytes(b"fixture updates image\n")
    update_image.chmod(0o644)
    machine_id = root / "etc/machine-id"
    machine_id.write_text("build-machine-id\n", encoding="ascii")
    machine_id.chmod(0o444)
    for relative_file in (
        "etc/brlapi.key",
        "etc/nvme/hostid",
        "etc/nvme/hostnqn",
        "root/anaconda-ks.cfg",
        "root/original-ks.cfg",
        "var/lib/noid-privacy/host-identity-installed.done",
        "var/lib/systemd/random-seed",
        "etc/NetworkManager/system-connections/build.nmconnection",
        "var/lib/NetworkManager/secret_key",
        "var/lib/chrony/drift",
        "var/log/ks-fixture.log",
        "var/log/anaconda/anaconda.log",
        "var/log/journal/build-machine-id/system.journal",
    ):
        target = root / relative_file
        target.write_bytes(b"compose-state\n")
        target.chmod(0o600)
    return root, update_image


def reference_du(root: Path) -> int:
    patterns = (
        "/dev/",
        "/proc/",
        "/tmp/*",
        "/sys/",
        "/run/",
        "/boot/*rescue*",
        "/boot/loader/",
        "/boot/efi/loader/",
        "/etc/machine-id",
        "/etc/machine-info",
    )
    command = ["/usr/bin/du", "--bytes", "--summarize", str(root)]
    for pattern in patterns:
        command.extend(["--exclude", f"{root}{pattern}"])
    measured = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    size, separator, reported_path = measured.stdout.rstrip("\n").partition("\t")
    if not separator or reported_path != str(root) or not size.isdigit():
        fail("independent reference du returned unexpected output")
    return int(size)


with tempfile.TemporaryDirectory(
    prefix="noid-lorax-live-size-fixture.",
    dir="/var/tmp",
) as temporary_dir:
    fixture = Path(temporary_dir)
    root, _update_image = make_source_tree(fixture / "valid")
    payload = root / "payload.bin"
    with payload.open("wb") as payload_file:
        payload_file.truncate(namespace["NOID_REQUIRED_SPACE_MINIMUM"] + 4096)
    os.link(payload, root / "payload-hardlink.bin")

    before_size = reference_du(root)
    namespace["_noid_prepare_live_required_space"](str(root))
    after_size = reference_du(root)
    if after_size >= before_size:
        fail("rootfs scrub did not retire the fixture compose state")

    machine_id = root / "etc/machine-id"
    metadata = machine_id.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or metadata.st_size != 0
    ):
        fail("rootfs scrub did not publish a canonical empty machine-id")
    for parts in namespace["NOID_ROOTFS_ABSENT_PARTS"]:
        if root.joinpath(*parts).exists() or root.joinpath(*parts).is_symlink():
            fail("rootfs scrub left a forbidden exact-path artifact")
    for parts in namespace["NOID_ROOTFS_EMPTY_DIRECTORY_PARTS"]:
        if any(root.joinpath(*parts).iterdir()):
            fail("rootfs scrub left a persistent-state directory populated")
    log_files = [path for path in (root / "var/log").rglob("*") if not path.is_dir()]
    if log_files:
        fail("rootfs scrub left a compose log payload")

    manifest = root.joinpath(*namespace["NOID_REQUIRED_SPACE_PARTS"])
    metadata = manifest.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
    ):
        fail("published manifest metadata differs")
    expected_required = after_size + namespace["NOID_REQUIRED_SPACE_HEADROOM"]
    expected_payload = (
        namespace["NOID_REQUIRED_SPACE_MAGIC"]
        + b"\nbytes="
        + f"{expected_required:020d}".encode("ascii")
        + b"\nheadroom="
        + str(namespace["NOID_REQUIRED_SPACE_HEADROOM"]).encode("ascii")
        + b"\nanaconda_base_sha256="
        + namespace["NOID_ANACONDA_BASE_SHA256"]
        + b"\n"
    )
    if manifest.read_bytes() != expected_payload:
        fail("published manifest payload differs from independent measurement")

    original_payload = manifest.read_bytes()
    try:
        namespace["_noid_prepare_live_required_space"](str(root))
    except RuntimeError:
        pass
    else:
        fail("a pre-existing manifest was silently replaced")
    if manifest.read_bytes() != original_payload:
        fail("pre-existing manifest changed after the fail-closed retry")

    writable_root, _writable_update = make_source_tree(fixture / "writable")
    writable_parent = writable_root / "boot/loader/noid-privacy"
    writable_parent.chmod(0o775)
    try:
        namespace["_noid_prepare_live_required_space"](str(writable_root))
    except RuntimeError:
        pass
    else:
        fail("a group-writable compose path was accepted")

    real_root, _real_update = make_source_tree(fixture / "root-symlink")
    symlinked_root = fixture / "source-link"
    symlinked_root.symlink_to(real_root, target_is_directory=True)
    try:
        namespace["_noid_prepare_live_required_space"](str(symlinked_root))
    except RuntimeError:
        pass
    else:
        fail("a symlinked compose root was accepted")

    symlink_root, symlink_update = make_source_tree(fixture / "symlink")
    real_update = symlink_update.with_name("liveinst-updates-real.img")
    symlink_update.replace(real_update)
    symlink_update.symlink_to(real_update.name)
    try:
        namespace["_noid_prepare_live_required_space"](str(symlink_root))
    except OSError:
        pass
    else:
        fail("a symlinked updates image was accepted")

print("lorax Live required-space fixture: PASS")
