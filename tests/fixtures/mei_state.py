#!/usr/bin/env python3
"""Exercise M15 runtime classification on private sysfs and kmod transports."""
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]).read_text()
detector = source.split("<<'CPU_DETECT_EOF'\n", 1)[1].split("\nCPU_DETECT_EOF", 1)[0]
start = detector.index('    mei_me_bound="no"\n')
end = detector.index('\n    if kt_sol_output=$(', start)
intel = detector[start:end]
amd = detector.split('elif [ "$CPU_VENDOR" = "amd" ]; then\n', 1)[1]
amd = amd.split('\n    PSP_FWUPD_VISIBILITY=', 1)[0]
lockdown = source.split("<<'MEI_LOCKDOWN_EOF'\n", 1)[1].split("\nMEI_LOCKDOWN_EOF", 1)[0]
start = lockdown.index('    echo "MEI core module state:"')
end = lockdown.index('\n    echo ""', start)
display = lockdown[start:end]

with tempfile.TemporaryDirectory(prefix="noid-mei-state-") as temporary:
    root = Path(temporary)
    sysfs = root / "sys"
    driver = sysfs / "bus/pci/drivers/mei_me"
    driver.mkdir(parents=True)
    module = sysfs / "module/mei"
    module.parent.mkdir()
    bound = driver / "0000:00:16.0"
    config = root / "kernel-config"
    config.write_text("")
    scripts = []
    for block in (intel, amd, display):
        block = block.replace("/sys/", str(sysfs) + "/")
        block = block.replace('/boot/config-$(uname -r)', str(config))
        scripts.append(block)
    intel, amd, display = scripts

    def run(block, prefix):
        result = subprocess.run(["/bin/bash", "-eu", "-c", prefix + block],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=5, check=False)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    # Each positive and negative case runs the actual producer branch. Metadata
    # failure and success are separate from loaded state and configured policy.
    cases = [
        ("loadable", True, True, 1, False, "mei-me-bound:available-platform-results-vary:no"),
        ("blacklisted", True, True, 1, False, "mei-me-bound:available-platform-results-vary:no"),
        ("loadable", False, True, 1, False, "loaded-unbound:conditional:no"),
        ("blacklisted", False, True, 1, False, "loaded-unbound:conditional:no"),
        ("blacklisted", False, False, 0, False, "blocked-by-policy:unavailable-by-policy:no"),
        ("loadable", False, False, 0, False, "available-not-loaded:conditional:no"),
        ("loadable", False, False, 1, False, "unknown:unknown:no"),
        ("loadable", False, False, 1, True, "absent:unavailable:yes"),
    ]
    for policy, is_bound, loaded, metadata_rc, disabled, expected in cases:
        bound.unlink(missing_ok=True)
        if is_bound:
            bound.symlink_to(module)
        if loaded:
            module.mkdir(exist_ok=True)
        elif module.exists():
            module.rmdir()
        config.write_text("# CONFIG_INTEL_MEI is not set\n" if disabled else "")
        prefix = (f"MEI_CORE_POLICY={shlex.quote(policy)}; MEI_KERNEL_REGRESSION=no;\n"
                  f"modinfo() {{ return {metadata_rc}; }}\n")
        output = run(intel + '\nprintf "%s:%s:%s\\n" "$MEI_STATE" '
                     '"$MEI_FWUPD_VISIBILITY" "$MEI_KERNEL_REGRESSION"\n', prefix)
        assert output == expected, (policy, is_bound, loaded, output, expected)

    for metadata_rc, expected in ((0, "available-not-loaded"), (1, "unavailable")):
        output = run(amd + '\nprintf "%s\\n" "$CCP_STATE"\n',
                     f"modinfo() {{ return {metadata_rc}; }}\n")
        assert output == expected, (output, expected)
    (sysfs / "module/ccp").mkdir()
    assert run(amd + '\nprintf "%s\\n" "$CCP_STATE"\n',
               "modinfo() { return 1; }\n") == "loaded"

    for loaded in (False, True):
        if loaded:
            module.mkdir(exist_ok=True)
        elif module.exists():
            module.rmdir()
        output = run(display, 'CORE_MODS=mei; CONF=/dev/null; grep() { return 0; };\n')
        assert "NoID Privacy ordinary-load block configured" in output
        assert ("mei: loaded;" if loaded else "mei: not loaded;") in output
        assert "detection OFF" not in output

print("MEI state: 13 producer/display cases passed")
