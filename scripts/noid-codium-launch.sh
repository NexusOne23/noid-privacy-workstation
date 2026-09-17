#!/usr/bin/env bash
# Launch VSCodium on the system-selected default GPU without enumerating every
# installed Vulkan ICD. Explicit user/session GPU-offload selections always win.
set -euo pipefail

VENDOR_EXECUTABLE=/usr/share/codium/codium
SWITCHEROOCTL=/usr/bin/switcherooctl

if [[ ! -f $VENDOR_EXECUTABLE || -L $VENDOR_EXECUTABLE \
      || ! -x $VENDOR_EXECUTABLE ]]; then
    printf 'noid-codium-launch: VSCodium executable is missing or unsafe\n' >&2
    exit 127
fi

# GNOME's "Launch using Discrete Graphics Card", switcherooctl, PRIME and
# Vulkan-loader selectors are explicit owner choices. Do not replace any of
# them with the default-GPU environment. This keeps Android Studio/emulators,
# Godot, games and intentional VSCodium offload behavior independent.
explicit_gpu_selectors=(
    DRI_PRIME
    __NV_PRIME_RENDER_OFFLOAD
    __NV_PRIME_RENDER_OFFLOAD_PROVIDER
    __GLX_VENDOR_LIBRARY_NAME
    __EGL_VENDOR_LIBRARY_FILENAMES
    __VK_LAYER_NV_optimus
    VK_DRIVER_FILES
    VK_ICD_FILENAMES
    VK_LOADER_DRIVERS_SELECT
    VK_LOADER_DRIVERS_DISABLE
    VK_LOADER_DEVICE_SELECT
    MESA_VK_DEVICE_SELECT
    MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE
)
for selector in "${explicit_gpu_selectors[@]}"; do
    if [[ -n ${!selector-} ]]; then
        exec "$VENDOR_EXECUTABLE" "$@"
    fi
done

# switcherooctl device 0 is the platform-declared default GPU, not a hardcoded
# Intel/AMD/NVIDIA choice. If switcheroo-control has no usable D-Bus topology,
# the Fedora helper deliberately execs the command unchanged.
if [[ -f $SWITCHEROOCTL && ! -L $SWITCHEROOCTL \
      && -x $SWITCHEROOCTL ]]; then
    exec "$SWITCHEROOCTL" launch --gpu=0 "$VENDOR_EXECUTABLE" "$@"
fi

exec "$VENDOR_EXECUTABLE" "$@"
