#!/usr/bin/env bash
# regenerate-icons.sh — generate the canonical icon set
#
# Generates all NoID Privacy branding icons on the build host so the runtime
# kickstart needs no ImageMagick dependency. Output goes to this directory
# (branding/icons/) and is shipped via Module 32's mandatory, SHA256-verified
# build-stage HTTP transport into the image during the lmc build.
#
# Two icon families:
#   1. NoID Privacy app launchers (7 names × 4 sizes = 28 PNGs)
#       setup/wizard/update/welcome/install/network/tools
#       - 48/64/128/256 px: logo + white outlined text label
#       - 'network' labels the NoID Privacy Network app (Module 36);
#         'tools' labels the NoID Privacy Tools app (Module 37).
#       - 'wizard' and 'welcome' are deliberate compatibility aliases for
#         older user-created launchers. New shipped launchers use 'setup';
#         retaining the aliases prevents a missing icon after an image update.
#   2. NoID Privacy logo size variants (8 sizes)
#       16/24/32/48/64/96/128/256 px scaled from 512px source
#       - Used by Module 32 to populate /usr/share/icons/hicolor/Nx N/apps/
#         (replaces former runtime `magick` resize block)
# Firefox Playground deliberately uses the unmodified `firefox` icon supplied
# by Fedora's Firefox package through icon-theme lookup. No duplicate or
# modified Firefox artwork is generated here.

set -euo pipefail

cd "$(dirname "$0")"
SRC_LOGO="../noid-privacy-logo.png"
SRC_LOGO_512="../noid-privacy-logo-512.png"

if [ ! -f "$SRC_LOGO" ]; then
    echo "ERROR: source logo not found: $SRC_LOGO"
    exit 1
fi
if [ ! -f "$SRC_LOGO_512" ]; then
    echo "ERROR: source logo-512 not found: $SRC_LOGO_512"
    exit 1
fi
if ! command -v magick >/dev/null 2>&1; then
    echo "ERROR: magick (ImageMagick 7) not installed on build host"
    echo "       sudo dnf install ImageMagick"
    exit 1
fi

# ============================================================================
# Family 1: NoID Privacy app launchers
# ============================================================================

declare -A LABELS=(
    [setup]="Setup"
    [wizard]="Wizard"
    [update]="Update"
    [welcome]="Welcome"
    [install]="Install"
    [network]="Network"
    [tools]="Tools"
)

# Text labels at ALL sizes provide visual disambiguation in the
# GNOME dock and Activities overview (which display 48/64 px in most cases).
# Bare logos at 48/64 made all five app icons look identical in the dock.
# pt + yoff calibrated against longest 7-char labels "Welcome" + "Install"
# at Liberation Sans Bold:
# Final style: white bold text with a black stroke,
# centered (gravity center, yoff = below center). Replaces the earlier
# undercolor band style (small white text on black bar at bottom) which was
# hard to read at 48/64 px.
#
# Calibration:
#   48px  → pt 7,  stroke 1, yoff 10  (text-strip lower-half of shield)
#   64px  → pt 10, stroke 1, yoff 14
#   128px → pt 22, stroke 2, yoff 28
#   256px → pt 44, stroke 4, yoff 56
declare -A LABELED_PT=([48]=7 [64]=10 [128]=22 [256]=44)
declare -A LABELED_SW=([48]=1 [64]=1 [128]=2 [256]=4)
declare -A LABELED_YOFF=([48]=10 [64]=14 [128]=28 [256]=56)

echo ""
echo "=== Family 1: NoID Privacy app launchers (7 names × 4 sizes = 28 PNGs, B-style) ==="

for name in "${!LABELS[@]}"; do
    label="${LABELS[$name]}"

    # B-style two-pass annotate at all 4 sizes
    for sz in 48 64 128 256; do
        ps="${LABELED_PT[$sz]}"
        sw="${LABELED_SW[$sz]}"
        yoff="${LABELED_YOFF[$sz]}"
        out="noid-privacy-${name}-${sz}.png"
        magick "$SRC_LOGO" \
            -filter Lanczos -resize "${sz}x${sz}" \
            -unsharp 0x0.75+0.75+0.008 \
            -font "Liberation-Sans-Bold" -pointsize "$ps" \
            -fill white -stroke black -strokewidth "$sw" \
            -gravity center -annotate "+0+${yoff}" "$label" \
            -fill white -stroke none \
            -annotate "+0+${yoff}" "$label" \
            "$out"
        printf "  B-style %5d bytes  %s  (label='%s' ps=%s sw=%s yoff=%s)\n" \
            "$(stat -c %s "$out")" "$out" "$label" "$ps" "$sw" "$yoff"
    done
done

# ============================================================================
# Family 2: NoID Privacy logo size variants (16/24/32/48/64/96/128/256)
# ============================================================================
# Replaces Module 32 runtime `magick` resize block. Used by GTK icon-name
# lookup for noid-privacy-logo at any standard hicolor size.

echo ""
echo "=== Family 2: noid-privacy-logo size variants (8 sizes) ==="

for sz in 16 24 32 48 64 96 128 256; do
    out="noid-privacy-logo-${sz}.png"
    magick "$SRC_LOGO_512" \
        -filter Lanczos -resize "${sz}x${sz}" \
        -unsharp 0x0.75+0.75+0.008 \
        "$out"
    printf "  logo    %5d bytes  %s\n" "$(stat -c %s "$out")" "$out"
done

# Strip metadata from generated PNGs. Defense-in-depth against
# author/timestamp/software metadata leak. ImageMagick's `-strip` excludes
# profile/text/date properties, but an input tIME chunk can survive a rewrite;
# exclude that PNG chunk explicitly while preserving image data.
echo ""
echo "Stripping metadata from generated PNGs..."
strip_targets=(noid-privacy-*.png)
magick mogrify -strip -define png:exclude-chunk=tIME "${strip_targets[@]}"
echo "  [OK] metadata stripped (EXIF + text + timestamp chunks removed)"

echo ""
echo "Summary:"
echo "  - 28 NoID Privacy app launcher PNGs   (7 names × 4 sizes)"
echo "  - 8  NoID Privacy logo size variants  (16/24/32/48/64/96/128/256)"
echo "  Total: 36 pre-rendered branding assets"
echo ""
ls -la noid-privacy-*.png 2>/dev/null \
    | awk '{printf "  %6s  %s\n", $5, $9}' \
    | wc -l \
    | xargs printf "  Files in branding/icons/: %s\n"
