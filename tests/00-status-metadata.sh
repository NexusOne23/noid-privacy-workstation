#!/usr/bin/env bash
# Every kickstart module must carry one dated/versioned LOCKED record and its
# current change (worktree first, otherwise newest commit) must move that
# record. A calendar-date comparison alone is insufficient: a same-day commit
# can hide a functional edit behind an earlier status bump.
set -euo pipefail

. "$(dirname "$0")/lib.sh"
ROOT=$(find_project_root)
GIT=(git -c core.filemode=false -C "$ROOT")
test_start "00-status-metadata"

# The published release tree is one parentless commit: every file then shares
# the release commit's date, so per-file lock provenance cannot exist there by
# construction. The Status-line format gates below still run everywhere; only
# the Git-history correlation is skipped. The development repository (full
# history) keeps enforcing it.
HISTORY_DEPTH=$("${GIT[@]}" rev-list --count HEAD 2>/dev/null || echo 0)

# Status provenance follows source content. Checkout filesystems may report
# executable-bit changes differently; executable contracts are asserted by
# their owning tests and must not turn an unchanged module into a false edit.
for file in "$ROOT/kickstart/master.ks" "$ROOT"/kickstart/snippets/*.ks; do
    rel=${file#"$ROOT"/}
    count=$(grep -c '^# Status:' "$file" || true)
    if [ "$count" -ne 1 ]; then
        _fail "$rel has exactly one Status line (found $count)"
        continue
    fi

    status=$(grep '^# Status:' "$file")
    if [[ ! $status =~ ^#\ Status:\ LOCKED\ ([0-9]{4}-[0-9]{2}-[0-9]{2})\ \(v[0-9]+(\.[0-9]+)*\)\ —\ .+\.$ ]]; then
        _fail "$rel Status line is dated/versioned LOCKED metadata"
        continue
    fi
    lock_date=${BASH_REMATCH[1]}
    if [ "$HISTORY_DEPTH" -le 1 ]; then
        printf '  [SKIP] %s lock provenance: single-commit release tree carries no per-file history\n' "$rel"
        continue
    fi
    commit_date=$("${GIT[@]}" log -1 --format=%cs -- "$rel")
    if [ -z "$commit_date" ]; then
        _fail "$rel has no Git provenance date"
    elif [[ $lock_date < $commit_date ]]; then
        _fail "$rel lock date $lock_date predates last source commit $commit_date"
    else
        _pass "$rel lock metadata current ($lock_date >= $commit_date)"
    fi

    if ! "${GIT[@]}" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
        _pass "$rel new untracked module carries its initial Status line"
        continue
    elif ! "${GIT[@]}" diff --quiet HEAD -- "$rel"; then
        # Read the whole listing: an awk `exit` closes the pipe while git may
        # still be writing, and with pipefail that SIGPIPE (141) aborts the test.
        old_rel=$("${GIT[@]}" diff --name-status -M HEAD -- |
            awk -v new="$rel" '!found && $1 ~ /^R[0-9]+$/ && $3 == new { print $2; found=1 }')
        diff_paths=("$rel")
        [ -z "$old_rel" ] || diff_paths=("$old_rel" "$rel")
        status_diff_count=$("${GIT[@]}" diff --unified=0 HEAD \
            -- "${diff_paths[@]}" |
            grep -Ec '^[+-]# Status:' || true)
        provenance="current worktree diff"
        expected_status_lines=2
    else
        latest_commit=$("${GIT[@]}" log -1 --format=%H -- "$rel")
        change_record=$("${GIT[@]}" diff-tree --no-commit-id --name-status \
            -r -M "$latest_commit" -- | \
            awk -v new="$rel" '!found && ($2 == new || $3 == new) { print; found=1 }')
        change_type=${change_record%%[[:space:]]*}
        old_rel=$(printf '%s\n' "$change_record" |
            awk '$1 ~ /^R[0-9]+$/ { print $2; exit }')
        show_paths=("$rel")
        [ -z "$old_rel" ] || show_paths=("$old_rel" "$rel")
        status_diff_count=$("${GIT[@]}" show --format= --unified=0 \
            "$latest_commit" -- "${show_paths[@]}" |
            grep -Ec '^[+-]# Status:' || true)
        provenance="newest commit ${latest_commit:0:12}"
        if [ "$change_type" = A ]; then
            expected_status_lines=1
        else
            expected_status_lines=2
        fi
    fi
    if [ "$status_diff_count" -eq "$expected_status_lines" ]; then
        _pass "$rel Status line moved with its $provenance"
    else
        _fail "$rel $provenance changed the module without moving its Status line"
    fi
done

# Published repository counts are release metadata too. Derive them from the
# tree instead of teaching this gate another magic number, then require every
# current-facing document to agree. Historical changelog entries are excluded:
# they describe the tree as it existed at that point in history.
structural_count=$(find "$ROOT/tests" -maxdepth 1 -type f \
    -name '[0-9][0-9]*-*.sh' -print | wc -l)
smoke_count=$(find "$ROOT/tests/smoke" -maxdepth 1 -type f \
    -name 'M*-smoke.sh' -print | wc -l)
total_count=$((structural_count + smoke_count))

assert_grep_fixed "tests-${structural_count}%2F${structural_count}%20pass" \
    "$ROOT/README.md" "README test badge matches discovered structural count"
assert_grep_fixed "# ${structural_count} structural tests" \
    "$ROOT/README.md" "README Quick Start count matches test discovery"
assert_grep_fixed "**${structural_count} structural + ${smoke_count} smoke regression tests**" \
    "$ROOT/README.md" "README repo summary count matches test discovery"
assert_grep_fixed "**${structural_count}/${structural_count} PASS**" \
    "$ROOT/README.md" "README all-green claim matches discovered structural count"
assert_grep_fixed "Full suite: **${structural_count} tests**" \
    "$ROOT/tests/README.md" "tests README structural count matches discovery"
assert_grep_fixed "= **${total_count} test scripts total**" \
    "$ROOT/tests/README.md" "tests README aggregate count matches discovery"
assert_grep_fixed "${structural_count} test programs" \
    "$ROOT/tests/smoke/README.md" "smoke README structural count matches discovery"
assert_grep_fixed "**Coverage**: ${structural_count} structural tests total" \
    "$ROOT/docs/test-strategy.md" "test strategy count matches discovery"
assert_grep_fixed "all ${structural_count} structural" \
    "$ROOT/docs/test-strategy.md" "CI test-strategy count matches discovery"
assert_grep_fixed "${structural_count}/${structural_count} pass" \
    "$ROOT/docs/CONTRIBUTING-technical.md" "contributor checklist count matches discovery"
assert_grep_fixed "${structural_count} structural test programs" \
    "$ROOT/docs/comparison.md" "comparison count matches discovery"
assert_grep_fixed "${structural_count}/${structural_count} structural" \
    "$ROOT/.github/pull_request_template.md" "PR structural checklist count matches discovery"
assert_grep_fixed "${smoke_count}/${smoke_count} smoke; prepared rootfs required" \
    "$ROOT/.github/pull_request_template.md" "PR smoke checklist count and prerequisite match discovery"
stamp_adopter_count=$(awk '
    /^EXPECTED_STAMPS=\($/ { in_stamps=1; next }
    in_stamps && /^\)$/ { exit }
    in_stamps && /^[[:space:]]+"[0-9]+:/ { count++ }
    END { print count+0 }
' "$ROOT/kickstart/snippets/99-finalize.ks")
assert_grep_fixed "migration pattern; ${stamp_adopter_count} modules" \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor health-stamp count matches finalizer discovery"
# Derive the documented adopter families from the finalizer's module numbers:
# consecutive numbers collapse into one M<first>-M<last> range.
stamp_adopter_families=$(awk '
    /^EXPECTED_STAMPS=\($/ { in_stamps=1; next }
    in_stamps && /^\)$/ { exit }
    in_stamps && /^[[:space:]]+"[0-9]+:/ {
        id=$1; gsub(/[^0-9:]/, "", id); sub(/:.*/, "", id); print id + 0
    }
' "$ROOT/kickstart/snippets/99-finalize.ks" | sort -n | awk '
    function flush() {
        if (start == "") return
        item = (start == prev) ? "M" start : "M" start "-M" prev
        items[++n] = item
    }
    { if (start != "" && $1 == prev + 1) { prev = $1; next } flush(); start = $1; prev = $1 }
    END {
        flush()
        for (i = 1; i <= n; i++) {
            printf "%s", items[i]
            if (i < n - 1) printf ", "
            else if (i == n - 1) printf " and "
        }
        printf "\n"
    }
')
assert_grep_fixed "$stamp_adopter_families" \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor health-stamp inventory lists every current adopter family ($stamp_adopter_families)"
assert_not_grep 'cat > "$STAMP"' \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor guide never recommends direct final-stamp publication"
assert_grep_fixed 'M28_HEALTH_INVALIDATION_BEGIN' \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor guide requires the canonical stale-evidence boundary"
assert_not_grep_extended \
    'exact [0-9]+-module health-stamp|adopter set \(M[0-9]' \
    "$ROOT/CHANGELOG.md" \
    "release highlights omit dynamic internal health-stamp inventories"
stamp_count_words=(zero one two three four five six seven eight nine ten
    eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen
    nineteen twenty)
if [ "$stamp_adopter_count" -lt "${#stamp_count_words[@]}" ]; then
    stamp_count_word=${stamp_count_words[$stamp_adopter_count]}
    assert_grep_fixed "${stamp_count_word^} modules implement the failure-atomic contract" \
        "$ROOT/docs/engineering-health-stamp-pattern.md" \
        "health-stamp design status matches finalizer discovery"
else
    _fail "health-stamp adopter count $stamp_adopter_count has no spelled-out form here"
fi
unset stamp_count_words stamp_count_word stamp_adopter_families
assert_grep_fixed "closed \`EXPECTED_STAMPS\` array of ${stamp_adopter_count} exact" \
    "$ROOT/docs/engineering-health-stamp-pattern.md" \
    "health-stamp design count matches finalizer discovery"
assert_grep_fixed '| 37 | **yes** |' \
    "$ROOT/docs/engineering-health-stamp-pattern.md" \
    "health-stamp design inventory includes Module 37"
assert_grep_fixed '`--setopt=install_weak_deps=False` explicitly' \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor DNF5 recipe uses the maintained weak-dependency option"
assert_not_grep '`--exclude-weakdeps` is mandatory' \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor guide does not pass a Kickstart-only option to DNF5"
assert_grep_fixed "<<'USER_DOC_EOF'" "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor documentation template disables shell interpolation"
assert_grep_fixed 'Snippet order CRITICAL CONSTRAINTS' \
    "$ROOT/docs/CONTRIBUTING-technical.md" \
    "contributor guide delegates include ordering to the canonical list"
assert_not_grep 'Supply-chain gate (Rule 11)' \
    "$ROOT/.github/pull_request_template.md" \
    "PR template cites no nonexistent numbered rule"
assert_grep_fixed 'before M37). Some snippets harden the base,' "$ROOT/INDEX.md" \
    "repository index records the dependency-driven include inversion"
# INDEX names the modules that embed the MIT notices and the stager of each
# Lorax patch; both claims are checked against the actual sources.
assert_grep_fixed 'M16 and M35 embed the MIT notices byte-for-byte' "$ROOT/INDEX.md" \
    "repository index attributes the MIT notices to M16 and M35"
assert_not_grep 'M16/M35/M31 embed the MIT notices' "$ROOT/INDEX.md" \
    "repository index does not attribute the MIT notices to M31"
assert_grep_fixed 'ARKENFOX_LICENSE="$LICENSE_DIR/arkenfox-user.js-MIT.txt"' \
    "$ROOT/kickstart/snippets/16-firefox.ks" "M16 installs the arkenfox MIT notice"
assert_grep_fixed 'HORLOGESKYNET_LICENSE="$LICENSE_DIR/horlogeskynet-thunderbird-user.js-MIT.txt"' \
    "$ROOT/kickstart/snippets/35-thunderbird.ks" "M35 installs the HorlogeSkynet MIT notice"
assert_not_grep '_LICENSE="$LICENSE_DIR/.*-MIT.txt"' \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    "M31 installs no MIT notice of its own"
for lorax_patch in 0001-drain-monitor-before-shutdown 0002-precompute-live-required-space \
        0003-terminate-cancelled-process; do
    assert_grep_fixed "overrides/lorax/$lorax_patch.patch" \
        "$ROOT/scripts/stage-lorax-overrides.sh" \
        "stage-lorax-overrides.sh stages $lorax_patch as INDEX states"
done
assert_grep_fixed 'overrides/lorax/0004-live-menu-default.patch' \
    "$ROOT/scripts/stage-lorax-templates.sh" \
    "stage-lorax-templates.sh stages 0004 as INDEX states"
assert_not_grep '0004-live-menu-default' "$ROOT/scripts/stage-lorax-overrides.sh" \
    "stage-lorax-overrides.sh does not stage the live-menu patch"
assert_grep_fixed '`scripts/stage-lorax-templates.sh` stages 0004' "$ROOT/INDEX.md" \
    "repository index names the stager of the live-menu patch"
assert_grep_fixed 'Fedora vendor file contains `<disable />`' \
    "$ROOT/docs/firewall-policies-explained.md" \
    "firewall guide attributes gateway policy disablement to Fedora"
assert_grep_fixed '1ACBFCE49687FEBB91010E52F8E3F11D6962256F' "$ROOT/docs/gpg-trust-chain.md" \
    "release trust guide names the exact release signing key"
assert_grep_fixed '/etc/sysctl.d/99-audit-fixes.conf' \
    "$ROOT/docs/migration-from-vanilla.md" \
    "migration guide inventories every M02 sysctl file"
assert_grep_fixed '`99-userns.conf`.' "$ROOT/docs/migration-from-vanilla.md" \
    "migration guide includes M02's user-namespace file"

# The tests README calls its first table the complete structural inventory.
# Parse only that table and require an exact one-to-one set: a filename merely
# mentioned in prose or in the separate Pre-Ship block must not produce a
# false-green inventory result.
declare -A documented_structural=()
structural_table_rows=0
inventory_errors=0
while IFS= read -r test_base; do
    [ -n "$test_base" ] || continue
    structural_table_rows=$((structural_table_rows + 1))
    if [[ -n ${documented_structural[$test_base]+present} ]]; then
        _fail "tests README structural table lists $test_base more than once"
        inventory_errors=$((inventory_errors + 1))
    fi
    documented_structural["$test_base"]=1
done < <(
    awk '
        /^## Current tests$/ { in_table = 1; next }
        /^## Pre-ship gates$/ { exit }
        in_table && /^\| `[^`]+\.sh` \|/ {
            entry = $0
            sub(/^\| `/, "", entry)
            sub(/` \|.*$/, "", entry)
            print entry
        }
    ' "$ROOT/tests/README.md"
)

for test_file in "$ROOT"/tests/[0-9][0-9]*-*.sh; do
    test_base=$(basename "$test_file")
    if [[ -z ${documented_structural[$test_base]+present} ]]; then
        _fail "tests README structural table omits $test_base"
        inventory_errors=$((inventory_errors + 1))
    fi
done
for test_base in "${!documented_structural[@]}"; do
    if [ ! -f "$ROOT/tests/$test_base" ]; then
        _fail "tests README structural table has stale/non-structural entry $test_base"
        inventory_errors=$((inventory_errors + 1))
    fi
done
if [ "$structural_table_rows" -ne "$structural_count" ]; then
    _fail "tests README structural table has $structural_table_rows rows, expected $structural_count"
    inventory_errors=$((inventory_errors + 1))
elif [ "$inventory_errors" -eq 0 ]; then
    _pass "tests README structural table exactly matches discovered programs"
fi

# The following block is the canonical executable Pre-Ship inventory. Require
# every referenced script to exist and every current script to be referenced;
# multiple phase/action commands for one script remain valid.
declare -A documented_pre_ship=()
while IFS= read -r pre_ship_base; do
    [ -n "$pre_ship_base" ] || continue
    documented_pre_ship["$pre_ship_base"]=1
done < <(
    awk '
        /^## Pre-ship gates$/ { in_block = 1; next }
        /^## / && in_block { exit }
        in_block { print }
    ' "$ROOT/tests/README.md" |
        grep -oE 'tests/pre-ship/[A-Za-z0-9._-]+\.sh' |
        sed 's#^tests/pre-ship/##' |
        sort -u
)

pre_ship_errors=0
for pre_ship_file in "$ROOT"/tests/pre-ship/*.sh; do
    pre_ship_base=$(basename "$pre_ship_file")
    if [[ -z ${documented_pre_ship[$pre_ship_base]+present} ]]; then
        _fail "tests README Pre-Ship block omits $pre_ship_base"
        pre_ship_errors=$((pre_ship_errors + 1))
    fi
done
for pre_ship_base in "${!documented_pre_ship[@]}"; do
    if [ ! -f "$ROOT/tests/pre-ship/$pre_ship_base" ]; then
        _fail "tests README Pre-Ship block has stale entry $pre_ship_base"
        pre_ship_errors=$((pre_ship_errors + 1))
    fi
done
if [ "$pre_ship_errors" -eq 0 ]; then
    _pass "tests README Pre-Ship block exactly covers discovered scripts"
fi

# Shipped Markdown and module counts are repeated in user-facing summaries.
# Derive both from their actual source-of-truth paths so future additions force
# the documentation update in the same change.
user_doc_count=$(
    {
        grep -RhE '^cat > /usr/share/doc/noid-privacy/[^ ]+\.md <<' \
            "$ROOT/kickstart/snippets" \
            | sed -E 's|^cat > (/usr/share/doc/noid-privacy/[^ ]+\.md) <<.*|\1|'
        grep -RhE '^# Shipped Markdown target: /usr/share/doc/noid-privacy/[^ ]+\.md$' \
            "$ROOT/kickstart/snippets" \
            | sed -E 's|^# Shipped Markdown target: ||'
    } | sort -u | wc -l
)
snippet_count=$(find "$ROOT/kickstart/snippets" -maxdepth 1 -type f \
    -name '*.ks' -print | wc -l)
functional_module_count=$((snippet_count - 1)) # exclude 99-finalize
kickstart_count=$((snippet_count + 1))         # include master.ks

assert_grep_fixed "**${user_doc_count} user-doc pages**" "$ROOT/README.md" \
    "README shipped user-doc count matches heredoc discovery"
assert_grep_fixed "and ${user_doc_count} AI-navigable docs" "$ROOT/README.md" \
    "README overview AI-doc count matches heredoc discovery"
assert_grep_fixed "+ ${user_doc_count} AI-navigable user docs" "$ROOT/README.md" \
    "README feature-table AI-doc count matches heredoc discovery"
assert_grep_fixed "| **AI-navigable docs corpus** | ${user_doc_count} user docs" \
    "$ROOT/README.md" \
    "README AI-doc corpus count matches heredoc discovery"
assert_grep_fixed "${user_doc_count} installed user-document pages" \
    "$ROOT/docs/comparison.md" "comparison user-doc count matches discovery"
assert_grep_fixed "modules-${functional_module_count}-blue" "$ROOT/README.md" \
    "README module badge matches snippet discovery"
assert_grep_fixed "**${functional_module_count} functional modules** provide the hardening baseline" \
    "$ROOT/README.md" "README overview module count matches snippet discovery"
assert_grep_fixed "${functional_module_count} 個功能模組涵蓋縱深防禦、第一方工具與文件" \
    "$ROOT/README.md" "README Traditional Chinese module count matches discovery"
assert_grep_fixed "${functional_module_count} 个功能模块涵盖纵深防御、第一方工具与文档" \
    "$ROOT/README.md" "README Simplified Chinese module count matches discovery"
assert_not_grep_extended 'across [0-9]+ functional' \
    "$ROOT/kickstart/snippets/32-branding.ks" \
    "installed trademark text carries no mutable module-count claim"
assert_grep_fixed "**${kickstart_count} kickstart files**" "$ROOT/README.md" \
    "README kickstart count matches discovery"
assert_grep_fixed "Four complementary layers of testing" \
    "$ROOT/docs/test-strategy.md" \
    "test strategy has one internally consistent layer count"
assert_grep_fixed "(M01–M37 + M11b + M40 + M41 + M42)" \
    "$ROOT/docs/test-strategy.md" \
    "test strategy includes every functional module family"
assert_grep_fixed "**Coverage**: ${kickstart_count} kickstart files (master.ks + ${snippet_count} snippets including 99-finalize)" \
    "$ROOT/docs/test-strategy.md" \
    "test strategy kickstart count matches discovery"
assert_eq 2 \
    "$(grep -cF 'branches: [main]' "$ROOT/.github/workflows/ci.yml")" \
    "CI targets the repository's single canonical main branch"
assert_not_grep_extended 'branches:.*master' \
    "$ROOT/.github/workflows/ci.yml" \
    "CI carries no retired master target"
assert_grep_fixed 'GitHub Actions workflow runs on every push + PR to `main`.' \
    "$ROOT/docs/test-strategy.md" \
    "test strategy names the actual CI target branch"

# Current-facing documentation must describe the single-Status-line
# convention, not per-change lock-history blocks.
for current_surface in \
    "$ROOT/README.md" \
    "$ROOT/.gitignore" \
    "$ROOT/docs/firewall-policies-explained.md"; do
    assert_not_grep_extended \
        'lock-history header|design \+ lock-history|lock-history rationale' \
        "$current_surface" \
        "$(basename "$current_surface") has no retired lock-history contract"
done

test_finish
