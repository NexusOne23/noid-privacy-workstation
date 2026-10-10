# Collapse the one canonical ksflatten partition block used by Lorax. The
# installed-system kickstart remains untouched. KVM receives its deterministic
# sda binding; no-virt receives the generic single-root layout expected by
# Anaconda dirinstall and must not name a nonexistent host disk. Every marker
# is a closed singleton: missing, duplicated, reordered or format-drifted
# anchors fail before build-iso.sh publishes the staged output.
BEGIN {
    collapsing = 0
    done = 0
    invalid = 0
    starts = 0
    ends = 0
}

$0 == "zerombr" {
    starts++
    if (starts != 1 || collapsing || done) {
        invalid = 1
        next
    }
    if (no_virt) {
        print "clearpart --all --initlabel"
        print "part / --fstype=\"ext4\" --size=12000"
    } else {
        print "zerombr"
        print "clearpart --all --initlabel --drives=sda"
        print "part / --fstype=\"ext4\" --size=12000 --ondisk=sda"
    }
    collapsing = 1
    next
}

$0 == "part / --fstype=\"ext4\" --size=12000" {
    ends++
    if (ends != 1 || !collapsing || done) {
        invalid = 1
        next
    }
    collapsing = 0
    done = 1
    next
}

collapsing { next }
{ print }

END {
    if (invalid || collapsing || !done || starts != 1 || ends != 1) {
        exit 3
    }
}
