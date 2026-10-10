#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject unreviewed weak dependencies in a composed Fedora image.

Query a private copy of its RPM database and the compose's current-only Fedora
metadata. Never install packages, run plugins, or modify the inspected root.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile


RELATIONS = {'recommends', 'suggests', 'supplements', 'enhances'}
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.-]*')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def record_key(row):
    return row['package'], row['relation'], row['expression']


def load_policy(path):
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    policy = json.loads(path.read_text(), object_pairs_hook=unique_keys)
    require(isinstance(policy, dict) and set(policy) == {'schema', 'required', 'exceptions'},
            'unexpected weak-dependency policy fields')
    require(type(policy['schema']) is int and policy['schema'] == 1, 'unsupported policy schema')
    required = policy['required']
    require(isinstance(required, list) and required
            and all(isinstance(n, str) and NAME.fullmatch(n) for n in required)
            and len(required) == len(set(required)), 'invalid required package inventory')
    require(isinstance(policy['exceptions'], list), 'invalid exception inventory')
    seen = set()
    for row in policy['exceptions']:
        require(isinstance(row, dict) and set(row) == {'package', 'relation', 'expression', 'reason'},
                'unexpected exception fields')
        require(all(isinstance(v, str) and v.strip() == v and v for v in row.values()),
                'empty or malformed exception')
        require(NAME.fullmatch(row['package']) and row['relation'] in RELATIONS,
                'invalid exception identity')
        require('\n' not in row['expression'] and '\x00' not in row['expression'],
                'invalid dependency expression')
        key = record_key(row)
        require(key not in seen, 'duplicate dependency exception')
        seen.add(key)
    return policy


def evaluate(installed_names, missing, policy):
    require(installed_names, 'empty installed package inventory')
    allowed = {record_key(row) for row in policy['exceptions']}
    observed = {record_key(row) for row in missing}
    unknown = [row for row in missing if record_key(row) not in allowed]
    required_missing = sorted(set(policy['required']) - set(installed_names))
    return {
        'verdict': 'fail' if unknown or required_missing else 'pass',
        'installed_packages': len(installed_names),
        'required_missing': required_missing,
        'unreviewed': unknown,
        'reviewed_missing': [row for row in missing if record_key(row) in allowed],
        'unused_exceptions': [list(key) for key in sorted(allowed - observed)],
    }


def collect_dependencies(installed, available):
    """Use libsolv's native rich/versioned dependency evaluation, not names."""
    import libdnf5.rpm
    names = {p.get_name() for p in installed}
    identities = {(p.get_name(), p.get_arch()) for p in installed}
    require(names, 'empty installed package inventory')
    missing = {}
    scanned = dict.fromkeys(RELATIONS, 0)
    for package in installed:
        for relation in ('recommends', 'suggests'):
            for dep in getattr(package, 'get_' + relation)():
                scanned[relation] += 1
                if installed.is_dep_satisfied(dep):
                    continue
                providers = libdnf5.rpm.PackageQuery(available)
                providers.filter_provides(dep)
                row = {'package': package.get_name(), 'relation': relation,
                       'expression': dep.to_string(),
                       'providers': sorted({p.get_name() for p in providers})}
                missing[record_key(row)] = row
    for package in available:
        if (package.get_name(), package.get_arch()) in identities:
            continue
        for relation in ('supplements', 'enhances'):
            for dep in getattr(package, 'get_' + relation)():
                scanned[relation] += 1
                if installed.is_dep_satisfied(dep):
                    row = {'package': package.get_name(), 'relation': relation,
                           'expression': dep.to_string(), 'providers': [package.get_name()]}
                    missing[record_key(row)] = row
    return names, [missing[key] for key in sorted(missing)], scanned


def regular(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink()
            and path.resolve() == path, 'expected a canonical regular file')
    return path


def configure(root, metadata, work):
    import libdnf5.base
    database = regular(root / 'usr/lib/sysimage/rpm/rpmdb.sqlite')
    for suffix in ('-wal', '-journal'):
        sidecar = Path(str(database) + suffix)
        require(not sidecar.exists() or sidecar.stat().st_size == 0,
                'RPM database has pending journal data')
    copied = work / 'root/usr/lib/sysimage/rpm/rpmdb.sqlite'
    copied.parent.mkdir(parents=True)
    with sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True) as source:
        with sqlite3.connect(copied) as dest:
            source.backup(dest)
            require(dest.execute('PRAGMA quick_check').fetchall() == [('ok',)],
                    'RPM database integrity failure')

    helper = Path(__file__).with_name('prepare-compose-metalinks.py')
    spec = importlib.util.spec_from_file_location('compose_metalinks', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    provenance = json.loads(regular(metadata / 'compose-metalinks.json').read_text())
    for name in ('fedora', 'updates'):
        blob = regular(metadata / (name + '-current.xml')).read_bytes()
        _, details = module.current_metalink(blob)
        require(details['removed_older_alternatives'] == 0, 'older metadata alternative present')
        expected = provenance[name]
        require(hashlib.sha256(blob).hexdigest() == expected['current_only_sha256']
                and details['primary_repomd_sha256'] == expected['primary_repomd_sha256'],
                'compose metadata identity mismatch')

    base = libdnf5.base.Base()
    cfg = base.get_config()
    cfg.get_installroot_option().set(str(work / 'root'))
    cfg.get_plugins_option().set(False)
    cfg.get_reposdir_option().set([])
    cfg.get_varsdir_option().set([])
    cfg.get_install_weak_deps_option().set(False)
    cfg.get_optional_metadata_types_option().set(['filelists'])
    for field in ('cachedir', 'system_cachedir', 'persistdir', 'logdir'):
        directory = work / field
        directory.mkdir()
        getattr(cfg, 'get_' + field + '_option')().set(str(directory))
    base.get_vars().set('releasever', '44')
    base.setup()
    sack = base.get_repo_sack()
    for name in ('fedora', 'updates'):
        repo = sack.create_repo(name)
        rcfg = repo.get_config()
        rcfg.get_metalink_option().set((metadata / (name + '-current.xml')).as_uri())
        rcfg.get_skip_if_unavailable_option().set(False)
        rcfg.get_sslverify_option().set(True)
        rcfg.get_pkg_gpgcheck_option().set(True)
        repo.enable()
    sack.load_repos()
    return base, {name: provenance[name]['primary_repomd_sha256'] for name in ('fedora', 'updates')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('root', 'metadata', 'policy', 'report', 'work-parent'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for path in (args.root, args.metadata, args.work_parent, args.report.parent):
        require(path.is_absolute() and path.is_dir() and not path.is_symlink()
                and path.resolve() == path, 'expected a canonical directory')
    require(args.root != Path('/'), 'the build gate must not inspect the running host')
    require(not args.report.exists() and not args.report.is_symlink(), 'report already exists')
    policy_path = regular(args.policy)
    policy = load_policy(policy_path)
    result = {'schema': 'NOID_WEAK_DEPENDENCIES_V1', 'verdict': 'fail',
              'policy_sha256': hashlib.sha256(policy_path.read_bytes()).hexdigest()}
    try:
        import libdnf5.rpm
        with tempfile.TemporaryDirectory(prefix='noid-weak-dependencies-', dir=args.work_parent) as tmp:
            base, metadata = configure(args.root, args.metadata, Path(tmp))
            installed = libdnf5.rpm.PackageQuery(base)
            installed.filter_installed()
            available = libdnf5.rpm.PackageQuery(base)
            available.filter_available()
            available.filter_arch(['x86_64', 'noarch'])
            available.filter_latest_evr()
            require(available.size() > 0, 'empty Fedora package inventory')
            names, missing, scanned = collect_dependencies(installed, available)
            result.update(evaluate(names, missing, policy))
            result.update(scanned=scanned, repository_metadata=metadata)
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    with args.report.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    if result['verdict'] != 'pass':
        print('weak-dependencies: FAIL: missing required package, unreviewed relationship, or query failure')
        return 1
    print('weak-dependencies: PASS: every unmet relationship has an explicit policy decision')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
