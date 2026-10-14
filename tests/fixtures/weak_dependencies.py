#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Policy acceptance and drift controls for the native dependency gate."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('weak_gate', root / 'scripts/verify-weak-dependencies.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
policy = gate.load_policy(root / 'manifests/weak-dependencies.json')
assert policy['exceptions'] and 'libcap-ng-python3' in policy['required']
assert 'python3-defusedxml' in policy['required']
known = copy.deepcopy(policy['exceptions'][0])
valid = gate.evaluate(set(policy['required']), [known], policy)
assert valid['verdict'] == 'pass' and not valid['unreviewed']
checks = 1
for relation in sorted(gate.RELATIONS):
    unknown = {'package': 'fixture-consumer', 'relation': relation,
               'expression': 'unreviewed-native-capability >= 2', 'providers': ['fixture-provider']}
    result = gate.evaluate(set(policy['required']), [known, unknown], policy)
    assert result['verdict'] == 'fail' and result['unreviewed'] == [unknown]
    checks += 1
changed = dict(known, expression=known['expression'] + ' changed')
assert gate.evaluate(set(policy['required']), [changed], policy)['verdict'] == 'fail'
checks += 1
for name in policy['required']:
    result = gate.evaluate(set(policy['required']) - {name}, [known], policy)
    assert result['verdict'] == 'fail' and result['required_missing'] == [name]
    checks += 1
try:
    gate.evaluate(set(), [], policy)
except ValueError:
    checks += 1
else:
    raise AssertionError('empty RPM inventory passed')

with tempfile.TemporaryDirectory(prefix='noid-weak-policy-fixture-') as tmp:
    path = Path(tmp) / 'policy.json'
    invalid = []
    for mutation in ('schema', 'required', 'exceptions', 'extra'):
        item = copy.deepcopy(policy)
        item[mutation] = {'schema': 999, 'required': ['*'], 'exceptions': {}, 'extra': True}[mutation]
        invalid.append(json.dumps(item))
    item = copy.deepcopy(policy)
    item['exceptions'].append(item['exceptions'][0])
    invalid.append(json.dumps(item))
    for field, value in (('reason', ''), ('relation', 'requires'), ('package', '*')):
        item = copy.deepcopy(policy)
        item['exceptions'][0][field] = value
        invalid.append(json.dumps(item))
    invalid.extend(['{"schema":1,"schema":1}', '{broken'])
    for text in invalid:
        path.write_text(text)
        try:
            gate.load_policy(path)
        except (ValueError, TypeError):
            checks += 1
        else:
            raise AssertionError('malformed policy passed')

builder = (root / 'scripts/build-iso.sh').read_text()
wrapper = (root / 'scripts/verify-live-image-hygiene.sh').read_text()
assert '"$COMPOSE_METALINK_DIR" "$WEAK_DEPENDENCY_REPORT"; then' in builder
assert 'weak-dependency report lacks its exact pass verdict' in builder
assert '"$PRIVATE_BUILD_EVIDENCE/weak-dependencies.json"' in builder
assert '--root "$ROOT_PATH" --metadata "$METALINK_DIR"' in wrapper
assert '[ "$dependency_rc" -eq 0 ] || exit "$dependency_rc"' in wrapper
print(f'PASS: {checks} weak-dependency policy controls and canonical build wiring')
