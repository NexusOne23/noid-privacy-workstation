#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline adversarial fixtures for the compose metadata trust boundary."""
import base64
import importlib.util
from pathlib import Path
import shlex
import sys
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('compose_metalinks', ROOT / 'scripts/prepare-compose-metalinks.py')
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
XML = b'''<?xml version="1.0"?>
<metalink xmlns="http://www.metalinker.org/" xmlns:mm0="http://fedorahosted.org/mirrormanager" version="3.0">
<files><file name="repomd.xml"><mm0:timestamp>200</mm0:timestamp><size>300</size>
<verification><hash type="sha256">''' + b'a' * 64 + b'''</hash><hash type="sha512">''' + b'b' * 128 + b'''</hash></verification>
<mm0:alternates><mm0:alternate><mm0:timestamp>100</mm0:timestamp><size>200</size>
<verification><hash type="sha256">''' + b'c' * 64 + b'''</hash></verification></mm0:alternate></mm0:alternates>
<resources><url protocol="https" type="https" preference="100">https://mirror.example.test/fedora/repodata/repomd.xml</url></resources>
</file></files></metalink>'''
KS = ('url --metalink="' + HELPER.SOURCES['fedora'] + '"\n'
      'repo --name="fedora-updates" --metalink="' + HELPER.SOURCES['updates'] + '"\n'
      '%post\ncat > /etc/yum.repos.d/preserved.repo <<\'EOF\'\n'
      'repo --name="fedora-updates" --metalink="' + HELPER.SOURCES['updates'] + '"\n'
      'EOF\n%end\nshutdown\n')
GUEST_DIR = '/run/noid-compose-metalinks-' + 'd' * 16


class MetalinkTests(unittest.TestCase):
    def test_metadata_only_cli_retains_private_evidence(self):
        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory(prefix='noid-metalink-cli-', dir='/var/tmp') as directory:
            target = Path(directory) / 'metadata'
            with mock.patch.object(sys, 'argv', ['helper', str(target)]), \
                    mock.patch.object(HELPER.subprocess, 'run', return_value=
                                      subprocess.CompletedProcess([], 0, stdout=XML)) as fetch:
                HELPER.main()
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(sorted(p.name for p in target.iterdir()), [
                'compose-metalinks.json', 'fedora-current.xml', 'fedora-upstream.xml',
                'updates-current.xml', 'updates-upstream.xml'])
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for file in target.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            filtered, _ = HELPER.current_metalink(XML)
            self.assertEqual((target / 'updates-current.xml').read_bytes(), filtered)

    def test_failed_second_source_cannot_publish_a_partial_kickstart(self):
        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory(prefix='noid-metalink-cli-', dir='/var/tmp') as directory:
            ks = Path(directory) / 'flat.ks'
            ks.write_text(KS)
            evidence = Path(directory) / 'metadata'
            replies = [subprocess.CompletedProcess([], 0, stdout=XML),
                       subprocess.CompletedProcess([], 0, stdout=b'invalid')]
            with mock.patch.object(sys, 'argv', ['helper', '--kickstart', str(ks), str(evidence)]), \
                    mock.patch.object(HELPER.subprocess, 'run', side_effect=replies), \
                    self.assertRaises(ET.ParseError):
                HELPER.main()
            self.assertEqual(ks.read_text(), KS)
            self.assertFalse((evidence / 'compose-metalinks.json').exists())
            self.assertTrue((evidence / 'updates-upstream.xml').exists())

    def test_primary_and_all_https_mirrors_survive(self):
        filtered, report = HELPER.current_metalink(XML)
        old = ET.fromstring(XML).find('m:files/m:file', HELPER.NS)
        new = ET.fromstring(filtered).find('m:files/m:file', HELPER.NS)
        self.assertEqual(report['removed_older_alternatives'], 1)
        self.assertEqual(report['primary_repomd_sha256'], 'a' * 64)
        for child in ('m:verification', 'm:resources', 'm:size', 'mm:timestamp'):
            self.assertEqual(ET.tostring(old.find(child, HELPER.NS)), ET.tostring(new.find(child, HELPER.NS)))
        self.assertFalse(new.findall('mm:alternates', HELPER.NS))
        self.assertIn(b'<metalink ', filtered)
        self.assertIn(b'<file name="repomd.xml">', filtered)
        self.assertNotIn(b'ns0:', filtered)

    def test_current_only_document_is_supported(self):
        filtered, _ = HELPER.current_metalink(XML)
        again, report = HELPER.current_metalink(filtered)
        self.assertEqual(again, filtered)
        self.assertEqual(report['removed_older_alternatives'], 0)

    def test_rejects_invalid_trust_inputs(self):
        cases = {
            'empty': b'', 'oversized': b'x' * (HELPER.MAX_BYTES + 1),
            'doctype': XML.replace(b'<metalink ', b'<!DOCTYPE test><metalink ', 1),
            'wrong-schema': XML.replace(b'version="3.0"', b'version="4.0"'),
            'wrong-file': XML.replace(b'name="repomd.xml"', b'name="other.xml"'),
            'duplicate-file': XML.replace(b'</files>', b'<file name="repomd.xml"/></files>'),
            'hidden-extra-file': XML.replace(b'</metalink>', b'<other><file name="repomd.xml"/></other></metalink>'),
            'missing-sha256': XML.replace(b'type="sha256"', b'type="unknown"', 1),
            'missing-sha512': XML.replace(b'type="sha512"', b'type="unknown"', 1),
            'duplicate-sha256': XML.replace(b'</verification>', b'<hash type="sha256">' + b'a'*64 + b'</hash></verification>', 1),
            'bad-digest': XML.replace(b'a'*64, b'z'*64),
            'bad-size': XML.replace(b'<size>300</size>', b'<size>0</size>'),
            'bad-time': XML.replace(b'<mm0:timestamp>200</mm0:timestamp>', b'<mm0:timestamp>0</mm0:timestamp>'),
            'newer-alternate': XML.replace(b'<mm0:timestamp>100</mm0:timestamp>', b'<mm0:timestamp>300</mm0:timestamp>'),
            'plaintext': XML.replace(b'https://mirror.', b'http://mirror.'),
            'credentials': XML.replace(b'https://mirror.', b'https://name:password@mirror.'),
            'empty-credentials': XML.replace(b'https://mirror.', b'https://@mirror.'),
            'no-mirrors': XML.replace(b'<resources>', b'<unused>').replace(b'</resources>', b'</unused>'),
        }
        for name, data in cases.items():
            with self.subTest(name=name), self.assertRaises((ValueError, ET.ParseError)):
                HELPER.current_metalink(data)

    def test_only_top_level_sources_change(self):
        payload, _ = HELPER.current_metalink(XML)
        result = HELPER.prepare_kickstart(KS, dict.fromkeys(HELPER.SOURCES, payload), GUEST_DIR)
        self.assertIn(KS.split('%post', 1)[1], result)
        lines = result.splitlines()
        self.assertEqual(shlex.split(lines[0]), ['url', '--metalink=file://' + GUEST_DIR + '/fedora.xml'])
        self.assertEqual(shlex.split(lines[1]), ['repo', '--name=fedora-updates', '--metalink=file://' + GUEST_DIR + '/updates.xml'])
        self.assertEqual(result.count(HELPER.MARKER), 1)
        self.assertIn(base64.b64encode(payload).decode(), result)

    def test_rejects_kickstart_drift(self):
        payloads = dict.fromkeys(HELPER.SOURCES, b'fixture')
        for text in (KS + KS, KS.replace('url --metalink=', 'url --mirrorlist=', 1),
                     KS.replace('fedora-44&', 'fedora-45&', 1), KS + '%post\n', KS + HELPER.MARKER,
                     KS + 'url --url=https://unexpected.example.test/repo/\n',
                     KS + 'repo --name=unexpected --baseurl=https://unexpected.example.test/repo/\n'):
            with self.subTest(text=text[:50]), self.assertRaises(ValueError):
                HELPER.prepare_kickstart(text, payloads, GUEST_DIR)
        with self.assertRaises(ValueError):
            HELPER.prepare_kickstart(KS, {'fedora': b''}, GUEST_DIR)
        with self.assertRaises(ValueError):
            HELPER.prepare_kickstart(KS, payloads, '/etc/unsafe')

    def test_generated_pre_runs_only_in_a_private_fixture(self):
        import ast
        import tempfile
        payload, _ = HELPER.current_metalink(XML)
        generated = HELPER.prepare_kickstart(KS, dict.fromkeys(HELPER.SOURCES, payload), GUEST_DIR)
        pre = generated.split('%pre --erroronfail --interpreter=/usr/bin/python3\n', 1)[1].split('\n%end', 1)[0]
        # Replace only the literal guest staging directory in the parsed AST.
        # The real /run path must never be written by a source test.
        tree = ast.parse(pre)
        assignments = [n for n in tree.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'directory' for t in n.targets)]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(assignments[0].value.value, GUEST_DIR)
        with tempfile.TemporaryDirectory(prefix='noid-metalink-pre-', dir='/var/tmp') as directory:
            target = Path(directory) / 'guest-run'
            assignments[0].value = ast.Constant(str(target))
            ast.fix_missing_locations(tree)
            exec(compile(tree, '<compose-pre-fixture>', 'exec'), {})
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            self.assertEqual(sorted(p.name for p in target.iterdir()), ['fedora.xml', 'updates.xml'])
            for name in HELPER.SOURCES:
                self.assertEqual((target / (name + '.xml')).read_bytes(), payload)
                self.assertEqual((target / (name + '.xml')).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                exec(compile(tree, '<compose-pre-fixture>', 'exec'), {})


if __name__ == '__main__':
    unittest.main()
