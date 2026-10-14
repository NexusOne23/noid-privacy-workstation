#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Select Fedora's current primary Metalink checksums for release checks.

Fedora also advertises older, valid repomd alternatives during mirror rollout.
Keep the native Metalink downloader, HTTPS mirrors and package verification;
remove only that older-metadata allowance for a compose or freshness query.
The normal installed repository configuration is never an output of this helper.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import tempfile
import xml.etree.ElementTree as ET

METALINK = 'http://www.metalinker.org/'
MIRRORMANAGER = 'http://fedorahosted.org/mirrormanager'
NS = {'m': METALINK, 'mm': MIRRORMANAGER}
MAX_BYTES = 1024 * 1024
SOURCES = {
    'fedora': 'https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64&protocol=https',
    'updates': 'https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64&protocol=https',
}
MARKER = '# BEGIN NOID_COMPOSE_CURRENT_METALINKS'


def current_metalink(blob):
    """Validate the publisher document and retain its primary file identity."""
    if not 0 < len(blob) <= MAX_BYTES or b'<!DOCTYPE' in blob.upper() or b'<!ENTITY' in blob.upper():
        raise ValueError('unsafe Metalink document size or entity declaration')
    root = ET.fromstring(blob)
    if root.tag != f'{{{METALINK}}}metalink' or root.get('version') != '3.0':
        raise ValueError('unsupported Metalink schema')
    files = root.findall('m:files/m:file', NS)
    if (len(files) != 1 or len(list(root.iter(f'{{{METALINK}}}file'))) != 1
            or files[0].get('name') != 'repomd.xml'):
        raise ValueError('expected exactly one repomd.xml file')
    file = files[0]
    hashes = {}
    for item in file.findall('m:verification/m:hash', NS):
        kind = item.get('type')
        lengths = {'md5': 32, 'sha1': 40, 'sha256': 64, 'sha512': 128}
        if (kind not in lengths or kind in hashes
                or not re.fullmatch('[0-9a-f]{' + str(lengths[kind]) + '}', item.text or '')):
            raise ValueError('invalid or duplicate primary checksum')
        hashes[kind] = item.text
    if 'sha256' not in hashes or 'sha512' not in hashes:
        raise ValueError('primary SHA-256 and SHA-512 checksums are required')
    sizes = file.findall('m:size', NS)
    timestamps = file.findall('mm:timestamp', NS)
    if len(sizes) != 1 or len(timestamps) != 1:
        raise ValueError('ambiguous primary size or timestamp')
    size = int(sizes[0].text)
    timestamp = int(timestamps[0].text)
    if not 0 < size <= MAX_BYTES or timestamp <= 0:
        raise ValueError('invalid primary size or timestamp')
    urls = file.findall('m:resources/m:url', NS)
    if not urls:
        raise ValueError('empty mirror inventory')
    from urllib.parse import urlsplit
    for url in urls:
        parsed = urlsplit(url.text or '')
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)
                or url.get('protocol') != 'https' or url.get('type') != 'https'
                or not parsed.path.endswith('/repodata/repomd.xml')):
            raise ValueError('mirror is not a credential-free HTTPS repomd URL')
    alternatives = file.findall('mm:alternates', NS)
    if len(alternatives) > 1:
        raise ValueError('duplicate alternate inventory')
    removed = 0
    for parent in alternatives:
        for alternate in parent:
            if alternate.tag != f'{{{MIRRORMANAGER}}}alternate':
                raise ValueError('unknown alternate entry')
            stamp = alternate.findall('mm:timestamp', NS)
            if len(stamp) != 1 or not 0 < int(stamp[0].text) < timestamp:
                raise ValueError('alternate is not older than the primary')
            removed += 1
        file.remove(parent)
    # Librepo expects the standard unprefixed Metalink elements. ElementTree's
    # automatic ns0 prefix is namespace-equivalent XML but not accepted by it.
    ET.register_namespace('', METALINK)
    ET.register_namespace('mm0', MIRRORMANAGER)
    filtered = ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'
    return filtered, {
        'primary_timestamp': timestamp, 'primary_repomd_bytes': size,
        'primary_repomd_sha256': hashes['sha256'],
        'primary_repomd_sha512': hashes['sha512'],
        'https_mirrors': len(urls), 'removed_older_alternatives': removed,
        'upstream_sha256': hashlib.sha256(blob).hexdigest(),
        'current_only_sha256': hashlib.sha256(filtered).hexdigest(),
    }


def prepare_kickstart(text, payloads, guest_directory):
    """Change only the two top-level compose sources and add an offline %pre."""
    if MARKER in text or not re.fullmatch('/run/noid-compose-metalinks-[a-f0-9]{16}', guest_directory):
        raise ValueError('already prepared Kickstart or invalid guest staging path')
    if set(payloads) != set(SOURCES):
        raise ValueError('incomplete Fedora Metalink set')
    counts = dict.fromkeys(SOURCES, 0)
    lines = []
    in_section = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped == '%end':
            in_section = False
        elif re.match(r'^%(?:pre(?:-install)?|post|packages|addon|onerror|traceback|certificate)\b', stripped):
            in_section = True
        elif not in_section and (stripped.startswith('url ') or stripped.startswith('repo ')):
            words = shlex.split(stripped)
            matched = False
            for name, source in SOURCES.items():
                expected = ['url', '--metalink=' + source] if name == 'fedora' else [
                    'repo', '--name=fedora-updates', '--metalink=' + source]
                if words == expected:
                    counts[name] += 1
                    prefix = 'url' if name == 'fedora' else 'repo --name=fedora-updates'
                    line = f'{prefix} --metalink="file://{guest_directory}/{name}.xml"\n'
                    matched = True
                    break
            if not matched:
                raise ValueError('unexpected top-level compose repository')
        lines.append(line)
    if in_section or counts != {'fedora': 1, 'updates': 1}:
        raise ValueError('Fedora compose source anchors are absent, duplicated or drifted')
    records = {name: [base64.b64encode(blob).decode('ascii'), hashlib.sha256(blob).hexdigest()]
               for name, blob in payloads.items()}
    # Only data is carried in the flattened Kickstart; no network or DNS is
    # needed in %pre, and no host HTTP endpoint becomes a metadata trust root.
    pre = [MARKER, '%pre --erroronfail --interpreter=/usr/bin/python3',
           'import base64, hashlib, os',
           'os.umask(0o077)', f'directory = {guest_directory!r}',
           'os.mkdir(directory, 0o700)', f'payloads = {records!r}',
           'for name, (encoded, digest) in payloads.items():',
           '    data = base64.b64decode(encoded, validate=True)',
           '    if hashlib.sha256(data).hexdigest() != digest:',
           '        raise SystemExit("compose Metalink payload digest mismatch")',
           '    with open(directory + "/" + name + ".xml", "xb") as stream:',
           '        stream.write(data)', '        stream.flush()',
           '        os.fsync(stream.fileno())',
           '%end', '# END NOID_COMPOSE_CURRENT_METALINKS', '']
    return ''.join(lines).rstrip('\n') + '\n\n' + '\n'.join(pre)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kickstart', type=Path,
                        help='also prepare this disposable flattened Kickstart')
    parser.add_argument('evidence_directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    ks = args.kickstart
    if ks is not None and (not ks.is_absolute() or ks.is_symlink()
                           or not ks.is_file() or ks.resolve() != ks):
        raise ValueError('Kickstart must be an existing absolute regular file')
    evidence = args.evidence_directory
    if not evidence.is_absolute() or evidence.exists() or evidence.is_symlink():
        raise ValueError('evidence directory must be a new absolute path')
    directory = '/run/noid-compose-metalinks-' + secrets.token_hex(8)
    # Reject drift before network traffic or creation of evidence.
    if ks is not None:
        original = ks.read_text(encoding='utf-8')
        prepare_kickstart(original, dict.fromkeys(SOURCES, b''), directory)
    evidence.mkdir(mode=0o700)
    payloads, report = {}, {}
    for name, url in SOURCES.items():
        result = subprocess.run([
            'curl', '--fail', '--silent', '--show-error', '--location',
            '--proto', '=https', '--proto-redir', '=https', '--max-time', '60',
            '--max-filesize', str(MAX_BYTES), url,
        ], check=True, capture_output=True)
        blob = result.stdout
        (evidence / (name + '-upstream.xml')).write_bytes(blob)
        filtered, details = current_metalink(blob)
        (evidence / (name + '-current.xml')).write_bytes(filtered)
        payloads[name] = filtered
        report[name] = {'url': url, **details}
    if ks is not None:
        prepared = prepare_kickstart(original, payloads, directory)
        report['kickstart_before_sha256'] = hashlib.sha256(original.encode()).hexdigest()
        report['kickstart_after_sha256'] = hashlib.sha256(prepared.encode()).hexdigest()
    (evidence / 'compose-metalinks.json').write_text(json.dumps(report, indent=2) + '\n')
    if ks is None:
        print('compose-metalinks: PASS: current-only Fedora Metalinks prepared for native query')
        return
    fd, temporary = tempfile.mkstemp(prefix='.compose-metalinks-', dir=ks.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(prepared)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, ks)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('compose-metalinks: PASS: Fedora primary hashes only; HTTPS mirrors and native downloader retained')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, ET.ParseError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'compose-metalinks: FAIL: {error}')
