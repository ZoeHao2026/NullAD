"""Reproducible, offline-by-default rule data generation.

Use --refresh to fetch official EasyList inputs at a pinned Git commit. Only
unconditional domain anchors are imported; ABP options are never discarded.
Use --check in CI to verify committed inputs/hashes/generated output offline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'rules/sources.lock.json'
SOURCES = {
    'easylist-adservers.source': 'easylist/easylist_adservers.txt',
    'easyprivacy-trackingservers.source': 'easyprivacy/easyprivacy_trackingservers.txt',
    'easyprivacy-trackingservers-general.source': 'easyprivacy/easyprivacy_trackingservers_general.txt',
    'easyprivacy-trackingservers-international.source': 'easyprivacy/easyprivacy_trackingservers_international.txt',
    'easylist-allowlist.source': 'easylist/easylist_allowlist.txt',
    'easyprivacy-allowlist.source': 'easyprivacy/easyprivacy_allowlist.txt',
    'easyprivacy-allowlist-international.source': 'easyprivacy/easyprivacy_allowlist_international.txt',
}
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I | re.ASCII)
ANCHOR = re.compile(r'(\|\|)([a-z0-9.-]+)\^$', re.I | re.ASCII)
EXCLUDED = {'graph.facebook.com', 'device-provisioning.googleapis.com'}


def exception_hosts(text):
    result = set()
    for line in text.splitlines():
        match = re.match(r'^@@(?:\|\|(?:\*\.)?|\|?https?://)([a-z0-9.-]+)(?:[\^/:$]|$)', line.strip(), re.I | re.ASCII)
        if match and DOMAIN.fullmatch(match[1]):
            result.add(match[1].lower())
    return result


def reduce_domains(domains, exceptions):
    # Whole-domain filtering cannot preserve a path/type exception underneath
    # it: exclude its ancestor block too, instead of silently widening scope.
    excluded = set()
    for host in exceptions:
        labels = host.split('.')
        excluded.update('.'.join(labels[index:]) for index in range(len(labels)-1))
    retained = []
    for host in sorted(domains - excluded):
        labels = host.split('.')
        if any('.'.join(labels[index:]) in exceptions for index in range(len(labels)-1)):
            continue
        retained.append(host)
    # Domain anchors already include subdomains. Keep one rule per effective
    # suffix, while preserving the unmodified input data for reproduction.
    domain_set = set(retained)
    return sorted(host for host in retained if not any('.'.join(host.split('.')[index:]) in domain_set for index in range(1, len(host.split('.'))-1)))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'NullAD-rule-snapshot/1'})
    with urllib.request.urlopen(request, timeout=45) as response:
        if response.geturl() != url:
            raise ValueError('Unexpected source redirect')
        data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError('Source too large')
        return data


def extract(text):
    domains, exceptions = set(), set()
    for line in text.splitlines():
        line = line.strip()
        exception = line.startswith('@@')
        candidate = line[2:] if exception else line
        match = ANCHOR.fullmatch(candidate)
        if match and DOMAIN.fullmatch(match[2]):
            (exceptions if exception else domains).add(match[2].lower())
    return domains, exceptions


def generate(lock, inputs):
    domains, exceptions = set(), set()
    for item in lock['sources']:
        data = inputs[item['file']]
        if digest(data) != item['sha256']:
            raise ValueError('Source hash mismatch: ' + item['file'])
        found, allowed = extract(data.decode('utf8'))
        domains.update(found)
        exceptions.update(allowed)
        exceptions.update(exception_hosts(data.decode('utf8')))
    # Old independent local rules stay reproducible; avoid two broad business
    # endpoints from the original demonstration list. No tester-host selection.
    local = (ROOT / 'rules/nullad-local-domains.txt').read_text(encoding='utf8')
    domains.update(line for line in local.splitlines() if DOMAIN.fullmatch(line))
    domains = reduce_domains(domains, exceptions | EXCLUDED)
    if not 500 <= len(domains) <= 100000:
        raise ValueError('Unexpected domain count; review upstream before publishing')
    metadata = {'generator': 1, 'upstream': 'easylist/easylist', 'commit': lock['commit'], 'upstream_date': lock['upstream_date'], 'domain_count': len(domains), 'exception_hosts': len(exceptions), 'license': 'CC-BY-SA-3.0', 'source_home': 'https://easylist.to/', 'changes': 'Only unconditional ||ASCII-domain^ rules extracted, deduplicated and sorted; literal-host exceptions (even path/type-specific), their ancestor blocks and child domains excluded; two local business endpoints excluded; redundant child rules removed; independent original local domains included. Generic/regex ABP exceptions cannot be expressed by this domain-only subset; it is not full ABP list execution.', 'source_inputs': lock['sources']}
    comment = '\n'.join(['! Title: NullAD Bundled Ads and Trackers', '! Generated; run scripts/update-bundled-rules.py. Do not edit.', '! Source: The EasyList authors (https://easylist.to/)', '! License for derived domain data: CC-BY-SA-3.0 (https://creativecommons.org/licenses/by-sa/3.0/)', '! Application code is independently MIT; see THIRD_PARTY_NOTICES.md.', '! Upstream commit: ' + lock['commit'], '! Imported unconditional domain rules only; no ABP options stripped.', '! Domains: ' + str(len(domains)), ''])
    hosts = comment + '\n'.join('0.0.0.0 ' + domain for domain in domains) + '\n'
    # This is data, independently licensed from the generic policy code.
    data_js = '/* Derived domain data: CC-BY-SA-3.0; The EasyList authors https://easylist.to/.\n * Generated from pinned upstream sources; changes/attribution: THIRD_PARTY_NOTICES.md. */\n(function(root){"use strict";const data=' + json.dumps({'metadata': metadata, 'domains': domains}, separators=(',', ':')) + ';if(typeof module!=="undefined"&&module.exports)module.exports=data;else root.NullADDomainRules=data;})(globalThis);\n'
    notice = '# Third-party rule data\n\nThe EasyList authors (https://easylist.to/) are the source of the imported\ndomain data. Official license: https://easylist.to/pages/licence.html\nThe derived lists/nullad-hosts.txt and extension/domain-rules.js data are\nlicensed under Creative Commons Attribution-ShareAlike 3.0 Unported:\nhttps://creativecommons.org/licenses/by-sa/3.0/\nLegal code: https://creativecommons.org/licenses/by-sa/3.0/legalcode\n\nUpstream commit: ' + lock['commit'] + '\nUpstream date: ' + lock['upstream_date'] + '\n\nChanges: ' + metadata['changes'] + '\n\nFull original inputs are committed in rules/vendor/*.source with hashes and\npaths in rules/sources.lock.json. Regenerate offline with\npython scripts/update-bundled-rules.py; --refresh explicitly fetches a new\npinned version from the official repository. No runtime downloads occur.\nThis data notice does not relicense the independent MIT application code.\n\nThese lists include advertising and tracking; false positives remain possible.\nDisable bundled rules or allow a site/domain when required. No warranty or\nupstream endorsement is implied.\n'
    return {ROOT/'lists/nullad-hosts.txt': hosts.encode(), ROOT/'extension/domain-rules.js': data_js.encode(), ROOT/'rules/metadata.json': (json.dumps(metadata, indent=2)+'\n').encode(), ROOT/'extension/THIRD_PARTY_NOTICES.md': notice.encode(), ROOT/'lists/THIRD_PARTY_NOTICES.md': notice.encode()}


def publish(files):
    # Stage every new and previous version before publication. If rollback also
    # fails, its on-disk recovery copy survives and the error names its location.
    staged, backups, absent, preserve = {}, {}, set(), set()
    try:
        for path, data in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                old = path.read_bytes()
                fd, name = tempfile.mkstemp(prefix='.nullad-rule-old-', dir=path.parent)
                backups[path] = Path(name)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(old)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                absent.add(path)
            fd, name = tempfile.mkstemp(prefix='.nullad-rule-', dir=path.parent)
            staged[path] = Path(name)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        changed = []
        try:
            for path, stage in staged.items():
                os.replace(stage, path)
                changed.append(path)
        except Exception as original:
            errors = []
            for path in reversed(changed):
                try:
                    if path in absent:
                        path.unlink()
                    else:
                        os.replace(backups[path], path)
                except Exception as rollback:
                    if path in backups:
                        preserve.add(backups[path])
                    errors.append(f'{path}: {rollback}; previous version: {backups.get(path, "file was absent")}')
            if errors:
                raise RuntimeError(f'Publication failed: {original}. Rollback incomplete; keep recovery copies: ' + '; '.join(errors)) from original
            raise
    finally:
        for stage in [*staged.values(), *backups.values()]:
            if stage not in preserve:
                stage.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--refresh', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.refresh:
        commit = json.loads(fetch('https://api.github.com/repos/easylist/easylist/commits/master'))
        sha = commit['sha']
        if not re.fullmatch('[a-f0-9]{40}', sha):
            raise ValueError('Invalid upstream commit')
        lock = {'commit': sha, 'upstream_date': commit['commit']['committer']['date'], 'sources': []}
        inputs = {}
        for filename, upstream_path in SOURCES.items():
            url = f'https://raw.githubusercontent.com/easylist/easylist/{sha}/{upstream_path}'
            data = fetch(url)
            inputs[filename] = data
            lock['sources'].append({'file': filename, 'path': upstream_path, 'url': url, 'sha256': digest(data)})
    else:
        lock = json.loads(LOCK.read_text(encoding='utf8'))
        inputs = {item['file']: (ROOT/'rules/vendor'/item['file']).read_bytes() for item in lock['sources']}
    files = generate(lock, inputs)
    if args.refresh:
        files.update({ROOT/'rules/vendor'/name: data for name, data in inputs.items()})
        files[LOCK] = (json.dumps(lock, indent=2)+'\n').encode()
    if args.check:
        different = [str(path.relative_to(ROOT)) for path, data in files.items() if not path.exists() or path.read_bytes() != data]
        if different:
            raise ValueError('Generated rule files differ: ' + ', '.join(different))
    else:
        publish(files)
    print(json.dumps({'commit': lock['commit'], 'domains': json.loads(files[ROOT/'rules/metadata.json'])['domain_count'], 'offline': not args.refresh, 'check': args.check}))


if __name__ == '__main__':
    main()
