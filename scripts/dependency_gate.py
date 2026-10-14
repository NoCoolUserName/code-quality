"""Fail-closed dependency merge gate. Never check out or execute PR code."""
import base64
import copy
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BOT_ID = 49699333
ACTIONS_ID = 15368


class Blocked(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def version_change(old, new, minor=False):
    pattern = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
    require(re.fullmatch(pattern, old) and re.fullmatch(pattern, new), 'Non-stable or non-semver version')
    a, b = tuple(map(int, old.split('.'))), tuple(map(int, new.split('.')))
    require(b > a and a[0] == b[0] and (minor or a[1] == b[1]), 'Not an allowed patch update')


def spec_change(old, new, minor=False):
    pattern = r'(\^|~|==|>=)?(\d+\.\d+\.\d+)'
    a, b = re.fullmatch(pattern, old), re.fullmatch(pattern, new)
    require(a and b and a[1] == b[1], 'Dependency range or source changed')
    version_change(a[2], b[2], minor)


def manifest_change(old, new, minor=False):
    a, b = copy.deepcopy(old), copy.deepcopy(new)
    changes = 0
    for field in ('dependencies', 'devDependencies', 'optionalDependencies'):
        da, db = a.pop(field, {}), b.pop(field, {})
        require(da.keys() == db.keys(), 'Added or removed direct dependency')
        for name in da:
            if da[name] != db[name]:
                spec_change(da[name], db[name], minor and field == 'devDependencies')
                changes += 1
    require(a == b, 'Non-dependency manifest edit (scripts/config/metadata)')
    return changes


def npm_lock_change(old, new, minor=False):
    require(old.get('lockfileVersion') == new.get('lockfileVersion') == 3, 'Only npm lockfile v3 supported')
    a, b = copy.deepcopy(old), copy.deepcopy(new)
    pa, pb = a.pop('packages'), b.pop('packages')
    require(a == b and pa.keys() == pb.keys(), 'Lockfile structure or package membership changed')
    changes = 0
    for path, before in pa.items():
        after = pb[path]
        if before == after:
            continue
        if path == '' or 'node_modules/' not in path:
            changes += manifest_change(before, after, minor)
            continue
        va, vb = before.get('version'), after.get('version')
        require(va != vb, 'Lock metadata changed without a version update')
        version_change(va or '', vb or '', minor and before.get('dev') is True and after.get('dev') is True)
        for pkg in (before, after):
            url = urllib.parse.urlsplit(pkg.get('resolved', ''))
            require(url.scheme == 'https' and url.hostname == 'registry.npmjs.org' and not url.username, 'Untrusted npm source')
            require(bool(re.fullmatch(r'sha512-[A-Za-z0-9+/=]+', pkg.get('integrity', ''))), 'Missing SHA512 integrity')
        ba, bb = copy.deepcopy(before), copy.deepcopy(after)
        # Registry package dependency declarations may change in a patch release.
        for field in ('version', 'resolved', 'integrity', 'dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'engines'):
            ba.pop(field, None)
            bb.pop(field, None)
        require(ba == bb, 'Changed package execution/link/dev metadata')
        changes += 1
    return changes


def requirements_change(old, new):
    a, b = old.splitlines(), new.splitlines()
    require(len(a) == len(b), 'Requirement added or removed')
    count = 0
    for x, y in zip(a, b):
        if x == y:
            continue
        rx = r'([A-Za-z0-9_.-]+)==(\d+\.\d+\.\d+)'
        p, q = re.fullmatch(rx, x), re.fullmatch(rx, y)
        require(p and q and p[1] == q[1], 'Only exact pinned requirement updates supported')
        version_change(p[2], q[2])
        count += 1
    return count


def changes_allowed(files, contents, policy):
    require(0 < len(files) <= 50, 'Unexpected changed-file count')
    allowed = set(policy['dependency_files'])
    changes = 0
    for f in files:
        path = f['filename']
        require(path in allowed and not path.startswith('.github/'), 'Non-dependency or policy/workflow file changed')
        require(f['status'] == 'modified', 'Added, renamed or deleted file')
        old, new = contents[path]
        if path.endswith('package-lock.json'):
            changes += npm_lock_change(json.loads(old), json.loads(new), policy.get('allow_dev_minor', False))
        elif path.endswith('package.json'):
            changes += manifest_change(json.loads(old), json.loads(new), policy.get('allow_dev_minor', False))
        elif re.fullmatch(r'(?:[^/]+/)*requirements(?:[.-][A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)?\.txt', path):
            changes += requirements_change(old, new)
        else:
            raise Blocked('Lock/manifest format has not been validated for automatic merging')
    require(changes > 0, 'No verified dependency version changes')


def identity_allowed(pr, repo):
    require(pr['state'] == 'open' and not pr.get('draft'), 'PR is not ready/open')
    require(pr['user']['login'] == 'dependabot[bot]' and pr['user']['id'] == BOT_ID, 'Not GitHub Dependabot')
    require(pr['head']['repo']['full_name'] == repo == pr['base']['repo']['full_name'], 'Fork or repository mismatch')
    require(pr['base']['ref'] == 'main', 'Non-default target')


def checks_allowed(policy, workflows, checks):
    required = set(policy['required_checks'])
    require(bool(required) and bool(policy['required_workflows']), 'No required checks/workflows configured')
    for path in policy['required_workflows']:
        runs = [r for r in workflows if r['path'] == path and r['event'] == 'pull_request']
        require(bool(runs), 'Required workflow missing: ' + path)
        newest = max(runs, key=lambda r: r['id'])
        require(newest['status'] == 'completed' and newest['conclusion'] == 'success', 'Required workflow incomplete/failed: ' + path)
    latest = {}
    for c in checks:
        if c['name'] not in latest or c['id'] > latest[c['name']]['id']:
            latest[c['name']] = c
    for name in required:
        c = latest.get(name)
        require(c and c['app']['id'] == ACTIONS_ID and c['status'] == 'completed' and c['conclusion'] == 'success', 'Required check missing/failed: ' + name)
    for c in latest.values():
        require(c['status'] == 'completed' and c['conclusion'] in ('success', 'skipped', 'neutral'), 'Another check is pending/failed: ' + c['name'])


def protections_allowed(policy, rules):
    enforced = set()
    strict = False
    pr_rule = False
    for rule in rules:
        if rule['type'] == 'required_status_checks':
            p = rule['parameters']
            strict |= p.get('strict_required_status_checks_policy', False)
            enforced.update(c['context'] for c in p['required_status_checks'] if c.get('integration_id') == ACTIONS_ID)
        if rule['type'] == 'pull_request':
            pr_rule = True
    require(pr_rule and strict and set(policy['required_checks']) <= enforced, 'Native strict required-check ruleset is missing/incomplete')


class GitHub:
    def __init__(self, repo, token):
        require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)), 'Invalid repository')
        self.base = 'https://api.github.com/repos/' + repo
        self.token = token

    def call(self, path, method='GET', data=None):
        request = urllib.request.Request(self.base + path, method=method, data=None if data is None else json.dumps(data).encode(), headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'code-quality-dependency-gate',
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise Blocked(f'GitHub API {exc.code}; no merge attempted/completed') from None

    def pages(self, path, key=None):
        result = []
        for page in range(1, 11):
            data = self.call(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            items = data[key] if key else data
            result.extend(items)
            if len(items) < 100:
                return result
        raise Blocked('API pagination limit; refusing incomplete evidence')

    def file(self, path, ref):
        data = self.call('/contents/' + urllib.parse.quote(path, safe='/') + '?ref=' + ref)
        require(data.get('type') == 'file' and data.get('encoding') == 'base64' and data.get('size', 0) < 900000, 'File unavailable, too large, or not regular')
        return base64.b64decode(data['content']).decode()


def assess(api, repo, number, merge=False):
    pr = api.call(f'/pulls/{number}')
    identity_allowed(pr, repo)
    head, base = pr['head']['sha'], pr['base']['sha']
    policy = json.loads(api.file('.github/dependency-policy.json', base))
    require(policy.get('enabled') is True, policy.get('blocked_reason', 'Automatic merging disabled for this repository'))
    commits = api.pages(f'/pulls/{number}/commits')
    require(commits and all((c.get('author') or {}).get('id') == BOT_ID for c in commits), 'PR contains non-Dependabot commits')
    files = api.pages(f'/pulls/{number}/files')
    require(len(files) == pr['changed_files'], 'Incomplete file inventory')
    # Check paths before downloading untrusted file contents.
    require(all(f['filename'] in policy['dependency_files'] for f in files), 'File outside dependency allowlist')
    contents = {f['filename']: (api.file(f['filename'], base), api.file(f['filename'], head)) for f in files}
    changes_allowed(files, contents, policy)
    runs = api.pages('/actions/runs?head_sha=' + head + '&event=pull_request', 'workflow_runs')
    checks = api.pages('/commits/' + head + '/check-runs', 'check_runs')
    checks_allowed(policy, runs, checks)
    status = api.call('/commits/' + head + '/status')
    require(not status['statuses'] or status['state'] == 'success', 'Legacy status is pending/failed')
    rules = api.call('/rules/branches/main')
    protections_allowed(policy, rules)
    branch = api.call('/branches/main')
    fresh = api.call(f'/pulls/{number}')
    require(fresh['head']['sha'] == head and fresh['base']['sha'] == base == branch['commit']['sha'], 'Head/base moved during assessment')
    require(fresh.get('mergeable') is True and fresh.get('mergeable_state') == 'clean', 'PR is behind, blocked, or mergeability is unknown')
    if merge:
        # Native strict rules close the remaining base/check race; no admin bypass.
        result = api.call(f'/pulls/{number}/merge', 'PUT', {'sha': head, 'merge_method': 'squash'})
        require(result.get('merged') is True, 'GitHub rejected the guarded merge')
        return 'MERGED ' + result['sha']
    return 'ELIGIBLE (read-only assessment)'


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    api = GitHub(repo, os.environ['GH_TOKEN'])
    requested = os.environ.get('PR_NUMBER', '')
    numbers = [int(requested)] if requested else [p['number'] for p in api.pages('/pulls?state=open') if p['user']['id'] == BOT_ID]
    for number in numbers:
        try:
            result = assess(api, repo, number, os.environ.get('MERGE_ENABLED') == 'true')
        except (Blocked, KeyError, ValueError, TypeError) as exc:
            result = 'BLOCKED: ' + str(exc)
        line = f'PR #{number}: {result}'
        print(line)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write(line + '\n\n')


if __name__ == '__main__':
    main()
