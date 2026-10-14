"""Fail CodeQL on high/critical findings or incomplete/unreadable SARIF.

This is a gate for self-contained SARIF 2.1.0, not a full schema validator.
Rule lookup follows SARIF 3.27.7, 3.52 and 3.54: indices are local to a
component, and an omitted toolComponent selects the driver. ID-only lookup
is supported when unambiguous. Externalized data is rejected, never skipped.
"""
import argparse
from decimal import Decimal, InvalidOperation
import json
import pathlib
import sys


class SarifError(ValueError):
    """The report cannot establish that the security gate passed."""


def _object(value, label):
    if not isinstance(value, dict):
        raise SarifError(f'{label} must be an object')
    return value


def _array(value, label):
    if not isinstance(value, list):
        raise SarifError(f'{label} must be an array')
    return value


def _string(value, label):
    if not isinstance(value, str) or not value.strip():
        raise SarifError(f'{label} must be a nonempty string')
    return value


def _index(obj, key):
    if key not in obj:
        return None
    value = obj[key]
    if type(value) is not int or value < 0:
        raise SarifError(f'{key} must be a nonnegative integer')
    return value


def _security_severity(rule, *, finding=False):
    properties = _object(rule.get('properties', {}), 'rule.properties')
    tags = _array(properties.get('tags', []), 'rule.properties.tags')
    for tag in tags:
        _string(tag, 'rule tag')
    if 'security-severity' not in properties:
        if finding and 'security' in tags:
            raise SarifError(f'{rule["id"]}: security rule has no security-severity')
        return None  # A resolved, non-security rule need not have a CVSS score.
    raw = properties['security-severity']
    if type(raw) not in (str, int, float):
        raise SarifError(f'{rule["id"]}: invalid security-severity')
    # Decimal avoids rounding a value across the threshold. Restrict string
    # scores to ordinary decimal notation (no NaN, infinity or underscores).
    if isinstance(raw, str):
        parts = raw.split('.')
        if len(parts) > 2 or any(not p or any(c not in '0123456789' for c in p) for p in parts):
            raise SarifError(f'{rule["id"]}: invalid security-severity')
    try:
        score = Decimal(str(raw))
    except (InvalidOperation, ValueError):
        raise SarifError(f'{rule["id"]}: invalid security-severity') from None
    if not score.is_finite() or not 0 <= score <= 10:
        raise SarifError(f'{rule["id"]}: security-severity must be finite and between 0 and 10')
    return score


def _component(tool, reference):
    reference = _object(reference, 'rule.toolComponent')
    index = _index(reference, 'index')
    guid = _string(reference['guid'], 'toolComponent.guid') if 'guid' in reference else None
    if index is not None:
        extensions = tool.get('extensions', [])
        if index >= len(extensions):
            raise SarifError('Unresolved toolComponent index')
        component = extensions[index]
    elif guid is not None:
        matches = [c for c in [tool['driver'], *tool.get('extensions', [])] if c.get('guid') == guid]
        if len(matches) != 1:
            raise SarifError('Unresolved or ambiguous toolComponent guid')
        component = matches[0]
    else:
        component = tool['driver']
    for key in ('name', 'guid'):
        if key in reference:
            _string(reference[key], f'toolComponent.{key}')
            if component.get(key) != reference[key]:
                raise SarifError(f'toolComponent {key} does not match selected component')
    return component


def _id_matches(result_id, rule_id):
    # SARIF permits one extra hierarchical component in a result's rule ID.
    return result_id == rule_id or result_id.rpartition('/')[0] == rule_id


def _rule(result, tool):
    reference = _object(result.get('rule', {}), 'result.rule')
    ids = [_string(obj[key], key) for obj, key in ((result, 'ruleId'), (reference, 'id')) if key in obj]
    if len(set(ids)) > 1:
        raise SarifError('ruleId and rule.id disagree')
    rule_id = ids[0] if ids else None
    indexes = [i for i in (_index(result, 'ruleIndex'), _index(reference, 'index')) if i is not None]
    if len(set(indexes)) > 1:
        raise SarifError('ruleIndex and rule.index disagree')
    guid = _string(reference['guid'], 'rule.guid') if 'guid' in reference else None
    component = _component(tool, reference.get('toolComponent', {}))
    rules = component.get('rules', [])
    if indexes:
        if indexes[0] >= len(rules):
            raise SarifError('Unresolved rule index')
        rule = rules[indexes[0]]
    else:
        if guid is not None:
            matches = [r for r in rules if r.get('guid') == guid]
        elif rule_id is not None:
            matches = [r for r in rules if _id_matches(rule_id, r['id'])]
        else:
            raise SarifError('Result has no rule identifier or index')
        if len(matches) != 1:
            raise SarifError(f'Unresolved or ambiguous rule: {rule_id or guid}')
        rule = matches[0]
    if rule_id is not None and not _id_matches(rule_id, rule['id']):
        raise SarifError('Rule ID does not match selected rule')
    if guid is not None and rule.get('guid') != guid:
        raise SarifError('Rule guid does not match selected rule')
    return rule


def _analysis_errors(run):
    errors = []
    for index, invocation in enumerate(_array(run.get('invocations', []), 'invocations')):
        invocation = _object(invocation, 'invocation')
        if invocation.get('executionSuccessful') is not True:
            errors.append(f'Analysis failed or success unconfirmed (invocation {index})')
        if any(key in invocation for key in ('processStartFailureMessage', 'exitSignalName', 'exitSignalNumber')):
            errors.append(f'Analysis failed to start or was interrupted (invocation {index})')
        for key in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            for notification in _array(invocation.get(key, []), key):
                notification = _object(notification, key)
                level = notification.get('level', 'warning')
                if level not in ('none', 'note', 'warning', 'error'):
                    raise SarifError(f'Invalid {key} level')
                if level == 'error':
                    errors.append(f'Analysis error in {key} (invocation {index})')
    return errors


def _run_failures(run):
    run = _object(run, 'run')
    external = _object(run.get('externalPropertyFileReferences', {}), 'externalPropertyFileReferences')
    if external:
        raise SarifError('Externalized SARIF data is unsupported; provide a self-contained report')
    results = _array(run.get('results'), 'results (missing/null means analysis did not complete)')
    errors = _analysis_errors(run)
    tool = _object(run.get('tool'), 'tool')
    driver = _object(tool.get('driver'), 'tool.driver')
    extensions = _array(tool.get('extensions', []), 'tool.extensions')
    for component in [driver, *extensions]:
        component = _object(component, 'tool component')
        _string(component.get('name'), 'tool component name')
        if 'guid' in component:
            _string(component['guid'], 'tool component guid')
        for rule in _array(component.get('rules', []), 'component.rules'):
            rule = _object(rule, 'rule')
            _string(rule.get('id'), 'rule.id')
            if 'guid' in rule:
                _string(rule['guid'], 'rule.guid')
            _security_severity(rule)
    for index, result in enumerate(results):
        try:
            result = _object(result, 'result')
            rule = _rule(result, tool)
            severity = _security_severity(rule, finding=True)
            # Result level, baseline state and suppressions never lower this gate.
            if severity is not None and severity >= 7:
                errors.append(f'{rule["id"]}: high/critical security-severity {severity}')
        except SarifError as exc:
            errors.append(f'result {index}: {exc}')
    return errors


def failures(report):
    """Return all gate failures, including errors that prevent safe evaluation."""
    try:
        report = _object(report, 'SARIF report')
        if report.get('version') != '2.1.0':
            raise SarifError('Expected SARIF version 2.1.0')
        if _array(report.get('inlineExternalProperties', []), 'inlineExternalProperties'):
            raise SarifError('Externalized SARIF data is unsupported; provide a self-contained report')
        runs = _array(report.get('runs'), 'runs')
        if not runs:
            raise SarifError('No SARIF runs')
    except SarifError as exc:
        return [str(exc)]
    errors = []
    for index, run in enumerate(runs):
        try:
            errors.extend(f'run {index}: {error}' for error in _run_failures(run))
        except SarifError as exc:
            errors.append(f'run {index}: {exc}')
    return errors


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SarifError(f'Duplicate JSON property: {key}')
        result[key] = value
    return result


def _invalid_constant(value):
    raise SarifError(f'Invalid JSON numeric constant: {value}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=pathlib.Path, help='SARIF file or directory to scan recursively')
    path = parser.parse_args(argv).path
    try:
        # os.walk reports traversal failures rather than silently omitting a
        # directory, which pathlib globbing can do on some Python versions.
        import os
        files = []
        if path.is_file() and path.suffix == '.sarif':
            files = [path]
        elif path.is_dir():
            def onerror(error):
                raise error
            for root, _, names in os.walk(path, onerror=onerror):
                files.extend(pathlib.Path(root) / name for name in names if name.endswith('.sarif'))
        if not files:
            raise SarifError('CodeQL did not produce SARIF')
    except (OSError, SarifError) as exc:
        print(f'SARIF gate: {exc}', file=sys.stderr)
        return 1
    found = []
    for file in sorted(files):
        try:
            report = json.loads(file.read_text(encoding='utf-8'), object_pairs_hook=_unique_object,
                                parse_constant=_invalid_constant)
            found.extend(f'{file}: {error}' for error in failures(report))
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            found.append(f'{file}: Cannot read/parse SARIF: {exc}')
    for line in found:
        print(line, file=sys.stderr)
    return int(bool(found))


if __name__ == '__main__':
    raise SystemExit(main())
