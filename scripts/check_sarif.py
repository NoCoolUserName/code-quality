"""Fail CodeQL on high/critical security findings or failed analysis."""
import json
import pathlib
import sys


def failures(report):
    errors=[]
    if not report.get('runs'):
        return ['No SARIF runs']
    for run in report['runs']:
        if any(x.get('executionSuccessful') is False for x in run.get('invocations', [])):
            errors.append('Analysis failed')
        rules={r['id']:r for r in run.get('tool',{}).get('driver',{}).get('rules',[])}
        for result in run.get('results',[]):
            rule=rules.get(result.get('ruleId'),{})
            severity=rule.get('properties',{}).get('security-severity','0')
            if float(severity)>=7:
                errors.append(result.get('ruleId','unknown'))
    return errors


if __name__=='__main__':
    files=list(pathlib.Path(sys.argv[1]).rglob('*.sarif'))
    if not files:
        raise SystemExit('CodeQL did not produce SARIF')
    found=[f'{p.name}: {x}' for p in files for x in failures(json.loads(p.read_text()))]
    for line in found: print(line)
    raise SystemExit(bool(found))
