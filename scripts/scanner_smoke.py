"""Run real scanner against temporary positive and negative security fixtures."""
import json
from pathlib import Path
import subprocess
import tempfile

config = Path(__file__).resolve().parents[1] / 'rules/security.yml'
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / 'unsafe.py').write_text('import subprocess, yaml, requests\nsubprocess.run(cmd, shell=True)\nyaml.unsafe_load(text)\nrequests.get(url, verify=False)\n')
    (root / 'unsafe.js').write_text('eval(input);\nconst options = { rejectUnauthorized: false };\nconst text = window.location.hash;\nelement.innerHTML = text;\n')
    (root / 'safe.py').write_text('import subprocess, yaml, requests\nsubprocess.run(["echo", text], check=True)\nyaml.safe_load(text)\nrequests.get(url, timeout=5)\n')
    (root / 'safe.js').write_text('const text = window.location.hash;\nelement.textContent = text;\n')
    args = ['semgrep', 'scan', '--config', str(config), '--metrics', 'off', '--disable-version-check', '--strict', '--error', '--json', '--no-git-ignore', str(root)]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    report = json.loads(result.stdout)
    findings = report['results']
    assert result.returncode == 1, result.stderr
    assert not report.get('errors'), report.get('errors')
    assert len({r['check_id'] for r in findings}) == 6, findings
    assert all(Path(r['path']).name.startswith('unsafe.') for r in findings), findings
    (root / 'unsafe.py').unlink()
    (root / 'unsafe.js').unlink()
    clean = subprocess.run(args, capture_output=True, text=True, check=False)
    assert clean.returncode == 0, clean.stderr
    assert not json.loads(clean.stdout)['results'], clean.stdout
print('PASS: all six rules detect unsafe fixtures and accept safe equivalents')
