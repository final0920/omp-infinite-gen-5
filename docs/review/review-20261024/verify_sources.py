"""Bind this review to exact files and parse source without importing engines."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
snapshot = json.loads((HERE / 'source-snapshot.json').read_text(encoding='utf-8-sig'))
results = []
for row in snapshot:
    filename = ROOT / row['file']
    data = filename.read_bytes()
    current = hashlib.sha256(data).hexdigest()
    if filename.suffix == '.py':
        ast.parse(data.decode('utf-8-sig'), filename=row['file'])
    else:
        checked = subprocess.run(['node', '--check', str(filename)], capture_output=True, text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if checked.returncode:
            raise RuntimeError(checked.stderr)
    results.append({**row, 'currentSha256': current, 'unchanged': current == row['sha256'], 'syntax': 'pass'})
output = {'files': len(results), 'lines': sum(r['lines'] for r in results),
    'syntaxPass': len(results), 'allUnchanged': all(r['unchanged'] for r in results), 'results': results}
(HERE / 'source-verification.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k: v for k, v in output.items() if k != 'results'}, ensure_ascii=False))
if not output['allUnchanged']:
    raise SystemExit(1)
