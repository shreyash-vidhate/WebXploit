#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
from pathlib import Path
import yaml
files=sorted(Path('engine/manifests').glob('a0[1-9]_*.yaml'))+[Path('engine/manifests/a10_ssrf_mock.yaml')]
ids=[]
for f in files:
 d=yaml.safe_load(f.read_text()); ids.append(d['scenario']['id'])
 assert d['target']['waf_port']==8080, f'{f}: non-central WAF port'
 assert 'waf_target' in d['target'], f'{f}: missing waf_target'
print(f'Validated {len(files)} OWASP scenario manifests')
PY
docker compose -f docker/docker-compose.yml config >/dev/null
echo 'Docker Compose configuration: OK'
