from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
def test_owasp_suite_complete():
    files=sorted((ROOT/'engine/manifests').glob('a0[1-9]_*.yaml'))+[ROOT/'engine/manifests/a10_ssrf_mock.yaml']
    ids={yaml.safe_load(f.read_text())['scenario']['id'] for f in files}
    assert {f'EXPLOIT-A0{i}' for i in range(1,10)} <= ids
    assert 'EXPLOIT-A10-SAFE' in ids

def test_single_common_waf_port():
    for f in (ROOT/'engine/manifests').glob('a0*.yaml'):
        d=yaml.safe_load(f.read_text()); assert d['target']['waf_port']==8080
