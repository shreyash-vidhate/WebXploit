import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine.safe_runner import validate_local_url, validate_payload, classify_result

def test_local_url_allowed(): validate_local_url("http://localhost:8080/ftp")

def test_external_url_rejected():
    with pytest.raises(ValueError): validate_local_url("http://example.com:80/")

def test_external_payload_rejected():
    with pytest.raises(ValueError): validate_payload("http://169.254.169.254/latest/meta-data")

def test_waf_classification():
    assert classify_result({"status_code":200},{"status_code":403})=="WAF_BLOCKED"

def test_control_classification():
    assert classify_result({"status_code":200},{"status_code":403},"authorization")=="CONTROL_ENFORCED"

def test_rate_limit_classification():
    assert classify_result({"status_code":401},{"status_code":429},expected="rate_limit")=="RATE_LIMITED"
