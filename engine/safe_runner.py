import hashlib, json, re, sys, time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import requests, yaml

ALLOWED_HOSTS={"localhost","127.0.0.1","::1"}
ALLOWED_PORTS={3000,3001,3002,3003,3005,3006,3007,8080}

def validate_local_url(url):
    p=urlparse(url)
    if p.scheme!="http" or p.hostname not in ALLOWED_HOSTS or (p.port or 80) not in ALLOWED_PORTS:
        raise ValueError(f"Target outside approved local lab: {url}")

def validate_payload(value):
    if isinstance(value,dict):
        for v in value.values(): validate_payload(v)
    elif isinstance(value,list):
        for v in value: validate_payload(v)
    elif isinstance(value,str):
        for u in re.findall(r"https?://[^\s]+",value):
            p=urlparse(u.rstrip(").,]"))
            if p.hostname not in {"mock-metadata","localhost","127.0.0.1","::1"}:
                raise ValueError(f"External URL inside payload blocked: {u}")

def summarize(r):
    return {"status_code":r.status_code,"content_type":r.headers.get("content-type",""),"response_bytes":len(r.content),"response_sha256":hashlib.sha256(r.content).hexdigest(),"headers":dict(r.headers)}

def request(method,url,payload,headers):
    try:
        h=dict(headers or {})
        return summarize(requests.request(method,url,params=payload if method=="GET" else None,json=payload if method!="GET" else None,headers=h,timeout=5,allow_redirects=False))
    except requests.RequestException as e: return {"error":str(e)}

def classify_result(d,w,control=None,expected=None):
    if "error" in d or "error" in w: return "EXECUTION_ERROR"
    ds,ws=d["status_code"],w["status_code"]
    if expected=="waf_block" and ws==403: return "WAF_BLOCKED"
    if expected=="rate_limit" and ws==429: return "RATE_LIMITED"
    if control and ds!=403 and ws==403: return "CONTROL_ENFORCED"
    if ds!=403 and ws==403: return "WAF_BLOCKED"
    if expected=="log_injection" and ds==200: return "LOG_INJECTION_OBSERVED"
    if expected=="vulnerable_component" and ds==200: return "VULNERABLE_COMPONENT_DETECTED"
    if expected=="ssrf" and ds==200: return "SSRF_SIMULATION_CONFIRMED"
    if expected=="business_logic" and ds==200: return "BUSINESS_LOGIC_FLAW_OBSERVED"
    if expected=="integrity" and ds==200: return "INTEGRITY_VALIDATION_FLAW_OBSERVED"
    if ds==ws: return "SAME_BEHAVIOR_REQUIRES_REVIEW"
    return "BEHAVIOR_DIFFERENCE_REQUIRES_REVIEW"

def run_manifest(path):
    mp=Path(path).resolve(); root=mp.parents[2]; data=yaml.safe_load(mp.read_text(encoding="utf-8")); s=data["scenario"]; t=data["target"]; target=t.get("waf_target","default")
    direct=f"{t['host']}:{t['direct_port']}{t['endpoint']}"; waf=f"{t['host']}:{t['waf_port']}{t['endpoint']}"; validate_local_url(direct); validate_local_url(waf)
    report={"scenario_id":s["id"],"scenario_name":s["name"],"category":s["category"],"description":s.get("description",""),"executed_at":datetime.now().isoformat(),"scope":"Local WebXploit lab only","direct_url":direct,"waf_url":waf,"waf_target":target,"results":[]}
    control=data.get("defense",{}).get("control")
    print(f"\n[{s['id']}] {s['name']}")
    for step in data["steps"]:
        method=step.get("method","GET").upper(); payload=step.get("payload",{}); validate_payload(payload); headers=dict(step.get("headers",{})); expected=step.get("expected") or data.get("expected")
        if target!="default": headers["X-WebXploit-Target"]=target
        d=request(method,direct,payload,step.get("headers",{})); w=request(method,waf,payload,headers); outcome=classify_result(d,w,control,expected)
        item={"step":step["step"],"name":step["name"],"method":method,"direct_app":d,"waf_proxy":w,"outcome":outcome}
        report["results"].append(item); print(f"  step {step['step']}: direct={d.get('status_code','ERR')} waf={w.get('status_code','ERR')} -> {outcome}")
        delay=step.get("delay_seconds",0)
        if delay: time.sleep(delay)
    out=root/"reports"/"runs"; out.mkdir(parents=True,exist_ok=True); ts=datetime.now().strftime("%Y%m%d_%H%M%S"); f=out/f"{s['id']}_{ts}.json"; f.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(f"  evidence: {f}"); return report

def main():
    if len(sys.argv)<2: print("Usage: python3 engine/safe_runner.py <manifest.yaml|directory>"); sys.exit(1)
    p=Path(sys.argv[1]); files=sorted(p.glob("*.yaml")) if p.is_dir() else [p]
    if not files: raise SystemExit("No manifests found")
    reports=[run_manifest(x) for x in files]
    counts={}
    for r in reports:
        for x in r["results"]: counts[x["outcome"]]=counts.get(x["outcome"],0)+1
    print("\nSuite summary:")
    for k,v in sorted(counts.items()): print(f"  {k}: {v}")

if __name__=="__main__": main()
