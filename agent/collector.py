"""Collect a Windows process/service snapshot and optionally submit it to Sentinel."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import psutil

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "config" / "rules.json"


def load_rules():
    with RULES_FILE.open(encoding="utf-8") as stream:
        return json.load(stream)


def norm(value):
    return str(value or "").replace("/", "\\").lower()


def process_inventory():
    processes = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "create_time"]):
        try:
            info = proc.info
            processes.append({"pid": info.get("pid"), "ppid": info.get("ppid"), "name": info.get("name") or "unknown",
                              "path": info.get("exe") or "", "user": info.get("username") or "",
                              "started_at": datetime.fromtimestamp(info["create_time"], timezone.utc).isoformat() if info.get("create_time") else None})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes


def service_inventory():
    if os.name != "nt":
        return []
    script = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Json -Depth 3 -Compress"
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=45, check=True)
        rows = json.loads(result.stdout.strip() or "[]")
        if isinstance(rows, dict):
            rows = [rows]
        services = []
        for row in rows:
            item = {"name": row.get("Name", ""), "display_name": row.get("DisplayName", ""),
                    "start_mode": row.get("StartMode", ""), "path": row.get("PathName", ""), "account": row.get("StartName", "")}
            item["config_hash"] = hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
            item["state"] = row.get("State", "")
            services.append(item)
        return services
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as exc:
        print(f"Warning: service enumeration failed: {exc}", file=sys.stderr)
        return []


def analyze(processes, services, rules):
    alerts = []
    by_pid = {p["pid"]: p for p in processes}
    for child in processes:
        parent = by_pid.get(child.get("ppid"))
        child_name = norm(child.get("name")).split("\\")[-1]
        if parent:
            parent_name = norm(parent.get("name")).split("\\")[-1]
            for rule in rules.get("suspicious_parent_child", []):
                if parent_name in [n.lower() for n in rule["parent"]] and child_name in [n.lower() for n in rule["child"]]:
                    alerts.append({"severity": rule.get("severity", "medium"), "category": "parent_child", "title": rule.get("reason", "Suspicious process lineage"),
                                   "fingerprint": f"parent-child:{parent.get('pid')}:{child.get('pid')}:{child_name}",
                                   "details": {"parent": parent, "child": child}})
        path = norm(child.get("path"))
        if path and any(marker in path for marker in rules.get("writable_path_markers", [])):
            alerts.append({"severity": "medium", "category": "writable_path", "title": "Process running from a user-writable location",
                           "fingerprint": f"writable-path:{child.get('pid')}:{path}", "details": child})
        if child_name in [n.lower() for n in rules.get("deny_process_names", [])]:
            alerts.append({"severity": "high", "category": "deny_list", "title": "Process matched configured deny list",
                           "fingerprint": f"deny:{child.get('pid')}:{child_name}", "details": child})
    service_markers = [m.lower() for m in rules.get("service_path_markers", [])]
    for service in services:
        if service.get("start_mode", "").lower() in ("auto", "automatic") and any(m in norm(service.get("path")) for m in service_markers):
            alerts.append({"severity": "high", "category": "service_path", "title": "Automatic service executable uses a user-writable path",
                           "fingerprint": f"service-path:{service.get('name')}:{service.get('config_hash')}", "details": service})
    return alerts


def collect():
    rules = load_rules()
    processes = process_inventory()
    services = service_inventory()
    hostname = platform.node()
    endpoint = os.getenv("MONITOR_ENDPOINT_ID", hostname).strip()[:128]
    return {"schema_version": "1.0", "endpoint": endpoint, "hostname": hostname,
            "captured_at": datetime.now(timezone.utc).isoformat(), "processes": processes,
            "services": services, "alerts": analyze(processes, services, rules)}


def submit(payload, base_url, token):
    if not token:
        raise RuntimeError("Set MONITOR_API_TOKEN before submitting a snapshot")
    body = json.dumps(payload).encode()
    request = Request(base_url.rstrip("/") + "/api/snapshots", data=body, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def main():
    parser = argparse.ArgumentParser(description="Windows process and service monitoring collector")
    parser.add_argument("--once", action="store_true", help="collect one snapshot (default)")
    parser.add_argument("--interval", type=int, default=0, help="repeat every N seconds")
    parser.add_argument("--output", help="also save each snapshot as JSON to this file")
    parser.add_argument("--local-only", action="store_true", help="do not submit to the API")
    args = parser.parse_args()
    while True:
        snapshot = collect()
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        print(f"{snapshot['captured_at']} endpoint={snapshot['endpoint']} processes={len(snapshot['processes'])} services={len(snapshot['services'])} alerts={len(snapshot['alerts'])}")
        if not args.local_only and os.getenv("MONITOR_API_URL"):
            try:
                print("API:", submit(snapshot, os.environ["MONITOR_API_URL"], os.getenv("MONITOR_API_TOKEN", "")))
            except (HTTPError, URLError, TimeoutError, RuntimeError) as exc:
                print(f"Submission failed: {exc}", file=sys.stderr)
                return 2
        if args.interval <= 0 or args.once:
            break
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
