#!/usr/bin/env python3
"""Find a checked protocol main commit. Uses a read-only repository token."""
import json
import os
from pathlib import Path
import re
import subprocess

def api(path):
    return json.loads(subprocess.check_output(["gh","api",path],text=True))

lock=json.loads(Path("protocol-lock.json").read_text())
if lock.get("repository")!="licensebox/protocol":
    raise SystemExit("unexpected contract repository")
target=api("repos/licensebox/protocol/commits/main")["sha"]
if not re.fullmatch(r"[0-9a-f]{40}",target):raise SystemExit("invalid contract commit")
checks=api(f"repos/licensebox/protocol/commits/{target}/check-runs")["check_runs"]
ready=bool(checks) and all(item["status"]=="completed" and item["conclusion"] in {"success","skipped","neutral"} for item in checks)
changed=ready and lock.get("ref")!=target
with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
    output.write(f"ref={target}\nchanged={'true' if changed else 'false'}\n")
print("New checked contract available" if changed else "No new checked contract")
