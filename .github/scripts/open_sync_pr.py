#!/usr/bin/env python3
"""Publish a pretested metadata update; never overwrite an existing bot branch."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from registry import SDK_REPOSITORIES

def run(*args,**kwargs):return subprocess.check_output(args,text=True,**kwargs).strip()
repo=os.environ["GITHUB_REPOSITORY"]
if repo not in SDK_REPOSITORIES.values():
    raise SystemExit("repository is not in the SDK allowlist")
lock=json.loads(Path("protocol-lock.json").read_text())
ref=lock["ref"]
if not re.fullmatch(r"[0-9a-f]{40}",ref) or lock.get("repository")!="licensebox/protocol":raise SystemExit("invalid contract pin")
allowed=["protocol-lock.json"]
if repo=="licensebox/cpp":allowed.append("c-version.cmake")
if Path("native-version.txt").is_file():allowed.append("native-version.txt")
changed=run("git","diff","--name-only").splitlines()
if set(changed)-set(allowed):raise SystemExit("unexpected tracked changes in metadata-only sync")
untracked=run("git","ls-files","--others","--exclude-standard").splitlines()
if set(untracked)-set(allowed):raise SystemExit("unexpected untracked files in metadata-only sync")
if not changed and not untracked:
    print("Already current");raise SystemExit(0)
branch="automation/protocol-"+ref[:12]
existing=run("gh","api",f"repos/{repo}/pulls?state=open&head=licensebox:{branch}")
if json.loads(existing):
    print("Update PR already exists; preserving its changes");raise SystemExit(0)
if run("git","ls-remote","--heads","origin",branch):
    print("Update branch already exists; preserving its changes");raise SystemExit(0)
run("git","config","user.name","github-actions[bot]")
run("git","config","user.email","41898282+github-actions[bot]@users.noreply.github.com")
run("git","switch","-c",branch)
run("git","add","--",*allowed)
run("git","commit","-m",f"Sync Licensebox contract revision {lock['revision']}")
run("git","push","origin",f"HEAD:refs/heads/{branch}")
validation=f"https://github.com/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
body=(f"Update the pinned Licensebox contract to `{ref}` (revision {lock['revision']}).\n\n"
      "The Linux SDK and shared behavioral conformance checks passed against this contract before this PR was created. "
      f"Validation: {validation}. "
      "Review any required language-specific implementation changes before release. No package publication is performed.\n")
with tempfile.NamedTemporaryFile(mode="w",suffix=".md") as file:
    file.write(body);file.flush()
    print(run("gh","pr","create","--repo",repo,"--base","main","--head",branch,"--title",f"Sync SDK contract revision {lock['revision']}","--body-file",file.name))
# Explicit dispatch avoids relying on token-created PR event approval behavior.
run("gh","workflow","run","test.yml","--repo",repo,"--ref",branch)
if repo=="licensebox/go":
    run("gh","workflow","run","conformance.yml","--repo",repo,"--ref",branch)
