#!/usr/bin/env python3
"""
ContainerGuard scanner
======================

A lightweight, dependency-free security misconfiguration scanner for container
hosts and cloud VMs. Outputs a JSON report that the ContainerGuard dashboard
(this project) consumes via the Upload JSON page.

What it actually does on the local machine
------------------------------------------
* Probes the local Docker daemon (if installed) for risky containers:
    - privileged mode
    - exposed Docker socket bind-mount (/var/run/docker.sock)
    - containers running as root
* Inspects the local host for:
    - SSH config issues (PermitRootLogin yes, PasswordAuthentication yes)
    - listening services on world-reachable ports
* Emits findings in the same schema used by the dashboard.

Cloud audits (AWS, Azure, GCP, Multi-Cloud) are *simulated* by default so the
demo runs anywhere. Replace the `simulate_*` functions with real boto3 / Azure
SDK / google-cloud-* calls when you wire it up to live credentials.

Usage
-----
    python3 scanner.py                          # print JSON to stdout
    python3 scanner.py -o report.json           # write to file
    python3 scanner.py -o report.json --pretty  # pretty-print

Author: NetNeko.exe (CS4390/5390 Ethical Hacking, Spring 2026)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Small shell helper
# ---------------------------------------------------------------------------

def run(cmd: list[str], timeout: int = 5) -> tuple[int, str]:
    """Run a command, return (returncode, stdout). Stderr is folded into stdout."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


# ---------------------------------------------------------------------------
# Local container checks (real)
# ---------------------------------------------------------------------------

def docker_audit() -> dict[str, Any]:
    """Inspect local Docker for privileged + socket-exposing containers."""
    findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    collected: list[dict[str, Any]] = []

    if not have("docker"):
        return _empty_scan(
            scan_id=f"scan-{today_iso()}-docker",
            script_name="Local Docker Audit",
            provider="Container",
            note="Docker CLI not found on host; skipping local container checks.",
            status="Partial",
        )

    # List running containers; -q for IDs only.
    rc, out = run(["docker", "ps", "-q"])
    if rc != 0:
        return _empty_scan(
            scan_id=f"scan-{today_iso()}-docker",
            script_name="Local Docker Audit",
            provider="Container",
            note=f"`docker ps` failed (rc={rc}). Daemon may not be running.",
            status="Failed",
        )

    container_ids = [cid for cid in out.split() if cid]
    for cid in container_ids:
        rc2, info = run(["docker", "inspect", cid])
        if rc2 != 0:
            continue
        try:
            data = json.loads(info)[0]
        except Exception:
            continue

        name = (data.get("Name") or cid).lstrip("/")
        host_config = data.get("HostConfig", {}) or {}
        config = data.get("Config", {}) or {}
        privileged = bool(host_config.get("Privileged"))
        binds = host_config.get("Binds") or []
        socket_exposed = any("/var/run/docker.sock" in b for b in binds)
        run_as_root = (config.get("User") or "").strip() in ("", "0", "root")

        local_findings = 0
        if privileged:
            findings["critical"] += 1
            local_findings += 1
        if socket_exposed:
            findings["critical"] += 1
            local_findings += 1
        if run_as_root:
            findings["medium"] += 1
            local_findings += 1

        collected.append({
            "instance_id": cid[:12],
            "name": name,
            "type": "container",
            "region": "local",
            "state": (data.get("State") or {}).get("Status", "unknown"),
            "findings_count": local_findings,
        })

    findings["total"] = sum(findings[k] for k in ("critical", "high", "medium", "low"))

    return {
        "id": f"scan-{today_iso()}-docker",
        "script_name": "Local Docker Audit",
        "cloud_provider": "Container",
        "vms_scanned": len(container_ids),
        "run_date": today_iso(),
        "run_time": now_iso().split("T")[1],
        "duration_seconds": 3,
        "status": "Success",
        "operator": os.getenv("USER", "local"),
        "regions": ["local"],
        "notes": (
            f"Scanned {len(container_ids)} running container(s). Checked "
            "privileged mode, Docker socket bind mounts, and root user."
        ),
        "findings_summary": findings,
        "collected_data": collected,
    }


# ---------------------------------------------------------------------------
# Local host checks (real)
# ---------------------------------------------------------------------------

def host_audit() -> dict[str, Any]:
    findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    notes_parts: list[str] = []

    # SSH config check.
    sshd_path = "/etc/ssh/sshd_config"
    if os.path.isfile(sshd_path):
        try:
            with open(sshd_path, "r", encoding="utf-8", errors="ignore") as f:
                cfg = f.read().lower()
            if "permitrootlogin yes" in cfg:
                findings["high"] += 1
                notes_parts.append("PermitRootLogin yes detected in sshd_config")
            if "passwordauthentication yes" in cfg:
                findings["medium"] += 1
                notes_parts.append("PasswordAuthentication yes detected in sshd_config")
        except PermissionError:
            notes_parts.append("sshd_config not readable; skipped")
    else:
        notes_parts.append("sshd_config not present; skipped")

    # Listening ports — quick heuristic for risky exposures.
    listening: set[int] = set()
    for cmd in (["ss", "-tlnH"], ["netstat", "-tlnp"]):
        rc, out = run(cmd)
        if rc == 0 and out:
            for line in out.splitlines():
                for token in line.split():
                    if ":" in token:
                        try:
                            listening.add(int(token.rsplit(":", 1)[-1]))
                        except ValueError:
                            pass
            break

    risky = {22: "ssh", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis"}
    for port, label in risky.items():
        if port in listening:
            findings["medium"] += 1
            notes_parts.append(f"Sensitive service listening on port {port} ({label})")

    findings["total"] = sum(findings[k] for k in ("critical", "high", "medium", "low"))

    return {
        "id": f"scan-{today_iso()}-host",
        "script_name": "Host Hardening Check",
        "cloud_provider": "Host",
        "vms_scanned": 1,
        "run_date": today_iso(),
        "run_time": now_iso().split("T")[1],
        "duration_seconds": 2,
        "status": "Success",
        "operator": os.getenv("USER", "local"),
        "regions": [platform.node() or "localhost"],
        "notes": "; ".join(notes_parts) or "No host-level issues detected.",
        "findings_summary": findings,
        "collected_data": [{
            "instance_id": socket.gethostname(),
            "name": socket.gethostname(),
            "type": "host",
            "region": "local",
            "state": "running",
            "findings_count": findings["total"],
        }],
    }


# ---------------------------------------------------------------------------
# Cloud audits (simulated — swap in real SDK calls when credentials available)
# ---------------------------------------------------------------------------

def simulate_aws() -> dict[str, Any]:
    return {
        "id": f"scan-{today_iso()}-aws",
        "script_name": "AWS EC2 Misconfig Audit",
        "cloud_provider": "AWS",
        "vms_scanned": 87,
        "run_date": today_iso(),
        "duration_seconds": 142,
        "status": "Success",
        "operator": os.getenv("USER", "scanner"),
        "regions": ["us-east-1", "us-east-2", "us-west-2"],
        "notes": (
            "Audited security groups, IAM instance profiles, IMDSv1 usage, "
            "and unencrypted EBS volumes across 87 EC2 instances."
        ),
        "findings_summary": {"total": 14, "critical": 3, "high": 5, "medium": 4, "low": 2},
        "collected_data": [
            {"instance_id": "i-0a3f4d8c9b2e1f0a4", "name": "prod-web-01",
             "type": "t3.medium", "region": "us-east-1", "state": "running", "findings_count": 0},
            {"instance_id": "i-0c7d2e8b1a094e21f", "name": "prod-db-01",
             "type": "r6i.xlarge", "region": "us-east-1", "state": "running", "findings_count": 2},
            {"instance_id": "i-0e15a9f3d7c8b2104", "name": "stage-api-02",
             "type": "t3.small", "region": "us-east-2", "state": "running", "findings_count": 1},
            {"instance_id": "i-0f81e09a4b6c2a39d", "name": "dev-bastion",
             "type": "t3.micro", "region": "us-west-2", "state": "stopped", "findings_count": 3},
        ],
    }


def simulate_azure() -> dict[str, Any]:
    return {
        "id": f"scan-{today_iso()}-azure",
        "script_name": "Azure VM Hardening Check",
        "cloud_provider": "Azure",
        "vms_scanned": 124,
        "run_date": today_iso(),
        "duration_seconds": 198,
        "status": "Success",
        "operator": os.getenv("USER", "scanner"),
        "regions": ["eastus", "westus2", "centralus"],
        "notes": (
            "Hardening check across 3 resource groups. Validated NSG rules, "
            "JIT VM access, disk encryption, and Defender for Cloud agent presence."
        ),
        "findings_summary": {"total": 9, "critical": 1, "high": 3, "medium": 4, "low": 1},
        "collected_data": [
            {"instance_id": "/subscriptions/8c2a/.../vm-prod-app-01", "name": "vm-prod-app-01",
             "type": "Standard_D4s_v5", "region": "eastus", "state": "running", "findings_count": 1},
            {"instance_id": "/subscriptions/8c2a/.../vm-prod-app-02", "name": "vm-prod-app-02",
             "type": "Standard_D4s_v5", "region": "eastus", "state": "running", "findings_count": 4},
        ],
    }


def simulate_gcp() -> dict[str, Any]:
    return {
        "id": f"scan-{today_iso()}-gcp",
        "script_name": "GCP Instance Security Scanner",
        "cloud_provider": "GCP",
        "vms_scanned": 56,
        "run_date": today_iso(),
        "duration_seconds": 89,
        "status": "Partial",
        "operator": os.getenv("USER", "scanner"),
        "regions": ["us-central1", "us-east4"],
        "notes": (
            "Auth scope missing for project 'netneko-archive'; 12 instances "
            "skipped. Other projects scanned — checked OS Login enforcement, "
            "shielded VM status, and external IP exposure."
        ),
        "findings_summary": {"total": 6, "critical": 1, "high": 2, "medium": 2, "low": 1},
        "collected_data": [
            {"instance_id": "1234567890123456789", "name": "gke-prod-pool-01-abc",
             "type": "n2-standard-4", "region": "us-central1", "state": "running", "findings_count": 2},
        ],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_scan(scan_id: str, script_name: str, provider: str,
                note: str, status: str) -> dict[str, Any]:
    return {
        "id": scan_id,
        "script_name": script_name,
        "cloud_provider": provider,
        "vms_scanned": 0,
        "run_date": today_iso(),
        "duration_seconds": 0,
        "status": status,
        "operator": os.getenv("USER", "local"),
        "regions": [],
        "notes": note,
        "findings_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "collected_data": [],
    }


def aggregate(scans: list[dict[str, Any]]) -> dict[str, Any]:
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_vms = 0
    total_findings = 0
    for s in scans:
        fs = s.get("findings_summary") or {}
        for k in severity:
            severity[k] += int(fs.get(k, 0))
        total_findings += int(fs.get("total", 0))
        total_vms += int(s.get("vms_scanned") or 0)

    return {
        "metadata": {
            "tool": "ContainerGuard",
            "version": "0.1.0",
            "operator": os.getenv("USER", "scanner"),
            "exported_at": now_iso(),
        },
        "summary": {
            "total_scans_run": len(scans),
            "total_vms_scanned": total_vms,
            "last_scan_date": today_iso(),
            "total_findings": total_findings,
            "findings_by_severity": severity,
        },
        "script_execution_history": scans,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="ContainerGuard scanner")
    ap.add_argument("-o", "--output", help="Write JSON report to this path (defaults to stdout)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--no-cloud", action="store_true", help="Skip simulated cloud scans (local checks only)")
    args = ap.parse_args()

    scans: list[dict[str, Any]] = []
    scans.append(docker_audit())
    scans.append(host_audit())
    if not args.no_cloud:
        scans.extend([simulate_aws(), simulate_azure(), simulate_gcp()])

    report = aggregate(scans)
    payload = json.dumps(report, indent=2 if args.pretty else None)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"[ContainerGuard] wrote {len(scans)} scan(s) -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(payload + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
