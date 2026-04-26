# ContainerGuard scanner (`scanner.py`)

A dependency-free Python scanner that produces a JSON report consumable by
the ContainerGuard dashboard via the **Upload JSON** page.

## What it checks

**Local (real checks):**
- **Docker daemon** — privileged containers, `/var/run/docker.sock` bind
  mounts, containers running as root.
- **Host hardening** — `sshd_config` (`PermitRootLogin`,
  `PasswordAuthentication`), and listening ports on common sensitive
  services (22, 3306, 3389, 5432, 6379).

**Cloud (simulated by default):**
- AWS EC2 misconfig audit
- Azure VM hardening check
- GCP instance security scanner

The cloud sections emit realistic stand-in data so the demo runs anywhere.
Replace the `simulate_*` functions with `boto3` / `azure-mgmt` /
`google-cloud-compute` calls when you wire up live credentials.

## Usage

```bash
# Print report to stdout
python3 scanner.py

# Write report to a file
python3 scanner.py -o report.json --pretty

# Local checks only (skip simulated cloud scans)
python3 scanner.py -o local.json --no-cloud --pretty
```

The dashboard accepts the resulting `report.json` directly — open the app,
go to **Upload JSON**, and drop the file in. The Reports page repopulates
with summary stats, the script execution history table, and per-scan
detail modals driven by the file you uploaded.

## Output schema

```jsonc
{
  "metadata": { "tool": "ContainerGuard", "version": "0.1.0", "operator": "...", "exported_at": "..." },
  "summary": {
    "total_scans_run": 5,
    "total_vms_scanned": 268,
    "last_scan_date": "2026-04-26",
    "total_findings": 31,
    "findings_by_severity": { "critical": 5, "high": 10, "medium": 12, "low": 4 }
  },
  "script_execution_history": [
    {
      "id": "scan-2026-04-26-aws",
      "script_name": "AWS EC2 Misconfig Audit",
      "cloud_provider": "AWS",
      "vms_scanned": 87,
      "run_date": "2026-04-26",
      "duration_seconds": 142,
      "status": "Success",          // "Success" | "Partial" | "Failed"
      "operator": "eric.dominguez",
      "regions": ["us-east-1", "us-east-2"],
      "notes": "...",
      "findings_summary": { "total": 14, "critical": 3, "high": 5, "medium": 4, "low": 2 },
      "collected_data": [
        { "instance_id": "...", "name": "...", "type": "...",
          "region": "...", "state": "running", "findings_count": 2 }
      ]
    }
  ]
}
```

The dashboard validates that `summary.total_scans_run` is a number and
`script_execution_history` is an array; everything else is optional.

## Extending the scanner

To add a new cloud module, write a function that returns a single scan
record (same shape as the entries above) and append it to the `scans`
list inside `main()`. The aggregator will roll its findings into the
top-level `summary` automatically.
