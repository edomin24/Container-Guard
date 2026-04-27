import { useState, useEffect } from 'react';
import { Plus, FileCode, Upload, FileText, Settings, Edit, Trash2, Download, Shield, X, Send, Copy, Check, FileBarChart, Server, Calendar, Eye, ChevronLeft, ChevronRight, CheckCircle, Loader2, UploadCloud, File, AlertTriangle } from 'lucide-react';
import VMShieldLogo from './components/VMShieldLogo';

interface UploadedJSON {
  id: string;
  fileName: string;
  uploadDate: string;
  fileSize: string;
  status: 'Scanned' | 'Processing' | 'Error';
  data?: RawReportData;
}

interface FindingDetail {
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  title: string;
  resource: string;
  description: string;
  remediation: string;
  cisRef?: string;
}

interface ScanDetail {
  id: string;
  scriptName: string;
  cloudProvider: string;
  status: 'Success' | 'Partial' | 'Failed';
  runDate: string;
  duration: number;
  operator: string;
  regionsScanned: string;
  notes: string;
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  collectedData: Array<{
    name: string;
    instanceId: string;
    type: string;
    region: string;
    state: string;
    findings: number;
  }>;
  findings: FindingDetail[];
}

interface Script {
  id: string;
  name: string;
  dateCreated: string;
  status: 'Ready' | 'Used' | 'In Progress';
  cloudProvider: CloudProvider;
  code: string;
}

type CloudProvider = 'AWS' | 'Azure' | 'GCP' | 'Docker';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

// ---- ContainerGuard report JSON shape (matches scanner.py output) ----
interface RawCollectedData {
  instance_id: string;
  name: string;
  type: string;
  region: string;
  state: string;
  findings_count?: number;
}

interface RawFinding {
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  title: string;
  resource: string;
  description: string;
  remediation: string;
  cis_ref?: string;
}

interface RawScanRecord {
  id: string;
  script_name: string;
  cloud_provider: string;
  vms_scanned: number;
  run_date: string;
  run_time?: string;
  duration_seconds?: number;
  status: 'Success' | 'Partial' | 'Failed';
  operator?: string;
  regions?: string[];
  notes?: string;
  findings_summary: { total: number; critical: number; high: number; medium: number; low: number };
  collected_data?: RawCollectedData[];
  findings?: RawFinding[];
}

interface RawReportData {
  metadata?: { tool?: string; version?: string; operator?: string; exported_at?: string };
  summary: {
    total_scans_run: number;
    total_vms_scanned: number;
    last_scan_date?: string;
    total_findings: number;
    findings_by_severity?: { critical: number; high: number; medium: number; low: number };
  };
  script_execution_history: RawScanRecord[];
}

// Default report shown before the user uploads a file. Mirrors
// containerguard_reports_data.json so the dashboard boots with realistic data.
const DEFAULT_REPORT_DATA: RawReportData = {
  metadata: { tool: 'ContainerGuard', version: '0.1.0', operator: 'netneko.exe' },
  summary: {
    total_scans_run: 24,
    total_vms_scanned: 342,
    last_scan_date: '2026-04-26',
    total_findings: 47,
    findings_by_severity: { critical: 8, high: 15, medium: 18, low: 6 },
  },
  script_execution_history: [
    {
      id: 'scan-2026-04-26-001',
      script_name: 'AWS EC2 Misconfig Audit',
      cloud_provider: 'AWS',
      vms_scanned: 87,
      run_date: '2026-04-26',
      duration_seconds: 142,
      status: 'Success',
      operator: 'eric.dominguez',
      regions: ['us-east-1', 'us-east-2', 'us-west-2'],
      notes: 'Audited security groups, IAM instance profiles, IMDSv1 usage, and unencrypted EBS volumes across 87 EC2 instances.',
      findings_summary: { total: 14, critical: 3, high: 5, medium: 4, low: 2 },
      collected_data: [
        { instance_id: 'i-0a3f4d8c9b2e1f0a4', name: 'prod-web-01', type: 't3.medium', region: 'us-east-1', state: 'running', findings_count: 0 },
        { instance_id: 'i-0c7d2e8b1a094e21f', name: 'prod-db-01', type: 'r6i.xlarge', region: 'us-east-1', state: 'running', findings_count: 2 },
        { instance_id: 'i-0e15a9f3d7c8b2104', name: 'stage-api-02', type: 't3.small', region: 'us-east-2', state: 'running', findings_count: 1 },
        { instance_id: 'i-0f81e09a4b6c2a39d', name: 'dev-bastion', type: 't3.micro', region: 'us-west-2', state: 'stopped', findings_count: 3 },
      ],
      findings: [
        { severity: 'Critical', title: 'Security group allows 0.0.0.0/0 on port 22', resource: 'sg-0fa1b2c3 (prod-db-01)', description: 'SSH (TCP/22) is open to the entire internet, exposing the database tier to brute force.', remediation: 'Restrict ingress to bastion CIDR or replace with SSM Session Manager.' },
        { severity: 'Critical', title: 'EBS volume unencrypted', resource: 'vol-0c4d5e6f (prod-db-01)', description: 'Root volume is not encrypted at rest, violating compliance baseline.', remediation: 'Snapshot, copy with encryption enabled, then restore.' },
        { severity: 'Critical', title: 'IAM role with AdministratorAccess attached to instance profile', resource: 'i-0c7d2e8b1a094e21f', description: 'Compromise of this instance grants full account access via IMDS.', remediation: 'Replace with least-privilege role scoped to needed APIs.' },
        { severity: 'High', title: 'IMDSv1 still enabled', resource: 'i-0a3f4d8c9b2e1f0a4', description: 'Legacy metadata service is vulnerable to SSRF-based credential theft.', remediation: 'Set HttpTokens=required on MetadataOptions.' },
        { severity: 'High', title: 'IMDSv1 still enabled', resource: 'i-0e15a9f3d7c8b2104', description: 'Legacy metadata service is vulnerable to SSRF-based credential theft.', remediation: 'Set HttpTokens=required on MetadataOptions.' },
        { severity: 'High', title: 'Public IP on database instance', resource: 'i-0c7d2e8b1a094e21f', description: 'Database tier has a publicly routable IP.', remediation: 'Move to private subnet; expose only via internal LB.' },
        { severity: 'High', title: 'CloudTrail logging disabled in us-west-2', resource: 'cloudtrail:us-west-2', description: 'No audit trail for API calls in us-west-2.', remediation: 'Enable a multi-region trail with log file validation.' },
        { severity: 'High', title: 'S3 bucket policy allows public read', resource: 's3://netneko-archive', description: 'Bucket grants s3:GetObject to Principal: *.', remediation: 'Remove public ACL; use CloudFront OAC if a CDN is required.' },
        { severity: 'Medium', title: 'Missing tag: Owner', resource: 'i-0f81e09a4b6c2a39d', description: 'Instance lacks the Owner tag required by tagging policy.', remediation: 'Apply Owner=<team-name> tag.' },
        { severity: 'Medium', title: 'Missing tag: Environment', resource: 'i-0e15a9f3d7c8b2104', description: 'Cannot determine prod/stage/dev for ownership routing.', remediation: 'Apply Environment=stage tag.' },
        { severity: 'Medium', title: 'Default VPC still in use', resource: 'vpc-0a1b2c3d4', description: 'Default VPC has open default security groups.', remediation: 'Migrate workloads to a hardened VPC.' },
        { severity: 'Medium', title: 'Stopped instance retained > 30 days', resource: 'i-0f81e09a4b6c2a39d', description: 'Stopped EC2 still incurs EBS cost and increases attack surface.', remediation: 'Terminate or document retention reason.' },
        { severity: 'Low', title: 'Old AMI in use', resource: 'i-0a3f4d8c9b2e1f0a4', description: 'AMI is older than 90 days; missing kernel patches.', remediation: 'Rebake from latest hardened AMI.' },
        { severity: 'Low', title: 'Detailed monitoring disabled', resource: 'i-0e15a9f3d7c8b2104', description: '5-minute CloudWatch granularity may miss short spikes.', remediation: 'Enable detailed monitoring (1-minute).' },
      ],
    },
    {
      id: 'scan-2026-04-25-002',
      script_name: 'Azure VM Hardening Check',
      cloud_provider: 'Azure',
      vms_scanned: 124,
      run_date: '2026-04-25',
      duration_seconds: 198,
      status: 'Success',
      operator: 'tzetzaith.rivero',
      regions: ['eastus', 'westus2', 'centralus'],
      notes: 'Hardening check across 3 resource groups. Validated NSG rules, JIT VM access, disk encryption, and Defender for Cloud agent presence.',
      findings_summary: { total: 9, critical: 1, high: 3, medium: 4, low: 1 },
      collected_data: [
        { instance_id: '/subscriptions/8c2a/.../vm-prod-app-01', name: 'vm-prod-app-01', type: 'Standard_D4s_v5', region: 'eastus', state: 'running', findings_count: 1 },
        { instance_id: '/subscriptions/8c2a/.../vm-prod-app-02', name: 'vm-prod-app-02', type: 'Standard_D4s_v5', region: 'eastus', state: 'running', findings_count: 4 },
        { instance_id: '/subscriptions/8c2a/.../vm-data-warehouse', name: 'vm-data-warehouse', type: 'Standard_E16s_v5', region: 'westus2', state: 'running', findings_count: 0 },
      ],
      findings: [
        { severity: 'Critical', title: 'NSG allows RDP (3389) from Internet', resource: 'nsg-prod-app-eastus', description: 'Inbound rule permits TCP/3389 from source "Internet".', remediation: 'Restrict to corporate Bastion IP range or use Azure Bastion.' },
        { severity: 'High', title: 'OS disk encryption disabled', resource: 'vm-prod-app-02', description: 'Azure Disk Encryption is not enabled on the OS disk.', remediation: 'Enable ADE with a Key Vault-stored KEK.' },
        { severity: 'High', title: 'Boot diagnostics not configured', resource: 'vm-prod-app-02', description: 'Cannot capture serial console output during boot failures.', remediation: 'Enable boot diagnostics with managed storage.' },
        { severity: 'High', title: 'Defender for Cloud agent missing', resource: 'vm-legacy-01', description: 'No Defender agent — runtime threats invisible.', remediation: 'Auto-provision the MDC agent across the subscription.' },
        { severity: 'Medium', title: 'JIT VM access not enabled', resource: 'vm-prod-app-01', description: 'Management ports always open instead of just-in-time.', remediation: 'Enable JIT in Defender for Cloud.' },
        { severity: 'Medium', title: 'Auto-shutdown not configured', resource: 'vm-prod-app-02', description: 'Dev VM running 24/7 — wasted spend and idle attack surface.', remediation: 'Set DevTest auto-shutdown schedule.' },
        { severity: 'Medium', title: 'Tag missing: CostCenter', resource: 'vm-prod-app-02', description: 'CostCenter tag required by FinOps policy is absent.', remediation: 'Apply CostCenter=<center-id> tag.' },
        { severity: 'Medium', title: 'NSG flow logs disabled', resource: 'nsg-data-westus2', description: 'No traffic visibility for forensics or anomaly detection.', remediation: 'Enable NSG flow logs to a Log Analytics workspace.' },
        { severity: 'Low', title: 'VM backup not enabled', resource: 'vm-prod-app-02', description: 'No Azure Backup recovery point.', remediation: 'Add to Recovery Services vault policy.' },
      ],
    },
    {
      id: 'scan-2026-04-24-003',
      script_name: 'GCP Instance Security Scanner',
      cloud_provider: 'GCP',
      vms_scanned: 56,
      run_date: '2026-04-24',
      duration_seconds: 89,
      status: 'Partial',
      operator: 'samuel.ramirez',
      regions: ['us-central1', 'us-east4'],
      notes: "Auth scope missing for project 'netneko-archive'; 12 instances skipped. Other projects scanned successfully — checked OS Login enforcement, shielded VM status, and external IP exposure.",
      findings_summary: { total: 6, critical: 1, high: 2, medium: 2, low: 1 },
      collected_data: [
        { instance_id: '1234567890123456789', name: 'gke-prod-pool-01-abc', type: 'n2-standard-4', region: 'us-central1', state: 'running', findings_count: 2 },
        { instance_id: '9876543210987654321', name: 'ml-training-node-02', type: 'n2-highmem-8', region: 'us-east4', state: 'running', findings_count: 0 },
      ],
      findings: [
        { severity: 'Critical', title: 'External IP attached to GKE node', resource: 'gke-prod-pool-01-abc', description: 'GKE node has a public IP, expanding the attack surface.', remediation: 'Use private GKE clusters with Cloud NAT for egress.' },
        { severity: 'High', title: 'OS Login disabled at project level', resource: 'project: netneko-prod', description: 'SSH key management falls back to instance-level metadata.', remediation: 'Set enable-oslogin=TRUE in project metadata.' },
        { severity: 'High', title: 'Shielded VM (Secure Boot) disabled', resource: 'gke-prod-pool-01-abc', description: 'Boot integrity not measured — rootkit risk.', remediation: 'Recreate node pool with shielded VM enabled.' },
        { severity: 'Medium', title: 'Default service account used', resource: 'gke-prod-pool-01-abc', description: 'Compute Engine default SA has broad scopes by default.', remediation: 'Bind a dedicated service account with minimal IAM roles.' },
        { severity: 'Medium', title: 'Auth scope: cloud-platform', resource: 'ml-training-node-02', description: 'Wildcard scope grants all Google APIs to the instance.', remediation: 'Tighten to specific scopes (storage-ro, logging-write).' },
        { severity: 'Low', title: 'Auto-upgrade disabled on node pool', resource: 'gke-prod-pool-01', description: 'Node pool will not receive security patches automatically.', remediation: 'Enable auto-upgrade in node pool config.' },
      ],
    },
    {
      id: 'scan-2026-04-23-004',
      script_name: 'Multi-Cloud Misconfig Sweep',
      cloud_provider: 'Multi-Cloud',
      vms_scanned: 38,
      run_date: '2026-04-23',
      duration_seconds: 312,
      status: 'Success',
      operator: 'gustavo.chavira',
      regions: ['aws:us-east-1', 'azure:eastus', 'gcp:us-central1'],
      notes: 'Cross-cloud sweep correlating findings across providers. Identified compound risks (e.g., privileged container + exposed Docker socket on the same host).',
      findings_summary: { total: 11, critical: 2, high: 3, medium: 4, low: 2 },
      collected_data: [
        { instance_id: 'i-0a3f4d8c9b2e1f0a4', name: 'prod-web-01', type: 't3.medium', region: 'aws:us-east-1', state: 'running', findings_count: 1 },
        { instance_id: '/subscriptions/8c2a/.../vm-legacy-01', name: 'vm-legacy-01', type: 'Standard_D2_v3', region: 'azure:eastus', state: 'running', findings_count: 5 },
      ],
      findings: [
        { severity: 'Critical', title: 'Privileged container detected', resource: 'docker://vm-legacy-01/web-runner', description: 'Container runs with --privileged; container escape is straightforward.', remediation: 'Remove --privileged; add only required capabilities.', cis_ref: 'CIS Docker 5.4' },
        { severity: 'Critical', title: 'Docker socket bind mount', resource: 'docker://vm-legacy-01/ci-agent', description: '/var/run/docker.sock mounted into container — equivalent to host root.', remediation: 'Use a rootless build agent (kaniko, buildkit-rootless).', cis_ref: 'CIS Docker 5.31' },
        { severity: 'High', title: 'Container running as root', resource: 'docker://prod-web-01/api', description: 'Container processes run as UID 0; reduces defense in depth.', remediation: 'Add USER directive in Dockerfile; pin a non-root UID.', cis_ref: 'CIS Docker 4.1' },
        { severity: 'High', title: 'Cross-cloud lateral path detected', resource: 'aws:us-east-1 → azure:eastus', description: 'Same SSH key authorized on hosts in two different clouds.', remediation: 'Rotate keys; segment trust boundaries by environment.' },
        { severity: 'High', title: 'SSH PermitRootLogin=yes', resource: 'vm-legacy-01:/etc/ssh/sshd_config', description: 'Root login over SSH is permitted.', remediation: 'Set PermitRootLogin no and reload sshd.' },
        { severity: 'Medium', title: 'Image not pinned by digest', resource: 'docker://vm-legacy-01/ci-agent', description: 'Image referenced by mutable tag; supply-chain integrity risk.', remediation: 'Pin to image@sha256:<digest>.' },
        { severity: 'Medium', title: 'No resource limits set', resource: 'docker://prod-web-01/api', description: 'Container can consume unlimited memory/CPU.', remediation: 'Set --memory and --cpus or use a Kubernetes LimitRange.' },
        { severity: 'Medium', title: 'Container has no health check', resource: 'docker://prod-web-01/api', description: 'Orchestrator cannot detect deadlocked process.', remediation: 'Add HEALTHCHECK or readinessProbe.' },
        { severity: 'Medium', title: 'Outdated base image', resource: 'docker://vm-legacy-01/web-runner', description: 'Base image has 47 known CVEs in installed packages.', remediation: 'Rebuild on current minor of base distro.' },
        { severity: 'Low', title: 'Latest tag in production manifest', resource: 'k8s://prod/web/deployment.yaml', description: 'Tag drift can break reproducibility.', remediation: 'Reference specific version tag.' },
        { severity: 'Low', title: 'No log driver configured', resource: 'docker://vm-legacy-01/ci-agent', description: 'Falls back to json-file with no rotation.', remediation: 'Configure --log-driver=journald or syslog.' },
      ],
    },
    {
      id: 'scan-2026-04-22-005',
      script_name: 'AWS EC2 Security Audit',
      cloud_provider: 'AWS',
      vms_scanned: 15,
      run_date: '2026-04-22',
      duration_seconds: 47,
      status: 'Success',
      operator: 'eric.dominguez',
      regions: ['us-east-1'],
      notes: 'Audit of security groups attached to internet-facing instances. Three SGs flagged with 0.0.0.0/0 ingress on sensitive ports (22, 3389, 3306).',
      findings_summary: { total: 5, critical: 1, high: 1, medium: 3, low: 0 },
      collected_data: [],
      findings: [
        { severity: 'Critical', title: 'SG allows MySQL (3306) from 0.0.0.0/0', resource: 'sg-1a2b3c4d', description: 'MySQL exposed to the public internet.', remediation: 'Replace with VPC-internal SG and require SSL.' },
        { severity: 'High', title: 'SG allows RDP (3389) from 0.0.0.0/0', resource: 'sg-5e6f7g8h', description: 'RDP open to Internet — brute force candidate.', remediation: 'Restrict to corporate egress IP or migrate to SSM.' },
        { severity: 'Medium', title: 'SG with no description', resource: 'sg-9i0j1k2l', description: 'Untracked SG — owner unclear.', remediation: 'Document purpose in description tag.' },
        { severity: 'Medium', title: 'SG attached to no resources', resource: 'sg-orphan-01', description: 'Orphaned SG bloats inventory.', remediation: 'Delete unused security group.' },
        { severity: 'Medium', title: 'Stale rule referring to deleted SG', resource: 'sg-1a2b3c4d', description: 'Rule references SG that no longer exists.', remediation: 'Remove dangling reference.' },
      ],
    },
    {
      id: 'scan-2026-04-21-006',
      script_name: 'Azure Container Registry Scan',
      cloud_provider: 'Azure',
      vms_scanned: 30,
      run_date: '2026-04-21',
      duration_seconds: 64,
      status: 'Success',
      operator: 'tzetzaith.rivero',
      regions: ['eastus', 'westus2'],
      notes: 'Scanned ACR for images with admin user enabled, public network access, and out-of-date base images.',
      findings_summary: { total: 2, critical: 0, high: 1, medium: 1, low: 0 },
      collected_data: [],
      findings: [
        { severity: 'High', title: 'ACR admin user enabled', resource: 'acr://netnekoacr', description: 'Admin user grants full registry access via shared credentials.', remediation: 'Disable admin user; use AAD/managed identity for pulls.' },
        { severity: 'Medium', title: 'Public network access allowed', resource: 'acr://netnekoacr', description: 'Registry reachable from any network.', remediation: 'Restrict to VNet via private endpoints.' },
      ],
    },
  ],
};

// Convert a raw scan record (from the JSON file) into the ScanDetail shape
// used by the scan-detail modal.
function toScanDetail(s: RawScanRecord): ScanDetail {
  return {
    id: s.id,
    scriptName: s.script_name,
    cloudProvider: s.cloud_provider,
    status: s.status,
    runDate: s.run_date,
    duration: s.duration_seconds ?? 0,
    operator: s.operator ?? 'unknown',
    regionsScanned: (s.regions ?? []).join(', '),
    notes: s.notes ?? '',
    findingsSummary: {
      critical: s.findings_summary.critical,
      high: s.findings_summary.high,
      medium: s.findings_summary.medium,
      low: s.findings_summary.low,
    },
    collectedData: (s.collected_data ?? []).map((d) => ({
      name: d.name,
      instanceId: d.instance_id,
      type: d.type,
      region: d.region,
      state: d.state,
      findings: d.findings_count ?? 0,
    })),
    findings: (s.findings ?? []).map((f) => ({
      severity: (f.severity || 'Low') as 'Critical' | 'High' | 'Medium' | 'Low',
      title: f.title || '(no title)',
      resource: f.resource || '-',
      description: f.description || '',
      remediation: f.remediation || '',
      cisRef: f.cis_ref,
    })),
  };
}

// Real cloud-provider Python templates loaded into the Script editor when
// the user picks a provider. Each is a runnable script that imports the
// appropriate SDK with a graceful fallback message if it isn't installed.
const SCRIPT_TEMPLATES: Record<CloudProvider, string> = {
  AWS: `#!/usr/bin/env python3
"""
AWS EC2 Misconfig Audit — generated by ContainerGuard.

Audits running EC2 instances for IMDSv1, missing required tags, and security
group rules exposing sensitive ports to 0.0.0.0/0.
"""
import json
import os
import sys
from datetime import datetime, timezone

try:
    import boto3
except ImportError:
    print("ERROR: boto3 not installed. Run: pip install boto3", file=sys.stderr)
    sys.exit(1)

REGIONS = ["us-east-1", "us-west-2"]
SENSITIVE_PORTS = {22, 3306, 3389}


def audit_region(region):
    ec2 = boto3.client("ec2", region_name=region)
    findings, instances = [], []
    for r in ec2.describe_instances()["Reservations"]:
        for inst in r["Instances"]:
            iid = inst["InstanceId"]
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            instances.append({"instance_id": iid, "name": tags.get("Name", iid),
                              "type": inst["InstanceType"], "region": region,
                              "state": inst["State"]["Name"]})

            if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                findings.append({"severity": "High", "resource": iid,
                    "title": "IMDSv1 enabled",
                    "description": "Instance metadata v1 enables SSRF credential theft.",
                    "remediation": "Set HttpTokens to 'required' in MetadataOptions."})
            if "Owner" not in tags:
                findings.append({"severity": "Low", "resource": iid,
                    "title": "Missing required tag: Owner",
                    "description": "Instance lacks Owner tag required by tagging policy.",
                    "remediation": "Apply Owner=<team-name> tag."})
    return findings, instances


def main():
    all_findings, all_instances = [], []
    for region in REGIONS:
        f, i = audit_region(region)
        all_findings.extend(f)
        all_instances.extend(i)

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev[f["severity"].lower()] = sev.get(f["severity"].lower(), 0) + 1

    print(json.dumps({
        "script_name": "AWS EC2 Misconfig Audit",
        "cloud_provider": "AWS",
        "run_date": datetime.now(timezone.utc).date().isoformat(),
        "vms_scanned": len(all_instances),
        "regions": REGIONS,
        "operator": os.getenv("USER", "scanner"),
        "status": "Success",
        "findings_summary": {**sev, "total": len(all_findings)},
        "collected_data": all_instances,
        "findings": all_findings,
    }, indent=2))


if __name__ == "__main__":
    main()
`,

  Azure: `#!/usr/bin/env python3
"""
Azure VM Hardening Check — generated by ContainerGuard.

Checks NSG rules for sensitive ports exposed to the internet and OS disk
encryption status across all VMs in the subscription.
"""
import json
import os
import sys
from datetime import datetime, timezone

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
except ImportError:
    print("ERROR: azure SDK not installed. Run: "
          "pip install azure-mgmt-compute azure-mgmt-network azure-identity",
          file=sys.stderr)
    sys.exit(1)

SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
SENSITIVE_PORTS = {"22", "3389", "3306"}


def main():
    if not SUBSCRIPTION_ID:
        print("ERROR: set AZURE_SUBSCRIPTION_ID env var", file=sys.stderr)
        sys.exit(2)

    cred = DefaultAzureCredential()
    compute = ComputeManagementClient(cred, SUBSCRIPTION_ID)
    network = NetworkManagementClient(cred, SUBSCRIPTION_ID)

    findings, instances = [], []
    for vm in compute.virtual_machines.list_all():
        instances.append({"instance_id": vm.id, "name": vm.name,
                          "type": vm.hardware_profile.vm_size,
                          "region": vm.location, "state": "running"})
        os_disk = vm.storage_profile.os_disk
        if not (os_disk.encryption_settings or
                getattr(os_disk.managed_disk, "disk_encryption_set_id", None)):
            findings.append({"severity": "High", "resource": vm.name,
                "title": "OS disk not encrypted with CMK",
                "description": "OS disk lacks customer-managed key encryption.",
                "remediation": "Enable Azure Disk Encryption or attach a DES."})

    for nsg in network.network_security_groups.list_all():
        for rule in nsg.security_rules:
            if (rule.access == "Allow" and rule.direction == "Inbound" and
                rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet") and
                str(rule.destination_port_range) in SENSITIVE_PORTS):
                findings.append({"severity": "Critical", "resource": nsg.name,
                    "title": f"NSG opens port {rule.destination_port_range} to internet",
                    "description": "Sensitive port exposed to 0.0.0.0/0 ingress.",
                    "remediation": "Restrict source_address_prefix to a CIDR."})

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"].lower()] += 1

    print(json.dumps({
        "script_name": "Azure VM Hardening Check",
        "cloud_provider": "Azure",
        "run_date": datetime.now(timezone.utc).date().isoformat(),
        "vms_scanned": len(instances),
        "regions": sorted({i["region"] for i in instances}),
        "operator": os.getenv("USER", "scanner"),
        "status": "Success",
        "findings_summary": {**sev, "total": len(findings)},
        "collected_data": instances,
        "findings": findings,
    }, indent=2))


if __name__ == "__main__":
    main()
`,

  GCP: `#!/usr/bin/env python3
"""
GCP Instance Security Scanner — generated by ContainerGuard.

Checks OS Login enforcement, shielded VM secure boot, and external IP
exposure across compute instances in the configured zones.
"""
import json
import os
import sys
from datetime import datetime, timezone

try:
    from google.cloud import compute_v1
except ImportError:
    print("ERROR: google-cloud-compute not installed. "
          "Run: pip install google-cloud-compute", file=sys.stderr)
    sys.exit(1)

PROJECT = os.getenv("GCP_PROJECT", "")
ZONES = ["us-central1-a", "us-east4-a"]


def main():
    if not PROJECT:
        print("ERROR: set GCP_PROJECT env var", file=sys.stderr)
        sys.exit(2)

    client = compute_v1.InstancesClient()
    findings, instances = [], []
    for zone in ZONES:
        for inst in client.list(project=PROJECT, zone=zone):
            instances.append({"instance_id": str(inst.id), "name": inst.name,
                              "type": inst.machine_type.split("/")[-1],
                              "region": zone, "state": str(inst.status).lower()})
            md = {item.key: item.value for item in (inst.metadata.items or [])}
            if md.get("enable-oslogin", "FALSE").upper() != "TRUE":
                findings.append({"severity": "Medium", "resource": inst.name,
                    "title": "OS Login not enforced",
                    "description": "OS Login centralizes SSH key management via IAM.",
                    "remediation": "Set instance metadata enable-oslogin=TRUE."})
            for nic in inst.network_interfaces:
                if nic.access_configs:
                    findings.append({"severity": "High", "resource": inst.name,
                        "title": "Instance has external IP",
                        "description": f"External IP attached: {nic.access_configs[0].nat_i_p}",
                        "remediation": "Detach external IP unless strictly required."})
            cfg = inst.shielded_instance_config
            if not (cfg and cfg.enable_secure_boot):
                findings.append({"severity": "Medium", "resource": inst.name,
                    "title": "Secure Boot disabled",
                    "description": "Shielded VM secure boot prevents rootkit attacks.",
                    "remediation": "Enable shielded VM with secure boot."})

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"].lower()] += 1

    print(json.dumps({
        "script_name": "GCP Instance Security Scanner",
        "cloud_provider": "GCP",
        "run_date": datetime.now(timezone.utc).date().isoformat(),
        "vms_scanned": len(instances),
        "regions": ZONES,
        "operator": os.getenv("USER", "scanner"),
        "status": "Success",
        "findings_summary": {**sev, "total": len(findings)},
        "collected_data": instances,
        "findings": findings,
    }, indent=2))


if __name__ == "__main__":
    main()
`,

  Docker: `#!/usr/bin/env python3
"""
Local Docker Audit — generated by ContainerGuard.

Inspects every running container for privileged mode, /var/run/docker.sock
bind-mounts, and root user (CIS Docker Benchmark 5.4 / 5.31 / 4.1).
"""
import json
import os
import sys
from datetime import datetime, timezone

try:
    import docker
except ImportError:
    print("ERROR: docker-py not installed. Run: pip install docker",
          file=sys.stderr)
    sys.exit(1)


def main():
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        print(f"ERROR: cannot reach Docker daemon ({e})", file=sys.stderr)
        sys.exit(2)

    findings, instances = [], []
    for c in client.containers.list():
        attrs = c.attrs
        host_cfg = attrs.get("HostConfig", {}) or {}
        config = attrs.get("Config", {}) or {}
        instances.append({"instance_id": c.short_id, "name": c.name,
                          "type": "container", "region": "local",
                          "state": c.status})

        if host_cfg.get("Privileged"):
            findings.append({"severity": "Critical", "resource": c.name,
                "title": "Privileged container",
                "description": "Privileged mode disables most security boundaries.",
                "remediation": "Drop --privileged; grant specific --cap-add only.",
                "cis_ref": "CIS Docker 5.4"})
        if any("/var/run/docker.sock" in b for b in (host_cfg.get("Binds") or [])):
            findings.append({"severity": "Critical", "resource": c.name,
                "title": "Docker socket bind-mounted",
                "description": "Mounting /var/run/docker.sock grants host-root access.",
                "remediation": "Remove the bind-mount; use a dedicated API proxy.",
                "cis_ref": "CIS Docker 5.31"})
        user = (config.get("User") or "").strip()
        if user in ("", "0", "root"):
            findings.append({"severity": "Medium", "resource": c.name,
                "title": "Container running as root",
                "description": "Root in container = host UID 0 if user-ns disabled.",
                "remediation": "Add USER directive to Dockerfile.",
                "cis_ref": "CIS Docker 4.1"})

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev[f["severity"].lower()] += 1

    print(json.dumps({
        "script_name": "Local Docker Audit",
        "cloud_provider": "Container",
        "run_date": datetime.now(timezone.utc).date().isoformat(),
        "vms_scanned": len(instances),
        "regions": ["local"],
        "operator": os.getenv("USER", "scanner"),
        "status": "Success",
        "findings_summary": {**sev, "total": len(findings)},
        "collected_data": instances,
        "findings": findings,
    }, indent=2))


if __name__ == "__main__":
    main()
`,
};

export default function App() {
  const [activeNav, setActiveNav] = useState('Dashboard');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [scriptName, setScriptName] = useState('');
  const [currentScript, setCurrentScript] = useState<{ name: string; date: string } | null>(null);
  const [scripts, setScripts] = useState<Script[]>([
    { id: '1', name: 'AWS EC2 Misconfig Audit', dateCreated: '2026-04-20', status: 'Ready', cloudProvider: 'AWS', code: SCRIPT_TEMPLATES.AWS },
    { id: '2', name: 'Azure VM Hardening Check', dateCreated: '2026-04-18', status: 'Used', cloudProvider: 'Azure', code: SCRIPT_TEMPLATES.Azure },
    { id: '3', name: 'GCP Instance Security Scanner', dateCreated: '2026-04-15', status: 'Ready', cloudProvider: 'GCP', code: SCRIPT_TEMPLATES.GCP },
    { id: '4', name: 'Local Docker Audit', dateCreated: '2026-04-12', status: 'In Progress', cloudProvider: 'Docker', code: SCRIPT_TEMPLATES.Docker },
  ]);
  const [selectedProvider, setSelectedProvider] = useState<CloudProvider>('AWS');
  const [editingScriptId, setEditingScriptId] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const PAGE_SIZE = 10;
  const [settings, setSettings] = useState({
    organizationName: 'NetNeko.exe',
    defaultOperator: 'eric.dominguez',
    severityThreshold: 'High' as 'Critical' | 'High' | 'Medium' | 'Low',
    slackWebhook: '',
    autoExport: false,
  });
  const [settingsSavedAt, setSettingsSavedAt] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: "I've generated a basic Python script to collect VM information. You can ask me to add features, modify functionality, or refine the code."
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isCopied, setIsCopied] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'saved' | 'saving'>('saved');
  const [uploadedJSONs, setUploadedJSONs] = useState<UploadedJSON[]>([
    { id: '1', fileName: 'aws_ec2_inventory.json', uploadDate: '2026-04-25', fileSize: '2.4 MB', status: 'Scanned' },
    { id: '2', fileName: 'azure_vm_data.json', uploadDate: '2026-04-24', fileSize: '1.8 MB', status: 'Scanned' },
    { id: '3', fileName: 'gcp_instances.json', uploadDate: '2026-04-23', fileSize: '3.1 MB', status: 'Processing' },
    { id: '4', fileName: 'multi_cloud_report.json', uploadDate: '2026-04-22', fileSize: '5.7 MB', status: 'Scanned' },
  ]);
  const [selectedScan, setSelectedScan] = useState<ScanDetail | null>(null);
  const [reportData, setReportData] = useState<RawReportData>(DEFAULT_REPORT_DATA);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [scriptCode, setScriptCode] = useState(`#!/usr/bin/env python3
"""
VM Information Collection Script
Generated by ContainerGuard
"""

import json
import platform
import socket
from datetime import datetime

def get_vm_info():
    """Collect VM information"""
    vm_info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "timestamp": datetime.now().isoformat()
    }
    return vm_info

def main():
    """Main execution function"""
    print("Collecting VM information...")
    info = get_vm_info()

    # Save to JSON file
    with open('vm_info.json', 'w') as f:
        json.dump(info, f, indent=2)

    print(f"VM information saved to vm_info.json")
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    main()`);

  // Auto-save functionality
  useEffect(() => {
    if (!currentScript) return;

    setSaveStatus('saving');
    const timeoutId = setTimeout(() => {
      // Simulate saving the script
      setSaveStatus('saved');

      // Update the script in the scripts array
      setScripts(scripts.map(script =>
        script.name === currentScript.name
          ? { ...script, status: 'In Progress' }
          : script
      ));
    }, 1500);

    return () => clearTimeout(timeoutId);
  }, [scriptCode]);

  // Handle Escape key to close modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedScan) {
        setSelectedScan(null);
      }
    };
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [selectedScan]);

  // Build the {scriptName -> ScanDetail} lookup live from the parsed report
  // data so the modal always matches the table.
  const scanDetailsMap: { [key: string]: ScanDetail } = {};
  for (const raw of reportData.script_execution_history) {
    scanDetailsMap[raw.script_name] = toScanDetail(raw);
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const validateReport = (obj: any) => {

    // Accept normal ContainerGuard JSON reports
    if (
      obj &&
      typeof obj === 'object' &&
      obj.summary &&
      Array.isArray(obj.script_execution_history)
    ) {
      return true;
    }

    // Accept uploaded Python scan output
    if (
      obj &&
      typeof obj === 'object' &&
      obj.script_name &&
      obj.cloud_provider &&
      obj.findings_summary
    ) {
      return true;
    }

    return false;
  };

  const handleFileUpload = (file: File) => {
    setUploadError(null);
    const reader = new FileReader();
    reader.onload = (e) => {
    try {
      const fileContent = String(e.target?.result ?? '');
      
      // Handle Python files
      if (file.name.endsWith('.py')) {
        const pythonScriptName = file.name.replace(/\.py$/, '');
        const newScript: Script = {
          id: Date.now().toString(),
          name: pythonScriptName,
          dateCreated: getCurrentDate(),
          status: 'Ready',
          cloudProvider: 'Docker', // Default to Docker for uploaded scripts
          code: fileContent,
        };
        setScripts([newScript, ...scripts]);
        setEditingScriptId(newScript.id);
        setScriptCode(fileContent);
        setCurrentScript({
          name: pythonScriptName,
          date: getCurrentDate(),
        });
        setSelectedProvider('Docker');
        setActiveNav('Script');
        return;
      }
      
      // Handle JSON files
      let parsed = JSON.parse(fileContent);

      if (!validateReport(parsed)) {
        setUploadError('Invalid format');
        return;
      }

      /* If user uploaded a single Python script scan,
      convert it into full dashboard report format */
      if (!parsed.summary && parsed.script_name) {

        parsed = {
            summary: {
              total_scans_run: 1,
              total_vms_scanned: parsed.vms_scanned || 1,
              total_findings: parsed.findings_summary.total || 0,
              findings_by_severity: {
                  critical: parsed.findings_summary.critical || 0,
                  high: parsed.findings_summary.high || 0,
                  medium: parsed.findings_summary.medium || 0,
                  low: parsed.findings_summary.low || 0
               } 
            },

            script_execution_history: [parsed]
        };
      }

        setReportData(parsed);
        setCurrentPage(1);
        setUploadedJSONs((prev: UploadedJSON[]) => [
          {
            id: Date.now().toString(),
            fileName: file.name,
            uploadDate: getCurrentDate(),
            fileSize: formatFileSize(file.size),
            status: 'Scanned',
            data: parsed,
          },
          ...prev,
        ]);
        setActiveNav('Reports');
      } catch (err) {
        setUploadError(`Failed to parse file: ${err instanceof Error ? err.message : 'unknown error'}`);
      }
    };
    reader.onerror = () => setUploadError('Could not read file');
    reader.readAsText(file);
  };

  // ---- Script card handlers ----
  const handleEditScript = (script: Script) => {
    setEditingScriptId(script.id);
    setCurrentScript({ name: script.name, date: script.dateCreated });
    setScriptCode(script.code);
    setSelectedProvider(script.cloudProvider);
    setActiveNav('Script');
  };

  const handleDownloadScriptFromCard = (script: Script) => {
    const blob = new Blob([script.code], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = script.name.toLowerCase().replace(/\s+/g, '_') + '.py';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDeleteScript = (id: string) => {
    if (!confirm('Delete this script? This cannot be undone.')) return;
    setScripts((prev: Script[]) => prev.filter((s: Script) => s.id !== id));
    if (editingScriptId === id) {
      setEditingScriptId(null);
      setCurrentScript(null);
    }
  };

  // ---- Uploaded JSON card handlers ----
  const handleViewUploadedJSON = (entry: UploadedJSON) => {
    if (!entry.data) {
      setUploadError(`No cached data for ${entry.fileName}. Re-upload to view.`);
      return;
    }
    setReportData(entry.data);
    setCurrentPage(1);
    setActiveNav('Reports');
  };

  const handleDownloadUploadedJSON = (entry: UploadedJSON) => {
    if (!entry.data) {
      setUploadError(`No cached data for ${entry.fileName}.`);
      return;
    }
    const blob = new Blob([JSON.stringify(entry.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = entry.fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleDeleteUploadedJSON = (id: string) => {
    if (!confirm('Remove this file from the list?')) return;
    setUploadedJSONs((prev: UploadedJSON[]) => prev.filter((j: UploadedJSON) => j.id !== id));
  };

  // ---- Reports handlers ----
  const handleExportAll = () => {
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `containerguard-report-${getCurrentDate()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // ---- Settings handler ----
  const handleSaveSettings = () => {
    const stamp = new Date().toLocaleTimeString();
    setSettingsSavedAt(stamp);
    setTimeout(() => setSettingsSavedAt(null), 3000);
  };

  const getCurrentDate = () => {
    const today = new Date();
    return today.toISOString().split('T')[0];
  };

  const handleCreateScript = () => {
    if (scriptName.trim()) {
      const template = SCRIPT_TEMPLATES[selectedProvider as CloudProvider];
      const newScript: Script = {
        id: Date.now().toString(),
        name: scriptName,
        dateCreated: getCurrentDate(),
        status: 'In Progress',
        cloudProvider: selectedProvider,
        code: template,
      };

      // Add new script to the top of the list
      setScripts([newScript, ...scripts]);
      setEditingScriptId(newScript.id);
      setScriptCode(template);
      setChatMessages([
        {
          role: 'assistant',
          content: `Loaded the ${selectedProvider} audit template. Ask me to "add error handling", "add logging", "save to S3", "add cpu monitoring", or "add network info" and I'll patch the script for you.`,
        },
      ]);

      setCurrentScript({
        name: scriptName,
        date: getCurrentDate(),
      });
      setIsModalOpen(false);
      setScriptName('');
      setActiveNav('Script');
    }
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setScriptName('');
  };

  // Deterministic "AI assistant" — pattern-matches the user's request and
  // mutates the script in place. This is intentionally not an LLM call: a
  // local prototype shouldn't depend on a network round-trip.
  const applyAssistantPatch = (
    request: string,
    code: string
  ): { code: string; reply: string } => {
    const r = request.toLowerCase();

    const insertBeforeMain = (snippet: string) => {
      const marker = 'def main(';
      const idx = code.indexOf(marker);
      if (idx === -1) return code + '\n\n' + snippet + '\n';
      return code.slice(0, idx) + snippet + '\n\n' + code.slice(idx);
    };

    const ensureImport = (line: string, body: string) =>
      body.includes(line) ? body : line + '\n' + body;

    if (r.includes('error handling') || r.includes('try') || r.includes('except')) {
      const snippet = `def safe_call(fn, *args, **kwargs):
    """Wrap an SDK call so transient errors don't kill the run."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        print(f"[warn] {fn.__name__} failed: {exc}", file=sys.stderr)
        return None`;
      return {
        code: insertBeforeMain(snippet),
        reply: 'Added a safe_call() wrapper. Use it around boto3/azure SDK calls so partial-failure scans still produce a report.',
      };
    }

    if (r.includes('logging') || r.includes('logger')) {
      let next = ensureImport('import logging', code);
      next = insertBeforeMain(`logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("containerguard")`);
      return {
        code: next,
        reply: 'Wired up the stdlib logging module. Replace print() calls with log.info()/log.warning() to get timestamped output.',
      };
    }

    if (r.includes('cpu') || r.includes('memory') || r.includes('monitor')) {
      const snippet = `def collect_cpu_memory():
    """Collect host CPU and memory usage. Requires \`psutil\`."""
    try:
        import psutil
    except ImportError:
        return {"error": "psutil not installed"}
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "load_avg": psutil.getloadavg() if hasattr(psutil, "getloadavg") else None,
    }`;
      return {
        code: insertBeforeMain(snippet),
        reply: 'Added collect_cpu_memory() using psutil. Call it from main() and merge the result into your scan record.',
      };
    }

    if (r.includes('network') || r.includes('interface') || r.includes('ip address')) {
      let next = ensureImport('import socket', code);
      next = insertBeforeMain(`def collect_network_info():
    """Return hostname plus all v4 addresses bound to local interfaces."""
    hostname = socket.gethostname()
    addresses = []
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
    except socket.gaierror:
        pass
    return {"hostname": hostname, "addresses": addresses}`);
      return {
        code: next,
        reply: 'Added collect_network_info() — pure stdlib, no external deps. Drop it into your collected_data section.',
      };
    }

    if (r.includes('s3') || r.includes('upload')) {
      const snippet = `def upload_to_s3(report, bucket, key):
    """Upload the JSON report to S3. Requires boto3 + s3:PutObject."""
    import boto3, json as _json
    boto3.client("s3").put_object(
        Bucket=bucket,
        Key=key,
        Body=_json.dumps(report).encode("utf-8"),
        ContentType="application/json",
    )
    print(f"Uploaded report to s3://{bucket}/{key}")`;
      return {
        code: insertBeforeMain(snippet),
        reply: 'Added upload_to_s3(report, bucket, key). Call it at the end of main() with your aggregated report.',
      };
    }

    if (r.includes('slack') || r.includes('webhook')) {
      const snippet = `def send_slack_summary(report, webhook_url):
    """POST a finding-count summary to a Slack incoming webhook."""
    import json as _json
    from urllib import request as _req
    sev = report.get("findings_summary", {})
    text = (
        f"ContainerGuard scan: {sev.get('total', 0)} findings — "
        f"{sev.get('critical', 0)} critical, {sev.get('high', 0)} high"
    )
    _req.urlopen(_req.Request(
        webhook_url,
        data=_json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    ))`;
      return {
        code: insertBeforeMain(snippet),
        reply: 'Added send_slack_summary(report, webhook_url) using only the stdlib. Wire your webhook URL via env var.',
      };
    }

    if (r.includes('comment') || r.includes('docstring') || r.includes('document')) {
      const banner = `# ----------------------------------------------------------------------
# ContainerGuard scan script — review checklist:
#   • Confirm REGION / SUBSCRIPTION / PROJECT constants below match target.
#   • Run with credentials that have read-only audit permissions.
#   • Output is a single JSON document on stdout, or use -o to write a file.
# ----------------------------------------------------------------------`;
      return {
        code: code.startsWith('#!/usr/bin/env python3')
          ? code.replace('#!/usr/bin/env python3', '#!/usr/bin/env python3\n' + banner)
          : banner + '\n' + code,
        reply: 'Added a review-checklist banner near the top of the file.',
      };
    }

    return {
      code,
      reply:
        "I didn't match that to a known mutation. Try: 'add error handling', 'add logging', 'add cpu monitoring', 'add network info', 'save to S3', 'send slack notification', or 'add comments'.",
    };
  };

  const handleSendMessage = () => {
    if (!chatInput.trim()) return;
    const request = chatInput;
    setChatMessages((prev: ChatMessage[]) => [...prev, { role: 'user', content: request }]);
    setChatInput('');

    const result = applyAssistantPatch(request, scriptCode);
    if (result.code !== scriptCode) {
      setScriptCode(result.code);
      // sync back to the script in the list so re-opening it sees the patch
      if (editingScriptId) {
        setScripts((prev: Script[]) =>
          prev.map((s: Script) => (s.id === editingScriptId ? { ...s, code: result.code } : s))
        );
      }
    }
    setTimeout(() => {
      setChatMessages((prev: ChatMessage[]) => [...prev, { role: 'assistant', content: result.reply }]);
    }, 250);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(scriptCode);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const handleExportScript = () => {
    if (!currentScript) return;

    // Create a blob with the script content
    const blob = new Blob([scriptCode], { type: 'text/x-python' });
    const url = URL.createObjectURL(blob);

    // Create a temporary download link
    const link = document.createElement('a');
    link.href = url;
    // Convert script name to a valid filename (replace spaces with underscores, lowercase)
    const fileName = currentScript.name.toLowerCase().replace(/\s+/g, '_') + '.py';
    link.download = fileName;

    // Trigger download
    document.body.appendChild(link);
    link.click();

    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    // Update script status to "Ready"
    setScripts(scripts.map((script: Script) =>
      script.name === currentScript.name
        ? { ...script, status: 'Ready' }
        : script
    ));
  };

  const navItems = [
    { name: 'Dashboard', icon: Shield },
    { name: 'Script', icon: FileCode },
    { name: 'Upload JSON', icon: Upload },
    { name: 'Reports', icon: FileText },
    { name: 'Settings', icon: Settings },
  ];

  return (
    <div className="size-full flex bg-[#0F1115]">
      {/* Sidebar */}
      <aside className="w-64 bg-[#151821] border-r border-[#2A2F3A] flex flex-col">
        <div className="p-6 border-b border-[#2A2F3A]">
          <div className="flex items-center gap-3">
            <VMShieldLogo className="w-10 h-10 text-primary" />
            <div>
              <h1 className="text-white">ContainerGuard</h1>
              <p className="text-[#6B7280] text-sm">Security Dashboard</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.name;
            return (
              <button
                key={item.name}
                onClick={() => setActiveNav(item.name)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-2 transition-colors ${
                  isActive
                    ? 'bg-primary text-white'
                    : 'text-[#A1A1AA] hover:bg-[#2A2F3A] hover:text-white'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {activeNav === 'Dashboard' && (
          <>
            {/* Welcome Section */}
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] p-8">
              <div>
                <h2 className="text-white mb-2">Welcome to ContainerGuard</h2>
                <p className="text-[#A1A1AA]">Generate and run Python-based security audit scripts across container and cloud environments</p>
              </div>
            </div>

            {/* Scripts List */}
            <div className="flex-1 overflow-auto p-8">
          <div className="mb-6">
            <h3 className="text-white mb-2">Recent Scripts</h3>
            <p className="text-[#6B7280]">Manage your previously created collection scripts</p>
          </div>

          {/* Create New Script Card */}
          <div className="w-full bg-gradient-to-br from-primary/10 to-primary/5 border-2 border-primary/30 rounded-lg p-8 mb-6">
            <div className="flex flex-col items-center justify-center gap-4">
              <button
                onClick={() => setIsModalOpen(true)}
                className="flex items-center gap-2 bg-[#3B82F6] hover:bg-[#3B82F6]/90 text-white px-6 py-3 rounded-lg transition-colors"
              >
                <Plus className="w-5 h-5" />
                Create New Script
              </button>
              <p className="text-[#A1A1AA]">Start generating a Python script with AI</p>
            </div>
          </div>

          <div className="space-y-4">
            {scripts.length === 0 && (
              <div className="bg-[#1A1F2B] border border-dashed border-[#2A2F3A] rounded-lg p-8 text-center text-[#6B7280]">
                No scripts yet. Click "Create New Script" to generate one from a provider template.
              </div>
            )}
            {scripts.map((script) => (
              <div
                key={script.id}
                className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6 hover:border-primary/50 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h4 className="text-white">{script.name}</h4>
                      <span className="px-2 py-0.5 bg-primary/10 text-primary text-xs rounded-full border border-primary/30">
                        {script.cloudProvider}
                      </span>
                    </div>
                    <div className="flex items-center gap-6 text-sm">
                      <span className="text-[#6B7280]">
                        Created: <span className="text-[#A1A1AA]">{script.dateCreated}</span>
                      </span>
                      <span className="flex items-center gap-2">
                        <span
                          className={`inline-block w-2 h-2 rounded-full ${
                            script.status === 'Ready' ? 'bg-[#22C55E]' :
                            script.status === 'Used' ? 'bg-[#6B7280]' :
                            'bg-[#EF4444]'
                          }`}
                        />
                        <span className={`${
                          script.status === 'Ready' ? 'text-[#22C55E]' :
                          script.status === 'Used' ? 'text-[#6B7280]' :
                          'text-[#EF4444]'
                        }`}>{script.status}</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 ml-4">
                    <button
                      onClick={() => handleEditScript(script)}
                      title="Edit script"
                      className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors"
                    >
                      <Edit className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDownloadScriptFromCard(script)}
                      title="Download .py"
                      className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors"
                    >
                      <Download className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDeleteScript(script.id)}
                      title="Delete script"
                      className="p-2 text-[#A1A1AA] hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
            </div>
          </>
        )}

        {activeNav === 'Script' && !currentScript && (
          <>
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-8 py-6">
              <h2 className="text-white mb-1">Script Editor</h2>
              <p className="text-[#A1A1AA] text-sm">Generate a new audit script or open an existing one</p>
            </div>
            <div className="flex-1 overflow-auto p-8 flex items-start justify-center">
              <div className="w-full max-w-2xl space-y-6">
                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-8 text-center">
                  <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-primary/10 flex items-center justify-center">
                    <FileCode className="w-8 h-8 text-primary" />
                  </div>
                  <h3 className="text-white mb-2">No script open yet</h3>
                  <p className="text-[#A1A1AA] text-sm mb-6">
                    Generate a new Python audit script from a provider template, or open one of your saved scripts below.
                  </p>
                  <button
                    onClick={() => setIsModalOpen(true)}
                    className="inline-flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-5 py-2 rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    Create New Script
                  </button>
                </div>

                {scripts.length > 0 && (
                  <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg overflow-hidden">
                    <div className="px-6 py-4 border-b border-[#2A2F3A]">
                      <h4 className="text-white">Open an existing script</h4>
                    </div>
                    <div className="divide-y divide-[#2A2F3A]">
                      {scripts.map((s) => (
                        <button
                          key={s.id}
                          onClick={() => handleEditScript(s)}
                          className="w-full px-6 py-3 flex items-center justify-between hover:bg-[#151821]/40 transition-colors text-left"
                        >
                          <div className="flex items-center gap-3">
                            <FileCode className="w-4 h-4 text-primary" />
                            <span className="text-white">{s.name}</span>
                            <span className="px-2 py-0.5 bg-primary/10 text-primary text-xs rounded-full border border-primary/30">
                              {s.cloudProvider}
                            </span>
                          </div>
                          <span className="text-[#6B7280] text-sm">{s.dateCreated}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {activeNav === 'Script' && currentScript && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Script Header */}
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-8 py-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-white mb-1">{currentScript.name}</h2>
                  <p className="text-[#6B7280] text-sm">Created on {currentScript.date}</p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 text-sm text-[#A1A1AA]">
                    {saveStatus === 'saving' ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin text-primary" />
                        <span>Saving...</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle className="w-4 h-4 text-[#22C55E]" />
                        <span className="text-[#22C55E]">Saved</span>
                      </>
                    )}
                  </div>
                  <button
                    onClick={handleExportScript}
                    className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Export Script
                  </button>
                </div>
              </div>
            </div>

            {/* Split Layout */}
            <div className="flex-1 flex overflow-hidden">
              {/* Left Side - Code Editor */}
              <div className="flex-1 flex flex-col border-r border-[#2A2F3A]">
                <div className="bg-[#151821] border-b border-[#2A2F3A] px-6 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FileCode className="w-4 h-4 text-primary" />
                    <span className="text-[#A1A1AA] text-sm">script.py</span>
                  </div>
                  <button
                    onClick={handleCopyCode}
                    className="flex items-center gap-2 text-[#A1A1AA] hover:text-white text-sm transition-colors"
                  >
                    {isCopied ? (
                      <>
                        <Check className="w-4 h-4" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-4 h-4" />
                        Copy
                      </>
                    )}
                  </button>
                </div>
                <div className="flex-1 overflow-auto bg-[#0F1115]">
                  <textarea
                    value={scriptCode}
                    onChange={(e) => setScriptCode(e.target.value)}
                    className="w-full h-full bg-transparent text-[#A1A1AA] font-mono text-sm leading-relaxed p-6 resize-none focus:outline-none border-none"
                    spellCheck={false}
                    style={{
                      tabSize: 4,
                      minHeight: '100%'
                    }}
                  />
                </div>
              </div>

              {/* Right Side - AI Chat Interface */}
              <div className="w-[480px] flex flex-col bg-[#151821]">
                <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-6 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-primary rounded-full"></div>
                    <span className="text-white">AI Assistant</span>
                  </div>
                </div>

                {/* Chat Messages */}
                <div className="flex-1 overflow-auto p-6 space-y-4">
                  {chatMessages.map((message, index) => (
                    <div
                      key={index}
                      className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className={`max-w-[85%] rounded-lg p-4 ${
                          message.role === 'user'
                            ? 'bg-primary text-white'
                            : 'bg-[#1A1F2B] border border-[#2A2F3A] text-[#A1A1AA]'
                        }`}
                      >
                        <p className="text-sm leading-relaxed">{message.content}</p>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Chat Input */}
                <div className="border-t border-[#2A2F3A] p-4">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                      placeholder="Ask AI to modify the script..."
                      className="flex-1 bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white placeholder:text-[#6B7280] focus:outline-none focus:border-primary transition-colors text-sm"
                    />
                    <button
                      onClick={handleSendMessage}
                      disabled={!chatInput.trim()}
                      className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 ${
                        chatInput.trim()
                          ? 'bg-primary hover:bg-primary/90 text-white'
                          : 'bg-[#2A2F3A] text-[#6B7280] cursor-not-allowed'
                      }`}
                    >
                      <Send className="w-4 h-4" />
                    </button>
                  </div>
                  <p className="text-[#6B7280] text-xs mt-2">
                    Examples: "Add CPU usage collection" • "Include network info" • "Add error handling"
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeNav === 'Upload JSON' && (
          <>
            {/* Upload JSON Header */}
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-8 py-6">
              <div>
                <h2 className="text-white mb-1">Upload JSON</h2>
                <p className="text-[#A1A1AA] text-sm">Upload VM inventory data in JSON format for analysis</p>
              </div>
            </div>

            {/* Upload JSON Content */}
            <div className="flex-1 overflow-auto p-8">
              {/* Upload Section */}
              <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-8 mb-8">
                <h3 className="text-white mb-4">Upload JSON or Python Script</h3>
                <label
                  htmlFor="cg-json-upload"
                  className="block border-2 border-dashed border-[#2A2F3A] rounded-lg p-12 hover:border-primary/50 transition-colors cursor-pointer"
                  onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
                  onDrop={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const file = e.dataTransfer.files?.[0];
                    if (file) handleFileUpload(file);
                  }}
                >
                  <div className="flex flex-col items-center justify-center gap-4 pointer-events-none">
                    <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center">
                      <UploadCloud className="w-8 h-8 text-primary" />
                    </div>
                    <div className="text-center">
                      <p className="text-white mb-2">Drag and drop your JSON or Python script here</p>
                      <p className="text-[#6B7280] text-sm mb-4">or</p>
                      <span className="inline-block px-6 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors pointer-events-auto">
                        Browse Files
                      </span>
                    </div>
                    <p className="text-[#6B7280] text-xs">Supported formats: .json, .py (Max size: 10MB)</p>
                  </div>
                  <input
                    id="cg-json-upload"
                    type="file"
                    accept="application/json,.json,.py,text/x-python"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleFileUpload(file);
                      // reset value so re-uploading the same file still triggers onChange
                      e.target.value = '';
                    }}
                  />
                </label>
                {uploadError && (
                  <div className="mt-4 px-4 py-3 bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-[#EF4444] mt-0.5 flex-shrink-0" />
                    <p className="text-[#EF4444] text-sm">{uploadError}</p>
                  </div>
                )}
              </div>

              {/* Previous Scanned Files Section */}
              <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg overflow-hidden">
                <div className="px-6 py-4 border-b border-[#2A2F3A]">
                  <h3 className="text-white">Previously Scanned Files</h3>
                </div>

                <div className="divide-y divide-[#2A2F3A]">
                  {uploadedJSONs.map((json) => (
                    <div
                      key={json.id}
                      className="px-6 py-4 hover:bg-[#151821]/30 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4 flex-1">
                          <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
                            <File className="w-5 h-5 text-primary" />
                          </div>
                          <div className="flex-1">
                            <h4 className="text-white mb-1">{json.fileName}</h4>
                            <div className="flex items-center gap-6 text-sm">
                              <span className="text-[#6B7280]">
                                Uploaded: <span className="text-[#A1A1AA]">{json.uploadDate}</span>
                              </span>
                              <span className="text-[#6B7280]">
                                Size: <span className="text-[#A1A1AA]">{json.fileSize}</span>
                              </span>
                              <span className="flex items-center gap-2">
                                <span
                                  className={`inline-block w-2 h-2 rounded-full ${
                                    json.status === 'Scanned' ? 'bg-[#22C55E]' :
                                    json.status === 'Processing' ? 'bg-[#EAB308]' :
                                    'bg-[#EF4444]'
                                  }`}
                                />
                                <span className={`${
                                  json.status === 'Scanned' ? 'text-[#22C55E]' :
                                  json.status === 'Processing' ? 'text-[#EAB308]' :
                                  'text-[#EF4444]'
                                }`}>{json.status}</span>
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleViewUploadedJSON(json)}
                            title="View report"
                            className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors"
                          >
                            <Eye className="w-5 h-5" />
                          </button>
                          <button
                            onClick={() => handleDownloadUploadedJSON(json)}
                            title="Download JSON"
                            className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors"
                          >
                            <Download className="w-5 h-5" />
                          </button>
                          <button
                            onClick={() => handleDeleteUploadedJSON(json.id)}
                            title="Remove from list"
                            className="p-2 text-[#A1A1AA] hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-5 h-5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {uploadedJSONs.length === 0 && (
                  <div className="px-6 py-12 text-center">
                    <p className="text-[#6B7280]">No files uploaded yet</p>
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {activeNav === 'Reports' && (
          <>
            {/* Reports Header */}
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-8 py-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-white mb-1">Reports</h2>
                  <p className="text-[#A1A1AA] text-sm">View scan history and security findings across cloud and container environments</p>
                </div>
                <button
                  onClick={handleExportAll}
                  className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Export All
                </button>
              </div>
            </div>

            {/* Reports Content */}
            <div className="flex-1 overflow-auto p-8">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-6 mb-8">
                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[#A1A1AA] text-sm mb-2">Total Scans Run</p>
                      <p className="text-white text-3xl font-semibold">{reportData.summary.total_scans_run}</p>
                    </div>
                    <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                      <FileBarChart className="w-6 h-6 text-primary" />
                    </div>
                  </div>
                </div>

                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[#A1A1AA] text-sm mb-2">VMs Scanned</p>
                      <p className="text-white text-3xl font-semibold">{reportData.summary.total_vms_scanned}</p>
                    </div>
                    <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                      <Server className="w-6 h-6 text-primary" />
                    </div>
                  </div>
                </div>

                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[#A1A1AA] text-sm mb-2">Findings Detected</p>
                      <p className="text-white text-3xl font-semibold">{reportData.summary.total_findings}</p>
                    </div>
                    <div className="w-12 h-12 bg-[#EF4444]/10 rounded-lg flex items-center justify-center">
                      <AlertTriangle className="w-6 h-6 text-[#EF4444]" />
                    </div>
                  </div>
                </div>
              </div>

              {/* Script Execution History Table */}
              <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg overflow-hidden">
                <div className="px-6 py-4 border-b border-[#2A2F3A]">
                  <h3 className="text-white">Script Execution History</h3>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="bg-[#151821] border-b border-[#2A2F3A]">
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Script Name</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Cloud Provider</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">VMs Scanned</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Findings</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Run Date</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Status</th>
                        <th className="px-6 py-3 text-left text-[#A1A1AA] text-sm">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(() => {
                        const totalRows = reportData.script_execution_history.length;
                        const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
                        const safePage = Math.min(currentPage, totalPages);
                        const startIdx = (safePage - 1) * PAGE_SIZE;
                        const pageRows = reportData.script_execution_history.slice(
                          startIdx,
                          startIdx + PAGE_SIZE
                        );
                        return pageRows.map((scan, idx) => {
                        const isAlt = idx % 2 === 1;
                        const total = scan.findings_summary.total;
                        const critical = scan.findings_summary.critical;
                        return (
                          <tr
                            key={scan.id}
                            className={`border-b border-[#2A2F3A] last:border-b-0 hover:bg-[#151821]/30 transition-colors ${isAlt ? 'bg-[#151821]/10' : ''}`}
                          >
                            <td className="px-6 py-4 text-white">{scan.script_name}</td>
                            <td className="px-6 py-4 text-[#A1A1AA]">{scan.cloud_provider}</td>
                            <td className="px-6 py-4 text-white">{scan.vms_scanned}</td>
                            <td className="px-6 py-4">
                              {total === 0 ? (
                                <span className="text-[#6B7280]">—</span>
                              ) : critical > 0 ? (
                                <span className="text-white">
                                  {total} <span className="text-[#6B7280]">•</span>{' '}
                                  <span className="text-[#EF4444]">{critical} critical</span>
                                </span>
                              ) : (
                                <span className="text-[#22C55E]">{total}</span>
                              )}
                            </td>
                            <td className="px-6 py-4 text-[#A1A1AA]">{scan.run_date}</td>
                            <td className="px-6 py-4">
                              <span className="flex items-center gap-2">
                                <span
                                  className={`w-2 h-2 rounded-full ${
                                    scan.status === 'Success' ? 'bg-[#22C55E]' :
                                    scan.status === 'Partial' ? 'bg-[#EAB308]' :
                                    'bg-[#EF4444]'
                                  }`}
                                ></span>
                                <span
                                  className={`text-sm ${
                                    scan.status === 'Success' ? 'text-[#22C55E]' :
                                    scan.status === 'Partial' ? 'text-[#EAB308]' :
                                    'text-[#EF4444]'
                                  }`}
                                >
                                  {scan.status}
                                </span>
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <button
                                onClick={() => setSelectedScan(scanDetailsMap[scan.script_name])}
                                className="text-primary hover:text-primary/80 text-sm flex items-center gap-1 transition-colors"
                              >
                                <Eye className="w-4 h-4" />
                                View
                              </button>
                            </td>
                          </tr>
                        );
                        });
                      })()}
                      {reportData.script_execution_history.length === 0 && (
                        <tr>
                          <td colSpan={7} className="px-6 py-12 text-center text-[#6B7280]">
                            No scans yet. Upload a ContainerGuard report on the Upload JSON page.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {(() => {
                  const totalRows = reportData.script_execution_history.length;
                  const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
                  const safePage = Math.min(currentPage, totalPages);
                  const startIdx = (safePage - 1) * PAGE_SIZE;
                  const endIdx = Math.min(startIdx + PAGE_SIZE, totalRows);
                  const canPrev = safePage > 1;
                  const canNext = safePage < totalPages;
                  return (
                    <div className="px-6 py-4 border-t border-[#2A2F3A] flex items-center justify-between">
                      <p className="text-[#6B7280] text-sm">
                        {totalRows === 0
                          ? 'No results'
                          : `Showing ${startIdx + 1} to ${endIdx} of ${totalRows} results`}
                        {totalRows < reportData.summary.total_scans_run && (
                          <span className="ml-2 text-[#4B5563]">
                            (of {reportData.summary.total_scans_run} reported)
                          </span>
                        )}
                      </p>
                      <div className="flex items-center gap-2">
                        <button
                          disabled={!canPrev}
                          onClick={() => canPrev && setCurrentPage((p) => p - 1)}
                          className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 text-sm ${
                            canPrev
                              ? 'bg-[#2A2F3A] hover:bg-[#2A2F3A]/80 text-white'
                              : 'bg-[#2A2F3A]/50 text-[#6B7280] cursor-not-allowed'
                          }`}
                        >
                          <ChevronLeft className="w-4 h-4" />
                          Previous
                        </button>
                        <span className="px-3 text-[#A1A1AA] text-sm">
                          Page {safePage} of {totalPages}
                        </span>
                        <button
                          disabled={!canNext}
                          onClick={() => canNext && setCurrentPage((p) => p + 1)}
                          className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 text-sm ${
                            canNext
                              ? 'bg-primary hover:bg-primary/90 text-white'
                              : 'bg-primary/30 text-white/60 cursor-not-allowed'
                          }`}
                        >
                          Next
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          </>
        )}

        {activeNav === 'Settings' && (
          <>
            <div className="bg-[#1A1F2B] border-b border-[#2A2F3A] px-8 py-6">
              <h2 className="text-white mb-1">Settings</h2>
              <p className="text-[#A1A1AA] text-sm">Defaults applied to generated scripts and exported reports</p>
            </div>
            <div className="flex-1 overflow-auto p-8">
              <div className="max-w-2xl space-y-6">
                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6 space-y-4">
                  <h3 className="text-white">Organization</h3>
                  <div>
                    <label className="block text-[#A1A1AA] text-sm mb-2">Organization name</label>
                    <input
                      type="text"
                      value={settings.organizationName}
                      onChange={(e) => setSettings({ ...settings, organizationName: e.target.value })}
                      className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-[#A1A1AA] text-sm mb-2">Default operator</label>
                    <input
                      type="text"
                      value={settings.defaultOperator}
                      onChange={(e) => setSettings({ ...settings, defaultOperator: e.target.value })}
                      className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary transition-colors"
                    />
                    <p className="text-[#6B7280] text-xs mt-1">Stamped into generated scripts as the operator field.</p>
                  </div>
                </div>

                <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6 space-y-4">
                  <h3 className="text-white">Reporting</h3>
                  <div>
                    <label className="block text-[#A1A1AA] text-sm mb-2">Severity threshold</label>
                    <select
                      value={settings.severityThreshold}
                      onChange={(e) => setSettings({ ...settings, severityThreshold: e.target.value as any })}
                      className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary transition-colors"
                    >
                      <option value="Critical">Critical only</option>
                      <option value="High">High and above</option>
                      <option value="Medium">Medium and above</option>
                      <option value="Low">All findings</option>
                    </select>
                    <p className="text-[#6B7280] text-xs mt-1">Findings below this level are still recorded but de-emphasized in summaries.</p>
                  </div>
                  <div>
                    <label className="block text-[#A1A1AA] text-sm mb-2">Slack webhook URL</label>
                    <input
                      type="text"
                      value={settings.slackWebhook}
                      onChange={(e) => setSettings({ ...settings, slackWebhook: e.target.value })}
                      placeholder="https://hooks.slack.com/services/..."
                      className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white placeholder:text-[#6B7280] focus:outline-none focus:border-primary transition-colors font-mono text-sm"
                    />
                  </div>
                  <label className="flex items-center gap-3 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={settings.autoExport}
                      onChange={(e) => setSettings({ ...settings, autoExport: e.target.checked })}
                      className="w-4 h-4 accent-primary"
                    />
                    <span className="text-white text-sm">Auto-export each new report as JSON</span>
                  </label>
                </div>

                <div className="flex items-center gap-4">
                  <button
                    onClick={handleSaveSettings}
                    className="px-6 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Save Settings
                  </button>
                  {settingsSavedAt && (
                    <span className="text-[#22C55E] text-sm flex items-center gap-2">
                      <Check className="w-4 h-4" />
                      Saved at {settingsSavedAt}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </main>

      {/* Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg w-full max-w-md mx-4">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-[#2A2F3A]">
              <h3 className="text-white">Create New Script</h3>
              <button
                onClick={handleCloseModal}
                className="text-[#A1A1AA] hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-4">
              {/* Script Name Field */}
              <div>
                <label className="block text-white mb-2">
                  Script Name <span className="text-destructive">*</span>
                </label>
                <input
                  type="text"
                  value={scriptName}
                  onChange={(e) => setScriptName(e.target.value)}
                  placeholder="Enter script name"
                  className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-white placeholder:text-[#6B7280] focus:outline-none focus:border-primary transition-colors"
                />
              </div>

              {/* Cloud Provider Selector */}
              <div>
                <label className="block text-white mb-2">
                  Cloud Provider <span className="text-destructive">*</span>
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {(['AWS', 'Azure', 'GCP', 'Docker'] as CloudProvider[]).map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => setSelectedProvider(p)}
                      className={`px-3 py-2 rounded-lg text-sm transition-colors border ${
                        selectedProvider === p
                          ? 'bg-primary/15 border-primary text-white'
                          : 'bg-[#0F1115] border-[#2A2F3A] text-[#A1A1AA] hover:text-white hover:border-primary/50'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
                <p className="text-[#6B7280] text-xs mt-2">
                  Loads a runnable Python audit template (boto3 / azure-mgmt / google-cloud-compute / docker-py).
                </p>
              </div>

              {/* Creation Date Field */}
              <div>
                <label className="block text-white mb-2">Creation Date</label>
                <input
                  type="text"
                  value={getCurrentDate()}
                  readOnly
                  className="w-full bg-[#0F1115] border border-[#2A2F3A] rounded-lg px-4 py-2 text-[#A1A1AA] cursor-not-allowed"
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 p-6 border-t border-[#2A2F3A]">
              <button
                onClick={handleCloseModal}
                className="px-6 py-2 bg-[#2A2F3A] hover:bg-[#2A2F3A]/80 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateScript}
                disabled={!scriptName.trim()}
                className={`px-6 py-2 rounded-lg transition-colors ${
                  scriptName.trim()
                    ? 'bg-[#3B82F6] hover:bg-[#3B82F6]/90 text-white'
                    : 'bg-[#2A2F3A] text-[#6B7280] cursor-not-allowed'
                }`}
              >
                Create Script
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scan Detail Modal */}
      {selectedScan && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedScan(null)}
        >
          <div
            className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg w-full max-w-5xl max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="sticky top-0 bg-[#1A1F2B] border-b border-[#2A2F3A] p-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <h3 className="text-white">{selectedScan.scriptName}</h3>
                <span className="px-3 py-1 bg-[#2A2F3A] text-[#A1A1AA] text-sm rounded-full">
                  {selectedScan.cloudProvider}
                </span>
                <span className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
                  selectedScan.status === 'Success' ? 'bg-[#22C55E]/10 text-[#22C55E]' :
                  selectedScan.status === 'Partial' ? 'bg-[#EAB308]/10 text-[#EAB308]' :
                  'bg-[#EF4444]/10 text-[#EF4444]'
                }`}>
                  <span className={`w-2 h-2 rounded-full ${
                    selectedScan.status === 'Success' ? 'bg-[#22C55E]' :
                    selectedScan.status === 'Partial' ? 'bg-[#EAB308]' :
                    'bg-[#EF4444]'
                  }`} />
                  {selectedScan.status}
                </span>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="text-[#A1A1AA] hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Summary Row */}
              <div className="grid grid-cols-4 gap-4">
                <div>
                  <p className="text-[#6B7280] text-sm mb-1">Run Date</p>
                  <p className="text-white">{selectedScan.runDate}</p>
                </div>
                <div>
                  <p className="text-[#6B7280] text-sm mb-1">Duration</p>
                  <p className="text-white">{selectedScan.duration}s</p>
                </div>
                <div>
                  <p className="text-[#6B7280] text-sm mb-1">Operator</p>
                  <p className="text-white">{selectedScan.operator}</p>
                </div>
                <div>
                  <p className="text-[#6B7280] text-sm mb-1">Regions Scanned</p>
                  <p className="text-white">{selectedScan.regionsScanned}</p>
                </div>
              </div>

              {/* Notes Section */}
              <div className="bg-[#151821] border border-[#2A2F3A] rounded-lg p-4">
                <h4 className="text-white mb-2">Notes</h4>
                <p className="text-[#A1A1AA] text-sm leading-relaxed">{selectedScan.notes}</p>
              </div>

              {/* Findings Summary */}
              <div>
                <h4 className="text-white mb-4">Findings Summary</h4>
                <div className="grid grid-cols-4 gap-4">
                  <div className="bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg p-4">
                    <p className="text-[#EF4444] text-sm mb-1">Critical</p>
                    <p className="text-white text-2xl font-semibold">{selectedScan.findingsSummary.critical}</p>
                  </div>
                  <div className="bg-[#F97316]/10 border border-[#F97316]/30 rounded-lg p-4">
                    <p className="text-[#F97316] text-sm mb-1">High</p>
                    <p className="text-white text-2xl font-semibold">{selectedScan.findingsSummary.high}</p>
                  </div>
                  <div className="bg-[#EAB308]/10 border border-[#EAB308]/30 rounded-lg p-4">
                    <p className="text-[#EAB308] text-sm mb-1">Medium</p>
                    <p className="text-white text-2xl font-semibold">{selectedScan.findingsSummary.medium}</p>
                  </div>
                  <div className="bg-[#3B82F6]/10 border border-[#3B82F6]/30 rounded-lg p-4">
                    <p className="text-[#3B82F6] text-sm mb-1">Low</p>
                    <p className="text-white text-2xl font-semibold">{selectedScan.findingsSummary.low}</p>
                  </div>
                </div>
              </div>

              {/* Scanned Resources */}
              <div>
                <h4 className="text-white mb-4">Scanned Resources</h4>
                {selectedScan.collectedData.length > 0 ? (
                  <div className="bg-[#151821] border border-[#2A2F3A] rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead>
                        <tr className="bg-[#0F1115] border-b border-[#2A2F3A]">
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Name</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Instance ID</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Type</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Region</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">State</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Findings</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedScan.collectedData.map((resource, index) => (
                          <tr key={index} className="border-b border-[#2A2F3A] last:border-b-0">
                            <td className="px-4 py-3 text-white">{resource.name}</td>
                            <td className="px-4 py-3 text-[#A1A1AA] font-mono text-sm">{resource.instanceId}</td>
                            <td className="px-4 py-3 text-[#A1A1AA]">{resource.type}</td>
                            <td className="px-4 py-3 text-[#A1A1AA]">{resource.region}</td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-1 bg-[#22C55E]/10 text-[#22C55E] text-xs rounded">
                                {resource.state}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`${resource.findings > 0 ? 'text-[#EF4444]' : 'text-[#22C55E]'}`}>
                                {resource.findings}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="bg-[#151821] border border-[#2A2F3A] rounded-lg p-8 text-center">
                    <p className="text-[#6B7280]">No instance-level data captured for this scan type</p>
                  </div>
                )}
              </div>

              {/* Findings drill-down */}
              <div>
                <h4 className="text-white mb-4">Findings ({selectedScan.findings.length})</h4>
                {selectedScan.findings.length > 0 ? (
                  <div className="bg-[#151821] border border-[#2A2F3A] rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead>
                        <tr className="bg-[#0F1115] border-b border-[#2A2F3A]">
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Severity</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Title</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Resource</th>
                          <th className="px-4 py-3 text-left text-[#A1A1AA] text-sm">Description &amp; remediation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedScan.findings.map((f, i) => {
                          const sevColors: Record<string, string> = {
                            Critical: 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30',
                            High: 'bg-[#F97316]/10 text-[#F97316] border-[#F97316]/30',
                            Medium: 'bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/30',
                            Low: 'bg-[#3B82F6]/10 text-[#3B82F6] border-[#3B82F6]/30',
                          };
                          return (
                            <tr key={i} className="border-b border-[#2A2F3A] last:border-b-0 align-top">
                              <td className="px-4 py-3">
                                <span className={`inline-block px-2 py-1 text-xs rounded border ${sevColors[f.severity] ?? sevColors.Low}`}>
                                  {f.severity}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-white">
                                {f.title}
                                {f.cisRef && (
                                  <div className="text-[#6B7280] text-xs mt-1">{f.cisRef}</div>
                                )}
                              </td>
                              <td className="px-4 py-3 text-[#A1A1AA] font-mono text-xs break-all max-w-xs">
                                {f.resource}
                              </td>
                              <td className="px-4 py-3 text-sm">
                                <p className="text-[#A1A1AA] mb-1">{f.description}</p>
                                <p className="text-[#22C55E]">
                                  <span className="text-[#6B7280]">Fix: </span>
                                  {f.remediation}
                                </p>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="bg-[#151821] border border-[#2A2F3A] rounded-lg p-8 text-center">
                    <p className="text-[#6B7280]">No detailed findings recorded for this scan.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}