import { useState, useEffect } from 'react';
import { Plus, FileCode, Upload, FileText, Settings, Edit, Trash2, Download, Shield, X, Send, Copy, Check, FileBarChart, Server, Calendar, Eye, ChevronLeft, ChevronRight, CheckCircle, Loader2, UploadCloud, File, AlertTriangle } from 'lucide-react';
import VMShieldLogo from './components/VMShieldLogo';

interface UploadedJSON {
  id: string;
  fileName: string;
  uploadDate: string;
  fileSize: string;
  status: 'Scanned' | 'Processing' | 'Error';
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
}

interface Script {
  id: string;
  name: string;
  dateCreated: string;
  status: 'Ready' | 'Used' | 'In Progress';
}

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
  };
}

export default function App() {
  const [activeNav, setActiveNav] = useState('Dashboard');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [scriptName, setScriptName] = useState('');
  const [currentScript, setCurrentScript] = useState<{ name: string; date: string } | null>(null);
  const [scripts, setScripts] = useState<Script[]>([
    { id: '1', name: 'AWS EC2 Misconfig Audit', dateCreated: '2026-04-20', status: 'Ready' },
    { id: '2', name: 'Azure VM Hardening Check', dateCreated: '2026-04-18', status: 'Used' },
    { id: '3', name: 'GCP Instance Security Scanner', dateCreated: '2026-04-15', status: 'Ready' },
    { id: '4', name: 'Multi-Cloud Misconfig Sweep', dateCreated: '2026-04-12', status: 'In Progress' },
  ]);
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

  const validateReport = (obj: any): obj is RawReportData => {
    return (
      obj &&
      typeof obj === 'object' &&
      obj.summary &&
      typeof obj.summary.total_scans_run === 'number' &&
      Array.isArray(obj.script_execution_history)
    );
  };

  const handleFileUpload = (file: File) => {
    setUploadError(null);
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(String(e.target?.result ?? ''));
        if (!validateReport(parsed)) {
          setUploadError('Invalid format: missing summary or script_execution_history');
          return;
        }
        setReportData(parsed);
        setUploadedJSONs((prev) => [
          {
            id: Date.now().toString(),
            fileName: file.name,
            uploadDate: getCurrentDate(),
            fileSize: formatFileSize(file.size),
            status: 'Scanned',
          },
          ...prev,
        ]);
        setActiveNav('Reports');
      } catch (err) {
        setUploadError(`Failed to parse JSON: ${err instanceof Error ? err.message : 'unknown error'}`);
      }
    };
    reader.onerror = () => setUploadError('Could not read file');
    reader.readAsText(file);
  };

  const getCurrentDate = () => {
    const today = new Date();
    return today.toISOString().split('T')[0];
  };

  const handleCreateScript = () => {
    if (scriptName.trim()) {
      const newScript: Script = {
        id: Date.now().toString(),
        name: scriptName,
        dateCreated: getCurrentDate(),
        status: 'In Progress'
      };

      // Add new script to the top of the list
      setScripts([newScript, ...scripts]);

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

  const handleSendMessage = () => {
    if (chatInput.trim()) {
      setChatMessages([...chatMessages, { role: 'user', content: chatInput }]);
      setChatInput('');

      // Simulate AI response
      setTimeout(() => {
        setChatMessages(prev => [...prev, {
          role: 'assistant',
          content: "I'll help you with that modification. The updated script will include the requested changes."
        }]);
      }, 1000);
    }
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
    setScripts(scripts.map(script =>
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
            {scripts.map((script) => (
              <div
                key={script.id}
                className="bg-[#1A1F2B] border border-[#2A2F3A] rounded-lg p-6 hover:border-primary/50 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h4 className="text-white mb-2">{script.name}</h4>
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
                    <button className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors">
                      <Edit className="w-5 h-5" />
                    </button>
                    <button className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors">
                      <Download className="w-5 h-5" />
                    </button>
                    <button className="p-2 text-[#A1A1AA] hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors">
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
                <h3 className="text-white mb-4">Upload JSON File</h3>
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
                      <p className="text-white mb-2">Drag and drop your JSON file here</p>
                      <p className="text-[#6B7280] text-sm mb-4">or</p>
                      <span className="inline-block px-6 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors pointer-events-auto">
                        Browse Files
                      </span>
                    </div>
                    <p className="text-[#6B7280] text-xs">Supported format: .json (Max size: 10MB)</p>
                  </div>
                  <input
                    id="cg-json-upload"
                    type="file"
                    accept="application/json,.json"
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
                          <button className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors">
                            <Eye className="w-5 h-5" />
                          </button>
                          <button className="p-2 text-[#A1A1AA] hover:text-white hover:bg-[#2A2F3A] rounded-lg transition-colors">
                            <Download className="w-5 h-5" />
                          </button>
                          <button className="p-2 text-[#A1A1AA] hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors">
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
                <button className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2">
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
                      {reportData.script_execution_history.map((scan, idx) => {
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
                      })}
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
                <div className="px-6 py-4 border-t border-[#2A2F3A] flex items-center justify-between">
                  <p className="text-[#6B7280] text-sm">
                    Showing 1 to {reportData.script_execution_history.length} of {reportData.summary.total_scans_run} results
                  </p>
                  <div className="flex items-center gap-2">
                    <button className="px-4 py-2 bg-[#2A2F3A] hover:bg-[#2A2F3A]/80 text-white rounded-lg transition-colors flex items-center gap-2 text-sm">
                      <ChevronLeft className="w-4 h-4" />
                      Previous
                    </button>
                    <button className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2 text-sm">
                      Next
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {activeNav === 'Settings' && (
          <div className="flex-1 flex items-center justify-center">
            <p className="text-[#6B7280]">Settings page - Coming soon</p>
          </div>
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
            </div>
          </div>
        </div>
      )}
    </div>
  );
}