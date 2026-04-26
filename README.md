# ContainerGuard

**Unified Container & VM Security Misconfiguration Scanner**

ContainerGuard is a security tool that audits container hosts and cloud VMs
for common misconfigurations (privileged containers, exposed Docker sockets,
weak SSH config, security-group overexposure, missing disk encryption, etc.)
and surfaces findings in a single dashboard with per-scan detail views.

> Course project for **CS4390 / CS5390 Ethical Hacking** (Spring 2026, UTEP).
> Team **NetNeko.exe** — Eric Dominguez, Aichel Rivero, Samuel Ramirez,
> Gustavo Chavira.

---

## Architecture

```
+------------------+        JSON report        +-----------------------+
|  scripts/        |  ----------------------->  |  Dashboard (React)    |
|  scanner.py      |                            |  Vite + Tailwind v4   |
|  (Python tool)   |  <--- "Upload JSON" UI --- |  + shadcn/ui          |
+------------------+                            +-----------------------+
   ^                                                  |
   | runs local Docker / host checks                  | renders summary stats,
   | + simulated cloud audits                         | execution history,
   v                                                  | scan-detail modal
   target system                                      v
                                                  human reviewer
```

Two pieces:

1. **`scripts/scanner.py`** — a zero-dependency Python scanner that runs real
   checks against the local Docker daemon and host (SSH config, listening
   ports) and emits simulated cloud audits. Output is a single JSON document.
   See [`scripts/README.md`](./scripts/README.md) for usage and schema.

2. **Dashboard** (this Vite app) — five-page React UI: Dashboard, Script
   editor, Upload JSON, Reports, Settings. The **Upload JSON** page accepts
   the scanner's output and drives the **Reports** page, including summary
   stats, the script-execution-history table, and per-scan detail modals.

---

## Quick start

```bash
# 1. Install UI dependencies
npm install

# 2. Start the dev server (default: http://localhost:5173)
npm run dev

# 3. In another terminal, run the scanner and pipe its output to a file
python3 scripts/scanner.py -o report.json --pretty

# 4. Open the dashboard, go to "Upload JSON", drop in report.json.
```

The dashboard ships with realistic default data so you can demo it without
running the scanner first.

---

## Project layout

```
.
├── README.md                       # this file
├── package.json                    # UI deps (Vite + React + Tailwind v4)
├── vite.config.ts
├── index.html
├── scripts/
│   ├── scanner.py                  # Python scanner (tool code)
│   └── README.md                   # scanner usage + JSON schema
└── src/
    ├── main.tsx
    ├── styles/                     # Tailwind + theme
    └── app/
        ├── App.tsx                 # all five UI pages
        └── components/
            ├── VMShieldLogo.tsx
            └── ui/                 # shadcn/ui components
```

---

## What the dashboard does

| Page          | What it does                                                         |
|---------------|----------------------------------------------------------------------|
| Dashboard     | Lists previously generated audit scripts and lets you create new ones. |
| Script        | In-app editor for the generated Python script with an AI assistant pane. |
| Upload JSON   | Accepts a `report.json` from `scanner.py` (drag-drop or browse).      |
| Reports       | Summary cards + script-execution-history table driven by the JSON.    |
| Settings      | Placeholder.                                                          |

When you upload a JSON file:

- Validation: must have `summary.total_scans_run` (number) and
  `script_execution_history` (array). Invalid files surface an inline error.
- The Reports page repopulates: total scans, total VMs scanned, total
  findings, and one row per scan in the history table.
- Clicking **View** on a row opens a modal with run metadata, the operator's
  notes, severity-banded finding counts, and a per-resource table.

---