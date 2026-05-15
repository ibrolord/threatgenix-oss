import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

// ── FAQ data ────────────────────────────────────────────────────────────────

const FAQS = [
  {
    q: "What is ThreatGenix?",
    a: "ThreatGenix is an AI-assisted product security workspace for engineering and security teams. You model the system as a DFD, ground the review with architecture and validation evidence, prioritize STRIDE findings, and export stakeholder-ready security review output.",
  },
  {
    q: "What file formats can I upload?",
    a: "Architecture document upload currently accepts PDF files. Validation Lab evidence can also be imported from supported security tool output such as Semgrep, Trivy, Checkov, OSV Scanner, Nuclei, TruffleHog, external security reviews, and pentest notes.",
  },
  {
    q: "Do I need AWS credentials to use ThreatGenix?",
    a: "AI-assisted extraction and review actions require a configured provider. Settings shows provider health, residency mode, and tenant-level external-provider opt-in. Deterministic validation imports and self-hosted scanner runs remain gated by execution policy and do not require outbound AI inference.",
  },
  {
    q: "What does STRIDE stand for?",
    a: "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. These are the six threat categories ThreatGenix analyzes against your DFD.",
  },
  {
    q: "What is a Data Flow Diagram (DFD)?",
    a: "A DFD maps your system's components (processes, data stores, external entities) and the data flows between them, plus trust boundaries. ThreatGenix auto-generates a DFD from your uploaded document and lets you refine it before analysis.",
  },
  {
    q: "Can I edit the DFD after it's generated?",
    a: "Yes. Use the DFD canvas to drag nodes, add/delete nodes and edges, draw trust boundaries, and rename any element. Save your changes before running analysis so threats reflect your latest diagram.",
  },
  {
    q: "What is threat triage?",
    a: "Triage lets you decide whether a finding is active, accepted, dismissed, or remediated. Validation evidence and DFD node binding help the review distinguish proved issues from contextual risks and evidence gaps.",
  },
  {
    q: "What compliance framework does ThreatGenix map to?",
    a: "Threats and review findings can carry NIST, OSFI B-13, PCI DSS, PIPEDA, FINTRAC, and ISO 27001 context depending on the model scope. The Security Review report separates validated evidence from contextual gaps.",
  },
  {
    q: "How do I export a report?",
    a: "Use Security Review > Report for the stakeholder readout, or click \"Generate Threat Model Document\" on the model page when DFD quality gates allow export. The output includes model metadata, prioritized findings, evidence posture, attack paths, and triage state.",
  },
  {
    q: "Can I create multiple security reviews?",
    a: "Yes. Each security review is independent with its own evidence, DFD, findings, decisions, and report. Use Dashboard to review active work and Start Review to create one.",
  },
  {
    q: "Why does evidence sometimes show as unbound?",
    a: "Imported or scanner evidence is stored even when it cannot be matched to a DFD node. Bind evidence to the relevant DFD component in Validation Lab when you want semantic review status to move from global context into node-backed validation.",
  },
];

// ── How-to steps ─────────────────────────────────────────────────────────────

const HOW_TOS = [
  {
    id: "create",
    title: "1. Start a Security Review",
    steps: [
      "Open Start Review from the top navigation, then click Start New Review.",
      "Enter an Application or PR Name (e.g., \"Payments API\").",
      "Choose the review goal and add a short review summary.",
      "Select the Data Classification: Public, Internal, Confidential, or Restricted.",
      "Click Start Security Review. You'll be taken directly to the review workspace.",
    ],
    screenshot: <CreateScreenshot />,
  },
  {
    id: "upload",
    title: "2. Ground the Model With Evidence",
    steps: [
      "Open Upload and Environment Setup on the threat model page.",
      "Attach architecture PDFs, repository context, IaC, cloud, or runtime evidence when available.",
      "Use imported evidence to populate or refine the DFD, then review the generated components and flows.",
      "If extraction is unavailable or sparse, keep the model moving by adding DFD nodes and flows manually.",
    ],
    screenshot: <UploadScreenshot />,
  },
  {
    id: "dfd",
    title: "3. Edit the DFD Canvas",
    steps: [
      "The DFD canvas shows nodes (processes, data stores, external entities) and edges (data flows).",
      "Drag any node to reposition it.",
      "Click Add Node in the toolbar to add a new node — choose its type and label.",
      "Connect two nodes by hovering a node until the handle appears, then dragging to another node.",
      "Click a node and press Delete (or use Remove Node) to delete it.",
      "Draw a Trust Boundary by clicking Draw Boundary in the toolbar, then drawing a rectangle around the nodes it should enclose.",
      "Click Save DFD to persist your changes before running analysis.",
    ],
    screenshot: <DFDScreenshot />,
  },
  {
    id: "threats",
    title: "4. Generate & Analyze Threats",
    steps: [
      "After saving your DFD, move to Review Findings.",
      "Use Generate Threats to run deterministic STRIDE analysis against the current DFD.",
      "Review findings by priority, STRIDE category, owner, status, and evidence state.",
      "Use quick triage or the finding detail view to assign remediation, gather evidence, verify controls, or accept risk.",
      "Open Security Review for the dedicated queue, compliance, model health, and report views.",
    ],
    screenshot: <ThreatsScreenshot />,
  },
  {
    id: "triage",
    title: "5. Triage Threats",
    steps: [
      "Click any row in the threat table to open the finding detail or quick triage workflow.",
      "Review the description, priority, category, evidence state, attack-path context, and mapped controls.",
      "Use remediation, verification, evidence, and acceptance actions to move the finding toward a defensible decision.",
      "Dismiss findings only when the reason is explicit enough for reviewers and auditors to understand.",
      "Triage decisions are reflected in Security Review and exported reporting.",
    ],
    screenshot: <TriageScreenshot />,
  },
  {
    id: "report",
    title: "6. Review Evidence and Validation",
    steps: [
      "Open Validation Lab from the model page or Security Review context.",
      "Confirm runner mode, ready tools, evidence count, and semantic binding state in the command strip.",
      "Run or import supported tool evidence only against approved paths and with the required authorization acknowledgement.",
      "Bind global evidence to DFD nodes when the finding belongs to a specific component or flow.",
      "Use unbound evidence as review context, not as proof that a specific DFD component is validated.",
    ],
    screenshot: <ValidationLabScreenshot />,
  },
  {
    id: "report-export",
    title: "7. Export Stakeholder Output",
    steps: [
      "Open Security Review, then use the Report tab for the full stakeholder readout.",
      "Confirm top risks, evidence confidence, blind spots, attack paths, deltas, and accepted risk.",
      "Use Generate Threat Model Document on the model page when quality gates permit formal export.",
      "Share only reports whose evidence labels match what the product actually proved.",
    ],
    screenshot: <ReportScreenshot />,
  },
];

// ── Inline SVG screenshots ───────────────────────────────────────────────────

function CreateScreenshot() {
  return (
    <svg viewBox="0 0 480 220" className="help-screenshot" aria-label="Start security review form">
      {/* card */}
      <rect x="8" y="8" width="464" height="204" rx="6" fill="#fff" stroke="#e2e8f0" />
      {/* header bar */}
      <rect x="8" y="8" width="464" height="36" rx="6" fill="#f8fafc" />
      <rect x="8" y="32" width="464" height="12" fill="#f8fafc" />
      <text x="20" y="30" fontSize="13" fontWeight="700" fill="#1e293b">Start Security Review</text>
      {/* field 1 */}
      <text x="20" y="66" fontSize="11" fontWeight="600" fill="#475569">Application or PR Name</text>
      <rect x="20" y="72" width="300" height="28" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="30" y="90" fontSize="12" fill="#94a3b8">e.g. Payments API</text>
      {/* field 2 */}
      <text x="20" y="118" fontSize="11" fontWeight="600" fill="#475569">Review Summary</text>
      <rect x="20" y="124" width="440" height="36" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="30" y="145" fontSize="12" fill="#94a3b8">Brief description of the system…</text>
      {/* field 3 */}
      <text x="20" y="178" fontSize="11" fontWeight="600" fill="#475569">Data Classification</text>
      <rect x="20" y="184" width="180" height="28" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="30" y="202" fontSize="12" fill="#1a1a1a">Confidential</text>
      <text x="188" y="202" fontSize="10" fill="#64748b">▼</text>
      {/* submit */}
      <rect x="340" y="184" width="120" height="28" rx="4" fill="#16a34a" />
      <text x="400" y="202" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Start</text>
    </svg>
  );
}

function UploadScreenshot() {
  return (
    <svg viewBox="0 0 480 200" className="help-screenshot" aria-label="Document upload panel">
      <rect x="8" y="8" width="464" height="184" rx="6" fill="#fff" stroke="#e2e8f0" />
      <text x="20" y="36" fontSize="14" fontWeight="700" fill="#1e293b">Upload Architecture Document</text>
      {/* drop zone */}
      <rect x="20" y="48" width="440" height="80" rx="6" fill="#f8fafc" stroke="#cbd5e1" strokeDasharray="6 3" />
      <text x="240" y="84" fontSize="22" fill="#94a3b8" textAnchor="middle">📄</text>
      <text x="240" y="106" fontSize="12" fill="#64748b" textAnchor="middle">Drop a PDF here or</text>
      <rect x="310" y="112" width="90" height="24" rx="4" fill="#2563eb" />
      <text x="355" y="128" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Choose File</text>
      {/* status */}
      <rect x="20" y="144" width="440" height="36" rx="4" fill="#f0fdf4" stroke="#86efac" />
      <text x="36" y="165" fontSize="12" fill="#16a34a">✓  architecture-doc.pdf uploaded — DFD generated (8 nodes, 11 flows)</text>
      {/* upload btn */}
      <rect x="340" y="156" width="110" height="28" rx="4" fill="#9ca3af" />
      <text x="395" y="174" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Upload</text>
    </svg>
  );
}

function DFDScreenshot() {
  return (
    <svg viewBox="0 0 480 260" className="help-screenshot" aria-label="DFD canvas with nodes and edges">
      {/* toolbar */}
      <rect x="8" y="8" width="464" height="36" rx="6" fill="#f8fafc" stroke="#e2e8f0" />
      <rect x="16" y="16" width="70" height="20" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="51" y="29" fontSize="11" fontWeight="600" fill="#334155" textAnchor="middle">Add Node</text>
      <rect x="94" y="16" width="90" height="20" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="139" y="29" fontSize="11" fontWeight="600" fill="#334155" textAnchor="middle">Draw Boundary</text>
      <rect x="380" y="16" width="84" height="20" rx="4" fill="#2563eb" stroke="#2563eb" />
      <text x="422" y="29" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Save DFD</text>
      {/* canvas */}
      <rect x="8" y="44" width="464" height="208" rx="0" fill="#fafafa" stroke="#e2e8f0" />
      {/* trust boundary */}
      <rect x="60" y="60" width="220" height="140" rx="8" fill="none" stroke="#f59e0b" strokeDasharray="8 4" strokeWidth="2" />
      <text x="68" y="76" fontSize="10" fill="#f59e0b" fontWeight="600">Trust Boundary: Internal</text>
      {/* external entity */}
      <rect x="20" y="130" width="90" height="36" rx="4" fill="#dbeafe" stroke="#93c5fd" />
      <text x="65" y="151" fontSize="11" fontWeight="600" fill="#1e40af" textAnchor="middle">Mobile Client</text>
      {/* process */}
      <ellipse cx="200" cy="148" rx="52" ry="26" fill="#f0fdf4" stroke="#86efac" />
      <text x="200" y="152" fontSize="11" fontWeight="600" fill="#166534" textAnchor="middle">API Gateway</text>
      {/* data store */}
      <rect x="340" y="130" width="90" height="36" rx="2" fill="#fef3c7" stroke="#fcd34d" />
      <rect x="340" y="130" width="90" height="8" rx="2" fill="#fcd34d" />
      <text x="385" y="152" fontSize="11" fontWeight="600" fill="#92400e" textAnchor="middle">User DB</text>
      {/* edges */}
      <line x1="110" y1="148" x2="148" y2="148" stroke="#94a3b8" strokeWidth="1.5" markerEnd="url(#arr)" />
      <line x1="252" y1="148" x2="340" y2="148" stroke="#94a3b8" strokeWidth="1.5" />
      <defs>
        <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#94a3b8" />
        </marker>
      </defs>
      <text x="129" y="142" fontSize="9" fill="#64748b">auth req</text>
      <text x="280" y="142" fontSize="9" fill="#64748b">query</text>
      {/* legend */}
      <rect x="16" y="216" width="10" height="10" rx="1" fill="#dbeafe" stroke="#93c5fd" />
      <text x="30" y="225" fontSize="9" fill="#475569">External Entity</text>
      <ellipse cx="108" cy="221" rx="10" ry="6" fill="#f0fdf4" stroke="#86efac" />
      <text x="122" y="225" fontSize="9" fill="#475569">Process</text>
      <rect x="190" y="216" width="10" height="10" rx="1" fill="#fef3c7" stroke="#fcd34d" />
      <text x="204" y="225" fontSize="9" fill="#475569">Data Store</text>
    </svg>
  );
}

function ThreatsScreenshot() {
  return (
    <svg viewBox="0 0 480 240" className="help-screenshot" aria-label="Threat table with STRIDE filter">
      {/* filter pills */}
      {[
        { label: "All", x: 16, active: true },
        { label: "Spoofing", x: 56 },
        { label: "Tampering", x: 122 },
        { label: "Repudiation", x: 198 },
        { label: "Info Disclosure", x: 284 },
        { label: "DoS", x: 384 },
      ].map(({ label, x, active }) => (
        <g key={label}>
          <rect x={x} y="8" width={label.length * 7 + 16} height="24" rx="12"
            fill={active ? "#1e293b" : "#fff"} stroke={active ? "#1e293b" : "#cbd5e1"} />
          <text x={x + (label.length * 7 + 16) / 2} y="24" fontSize="11" fontWeight="500"
            fill={active ? "#fff" : "#475569"} textAnchor="middle">{label}</text>
        </g>
      ))}
      {/* generate button */}
      <rect x="330" y="44" width="140" height="32" rx="4" fill="#7c3aed" />
      <text x="400" y="64" fontSize="12" fontWeight="600" fill="#fff" textAnchor="middle">Generate Threats</text>
      {/* table header */}
      <rect x="8" y="84" width="464" height="28" rx="0" fill="#f8fafc" stroke="#e2e8f0" />
      {["ID", "Category", "Description", "Severity", "Status"].map((h, i) => (
        <text key={h} x={[20, 72, 160, 340, 410][i]} y="102" fontSize="11" fontWeight="600" fill="#475569">{h}</text>
      ))}
      {/* rows */}
      {[
        { id: "T-001", cat: "Spoofing", catColor: "#1e40af", catBg: "#dbeafe", desc: "Identity spoofing at trust boundary…", sev: "High", sevColor: "#fff", sevBg: "#ea580c", status: "Open", stColor: "#92400e", stBg: "#fef3c7" },
        { id: "T-002", cat: "Tampering", catColor: "#9a3412", catBg: "#ffedd5", desc: "Unvalidated data store write…", sev: "Critical", sevColor: "#fff", sevBg: "#dc2626", status: "Accepted", stColor: "#166534", stBg: "#dcfce7" },
        { id: "T-003", cat: "Info Disc.", catColor: "#991b1b", catBg: "#fee2e2", desc: "Sensitive data exposed in response…", sev: "Medium", sevColor: "#78350f", sevBg: "#fbbf24", status: "Dismissed", stColor: "#4b5563", stBg: "#e5e7eb" },
        { id: "T-004", cat: "DoS", catColor: "#92400e", catBg: "#fef3c7", desc: "Unauthenticated endpoint flooding…", sev: "High", sevColor: "#fff", sevBg: "#ea580c", status: "Open", stColor: "#92400e", stBg: "#fef3c7" },
      ].map(({ id, cat, catColor, catBg, desc, sev, sevColor, sevBg, status, stColor, stBg }, i) => (
        <g key={id}>
          <rect x="8" y={112 + i * 30} width="464" height="30" fill={i % 2 === 0 ? "#fff" : "#f8fafc"} stroke="#e2e8f0" />
          <text x="20" y={131 + i * 30} fontSize="11" fill="#334155">{id}</text>
          <rect x="66" y={118 + i * 30} width={cat.length * 7 + 12} height="16" rx="8" fill={catBg} />
          <text x={66 + (cat.length * 7 + 12) / 2} y={130 + i * 30} fontSize="10" fontWeight="600" fill={catColor} textAnchor="middle">{cat}</text>
          <text x="155" y={131 + i * 30} fontSize="11" fill="#334155">{desc}</text>
          <rect x="330" y={118 + i * 30} width={sev.length * 7 + 12} height="16" rx="8" fill={sevBg} />
          <text x={336 + (sev.length * 7 + 12) / 2} y={130 + i * 30} fontSize="10" fontWeight="600" fill={sevColor} textAnchor="middle">{sev}</text>
          <rect x="402" y={118 + i * 30} width={status.length * 7 + 12} height="16" rx="8" fill={stBg} />
          <text x={408 + (status.length * 7 + 12) / 2} y={130 + i * 30} fontSize="10" fontWeight="600" fill={stColor} textAnchor="middle">{status}</text>
        </g>
      ))}
    </svg>
  );
}

function ValidationLabScreenshot() {
  return (
    <svg viewBox="0 0 480 220" className="help-screenshot" aria-label="Validation Lab evidence workspace">
      <rect x="8" y="8" width="464" height="204" rx="6" fill="#fff" stroke="#e2e8f0" />
      <text x="20" y="34" fontSize="14" fontWeight="700" fill="#1e293b">Validation Lab</text>
      <rect x="20" y="48" width="440" height="42" rx="6" fill="#f8fafc" stroke="#e2e8f0" />
      {[
        ["Runner", "self-hosted", 32],
        ["Tools", "6/6 ready", 132],
        ["Evidence", "node-bound", 232],
        ["Binding", "semantic", 342],
      ].map(([label, value, x]) => (
        <g key={label}>
          <text x={Number(x)} y="66" fontSize="9" fontWeight="600" fill="#64748b" textAnchor="middle">{label}</text>
          <text x={Number(x)} y="82" fontSize="11" fontWeight="700" fill="#0f172a" textAnchor="middle">{value}</text>
        </g>
      ))}
      <rect x="20" y="104" width="210" height="84" rx="6" fill="#f0f9ff" stroke="#bae6fd" />
      <text x="34" y="128" fontSize="12" fontWeight="700" fill="#075985">Tool Readiness</text>
      <text x="34" y="148" fontSize="10" fill="#0f172a">Nuclei · Semgrep · OSV</text>
      <text x="34" y="164" fontSize="10" fill="#0f172a">Trivy · Checkov · TruffleHog</text>
      <rect x="34" y="172" width="92" height="20" rx="4" fill="#0369a1" />
      <text x="80" y="186" fontSize="10" fontWeight="700" fill="#fff" textAnchor="middle">Run approved</text>
      <rect x="250" y="104" width="210" height="84" rx="6" fill="#fefce8" stroke="#fde68a" />
      <text x="264" y="128" fontSize="12" fontWeight="700" fill="#854d0e">Evidence Binding</text>
      <text x="264" y="148" fontSize="10" fill="#0f172a">Bind findings to DFD nodes</text>
      <text x="264" y="164" fontSize="10" fill="#0f172a">to move semantic status.</text>
      <rect x="264" y="172" width="82" height="20" rx="4" fill="#a16207" />
      <text x="305" y="186" fontSize="10" fontWeight="700" fill="#fff" textAnchor="middle">Review DFD</text>
    </svg>
  );
}

function TriageScreenshot() {
  return (
    <svg viewBox="0 0 480 300" className="help-screenshot" aria-label="Threat triage modal">
      {/* overlay hint */}
      <rect x="0" y="0" width="480" height="300" fill="#f1f5f9" rx="6" />
      <text x="240" y="20" fontSize="10" fill="#94a3b8" textAnchor="middle">Click any threat row to open triage</text>
      {/* modal */}
      <rect x="40" y="28" width="400" height="256" rx="8" fill="#fff" stroke="#e2e8f0"
        style={{ filter: "drop-shadow(0 8px 24px rgba(0,0,0,0.15))" }} />
      {/* header */}
      <rect x="40" y="28" width="400" height="48" rx="8" fill="#f8fafc" />
      <rect x="40" y="60" width="400" height="16" fill="#f8fafc" />
      <text x="56" y="58" fontSize="14" fontWeight="700" fill="#1e293b">T-001 — Identity Spoofing</text>
      <text x="424" y="58" fontSize="18" fill="#64748b">×</text>
      {/* body */}
      <text x="56" y="92" fontSize="11" fill="#334155">An attacker may impersonate a trusted service by forging credentials</text>
      <text x="56" y="107" fontSize="11" fill="#334155">at the API Gateway trust boundary, bypassing authentication checks.</text>
      {/* badges */}
      <rect x="56" y="118" width="64" height="18" rx="9" fill="#dbeafe" />
      <text x="88" y="130" fontSize="10" fontWeight="600" fill="#1e40af" textAnchor="middle">Spoofing</text>
      <rect x="128" y="118" width="52" height="18" rx="9" fill="#fff0f0" stroke="#ea580c" />
      <text x="154" y="130" fontSize="10" fontWeight="600" fill="#ea580c" textAnchor="middle">High</text>
      <rect x="188" y="118" width="42" height="18" rx="9" fill="#fef3c7" />
      <text x="209" y="130" fontSize="10" fontWeight="600" fill="#92400e" textAnchor="middle">Open</text>
      {/* nist section */}
      <text x="56" y="152" fontSize="11" fontWeight="600" fill="#475569">NIST 800-53 Controls</text>
      <text x="56" y="168" fontSize="11" fill="#334155">• IA-2 — Identification and Authentication (Org. Users)</text>
      <text x="56" y="183" fontSize="11" fill="#334155">• IA-8 — Identification and Authentication (Non-Org. Users)</text>
      {/* dismiss input */}
      <text x="56" y="204" fontSize="11" fontWeight="600" fill="#475569">Dismiss reason (required to dismiss)</text>
      <rect x="56" y="210" width="368" height="26" rx="4" fill="#fff" stroke="#cbd5e1" />
      <text x="66" y="227" fontSize="11" fill="#94a3b8">e.g. Mitigated by mTLS at gateway…</text>
      {/* actions */}
      <rect x="40" y="252" width="400" height="32" rx="8" fill="#f8fafc" />
      <rect x="40" y="252" width="400" height="14" fill="#f8fafc" />
      <rect x="56" y="256" width="90" height="24" rx="4" fill="#16a34a" />
      <text x="101" y="272" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Accept</text>
      <rect x="154" y="256" width="90" height="24" rx="4" fill="#64748b" />
      <text x="199" y="272" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Dismiss</text>
      <rect x="252" y="256" width="90" height="24" rx="4" fill="#e2e8f0" />
      <text x="297" y="272" fontSize="11" fontWeight="600" fill="#334155" textAnchor="middle">Cancel</text>
    </svg>
  );
}

function ReportScreenshot() {
  return (
    <svg viewBox="0 0 480 200" className="help-screenshot" aria-label="PDF report export">
      <rect x="8" y="8" width="464" height="184" rx="6" fill="#fff" stroke="#e2e8f0" />
      {/* report preview */}
      <rect x="24" y="24" width="200" height="160" rx="4" fill="#fff" stroke="#e2e8f0"
        style={{ filter: "drop-shadow(2px 2px 6px rgba(0,0,0,0.1))" }} />
      {/* report header */}
      <rect x="24" y="24" width="200" height="28" rx="4" fill="#1e293b" />
      <text x="124" y="42" fontSize="11" fontWeight="700" fill="#fff" textAnchor="middle">ThreatGenix Report</text>
      <text x="32" y="62" fontSize="9" fill="#475569">System: Payments API</text>
      <text x="32" y="74" fontSize="9" fill="#475569">Classification: Confidential</text>
      <text x="32" y="86" fontSize="9" fill="#475569">Generated: 2025-04-18</text>
      <line x1="32" y1="92" x2="212" y2="92" stroke="#e2e8f0" />
      <text x="32" y="104" fontSize="9" fontWeight="600" fill="#1e293b">Threat Summary</text>
      {[["Critical", 2, "#dc2626"], ["High", 5, "#ea580c"], ["Medium", 4, "#fbbf24"], ["Low", 1, "#22c55e"]].map(([label, count, color], i) => (
        <g key={String(label)}>
          <rect x="32" y={110 + i * 14} width={Number(count) * 18} height="10" rx="2" fill={String(color)} />
          <text x={32 + Number(count) * 18 + 6} y={119 + i * 14} fontSize="8" fill="#475569">{label} ({count})</text>
        </g>
      ))}
      {/* export btn area */}
      <text x="270" y="60" fontSize="12" fontWeight="700" fill="#1e293b">Generate Threat Model</text>
      <text x="270" y="74" fontSize="12" fontWeight="700" fill="#1e293b">Document</text>
      <text x="270" y="94" fontSize="11" fill="#64748b">Download a complete threat model</text>
      <text x="270" y="108" fontSize="11" fill="#64748b">report with NIST mappings and</text>
      <text x="270" y="122" fontSize="11" fill="#64748b">triage decisions.</text>
      <rect x="270" y="136" width="172" height="32" rx="4" fill="#1e293b" />
      <text x="356" y="156" fontSize="11" fontWeight="600" fill="#fff" textAnchor="middle">Generate Document</text>
    </svg>
  );
}

// ── FAQ accordion item ────────────────────────────────────────────────────────

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`help-faq-item${open ? " help-faq-item-open" : ""}`}>
      <button className="help-faq-q" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span>{q}</span>
        <span className="help-faq-icon">{open ? "−" : "+"}</span>
      </button>
      {open && <p className="help-faq-a">{a}</p>}
    </div>
  );
}

// ── How-to section ────────────────────────────────────────────────────────────

function HowToSection({
  title,
  steps,
  screenshot,
}: {
  title: string;
  steps: string[];
  screenshot: ReactNode;
}) {
  return (
    <div className="help-howto">
      <h3 className="help-howto-title">{title}</h3>
      <div className="help-howto-body">
        <ol className="help-howto-steps">
          {steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
        <div className="help-howto-screenshot">{screenshot}</div>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function HelpPage() {
  const [activeSection, setActiveSection] = useState<"howto" | "faq">("howto");

  return (
    <div className="help-page">
      {/* breadcrumb */}
      <div className="help-breadcrumb">
        <Link to="/">Home</Link>
        <span> / </span>
        <span>Help &amp; Documentation</span>
      </div>

      <h2 className="help-title">Help &amp; Documentation</h2>
      <p className="help-subtitle">
        Learn how to move from architecture model to evidence-backed security review.
      </p>

      {/* tab nav */}
      <div className="help-tabs">
        <button
          className={`help-tab${activeSection === "howto" ? " help-tab-active" : ""}`}
          onClick={() => setActiveSection("howto")}
        >
          How-to Guides
        </button>
        <button
          className={`help-tab${activeSection === "faq" ? " help-tab-active" : ""}`}
          onClick={() => setActiveSection("faq")}
        >
          FAQs
        </button>
      </div>

      {/* how-to guides */}
      {activeSection === "howto" && (
        <div className="help-section">
          <p className="help-section-intro">
            Follow these steps to go from a new review to a defensible product security readout.
          </p>
          {HOW_TOS.map((h) => (
            <HowToSection key={h.id} title={h.title} steps={h.steps} screenshot={h.screenshot} />
          ))}
        </div>
      )}

      {/* faq */}
      {activeSection === "faq" && (
        <div className="help-section">
          <p className="help-section-intro">Common questions about ThreatGenix.</p>
          <div className="help-faq-list">
            {FAQS.map((f) => (
              <FAQItem key={f.q} q={f.q} a={f.a} />
            ))}
          </div>
        </div>
      )}

      {/* footer cta */}
      <div className="help-cta">
        <p>Ready to start?</p>
        <Link to="/dashboard" className="btn-create">
          Go to Reviews
        </Link>
      </div>
    </div>
  );
}
