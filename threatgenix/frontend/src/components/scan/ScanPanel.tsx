import { useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../../api/client';
import {
  ScanJob,
  ScanExecutionArtifact,
  ScanFinding,
  ScanJobDetail,
  ScanThreatResult,
  ScanCreateRequest,
  ScanCredential,
  ValidationToolInventoryItem,
  ValidationTargetType,
  DFDNodeResponse,
  ValidationRunbookResponse,
} from '../../types/api';
import { CredentialManager } from './CredentialManager';

interface ScanPanelProps {
  threatModelId: string;
  onScanComplete?: () => void;
}

const AUTHORIZATION_TEXT =
  'I confirm that I am authorized to perform security testing on all targets listed ' +
  'in this scan. I understand that unauthorized scanning may violate computer crime laws. ' +
  'By proceeding, I accept full legal responsibility for ensuring proper authorization exists for each target.';

const STATUS_COLORS: Record<string, string> = {
  pending: '#f59e0b',
  running: '#3b82f6',
  completed: '#10b981',
  failed: '#ef4444',
  cancelled: '#6b7280',
};

const token = () => localStorage.getItem('tg_token') ?? '';

function validationToolLabel(name: string): string {
  if (name === 'osv-scanner') return 'OSV';
  if (name === 'ai-red-team') return 'AI Red Team';
  if (name === 'external-report') return 'External Tool Report';
  if (name === 'pentest-report') return 'Pentest Report';
  return name.charAt(0).toUpperCase() + name.slice(1);
}

const ALL_IMPORT_TARGET_TYPES: ValidationTargetType[] = [
  'url',
  'repository_path',
  'lockfile',
  'container_image',
  'iac_directory',
  'ai_system',
];

const IMPORT_ONLY_SOURCES = [
  {
    name: 'external-report',
    label: 'External Tool Report',
    supported_targets: ALL_IMPORT_TARGET_TYPES,
    proof_mode: 'externally supplied security evidence',
    safety_boundary: 'Parse-only import; ThreatGenix does not execute the external tool.',
  },
  {
    name: 'pentest-report',
    label: 'Pentest Report',
    supported_targets: ALL_IMPORT_TARGET_TYPES,
    proof_mode: 'human pentest evidence',
    safety_boundary: 'Parse-only import; human evidence remains reviewable and non-deterministic.',
  },
] as const;

function validationToolStatus(tool: ValidationToolInventoryItem): { label: string; color: string; background: string } {
  if (!tool.execution_enabled) {
    return { label: 'policy off', color: '#475569', background: '#e2e8f0' };
  }
  if (tool.active && tool.available && tool.execution_enabled) {
    return { label: 'active', color: '#047857', background: '#d1fae5' };
  }
  if (tool.active && !tool.available) {
    return { label: 'not installed', color: '#92400e', background: '#fef3c7' };
  }
  return { label: 'inactive', color: '#475569', background: '#e2e8f0' };
}

const ARTIFACT_STATUS_STYLES: Record<ScanExecutionArtifact['status'], { color: string; background: string }> = {
  completed: { color: '#047857', background: '#d1fae5' },
  failed: { color: '#b91c1c', background: '#fee2e2' },
  timed_out: { color: '#92400e', background: '#fef3c7' },
  blocked: { color: '#475569', background: '#e2e8f0' },
};

function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'not recorded';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function formatDuration(value: number | null | undefined): string {
  if (value === null || value === undefined) return 'not recorded';
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)} s`;
}

function formatBytes(value: number | null | undefined): string {
  if (!value) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTargetType(value: string | null | undefined): string {
  return value?.replace(/_/g, ' ') ?? 'target';
}

function compactCategory(value: string): string {
  return value.replace(/_/g, ' ');
}

function formatTargets(targets: Record<string, string> | null | undefined): string {
  if (!targets || Object.keys(targets).length === 0) return 'No targets recorded';
  return Object.entries(targets)
    .map(([nodeId, target]) => `${nodeId}: ${target}`)
    .join(', ');
}

function summarizeThreatResults(threatResults: ScanThreatResult[]): string {
  if (threatResults.length === 0) return 'No mapped threats yet';
  const counts = threatResults.reduce<Record<string, number>>((acc, result) => {
    acc[result.scan_status] = (acc[result.scan_status] ?? 0) + 1;
    return acc;
  }, {});
  return Object.entries(counts)
    .map(([status, count]) => `${count} ${status.replace(/_/g, ' ')}`)
    .join(' · ');
}

function confidenceStyle(label: string): { color: string; background: string } {
  if (label === 'validated') return { color: '#047857', background: '#d1fae5' };
  if (label === 'indicated') return { color: '#92400e', background: '#fef3c7' };
  return { color: '#475569', background: '#e2e8f0' };
}

function formatBinding(value: string | null | undefined): string {
  if (value === 'node_bound') return 'node bound';
  return value?.replace(/_/g, ' ') ?? 'none';
}

function artifactStatusStyle(status: ScanExecutionArtifact['status']): { color: string; background: string } {
  return ARTIFACT_STATUS_STYLES[status] ?? { color: '#374151', background: '#f3f4f6' };
}

interface EvidenceLedgerProps {
  job: ScanJob;
  detail?: ScanJobDetail;
  runbook?: ValidationRunbookResponse | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

function EvidenceBadge({ children }: { children: string }) {
  return (
    <span style={{ fontSize: '11px', color: '#334155', background: '#e2e8f0', borderRadius: '999px', padding: '3px 7px', fontWeight: 700 }}>
      {children}
    </span>
  );
}

function ScanArtifactRow({ artifact }: { artifact: ScanExecutionArtifact }) {
  const statusStyle = artifactStatusStyle(artifact.status);
  const commandText = artifact.command.length > 0 ? artifact.command.join(' ') : 'No command captured';
  return (
    <div style={{ border: '1px solid #dbe4f0', borderRadius: '8px', padding: '12px', background: '#fff' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px', marginBottom: '8px' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 800, color: '#111827' }}>
            {validationToolLabel(artifact.tool_name)} · {formatTargetType(artifact.target_type)}
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
            {artifact.source} evidence · started {formatDateTime(artifact.started_at)}
          </div>
        </div>
        <span style={{ fontSize: '11px', color: statusStyle.color, background: statusStyle.background, borderRadius: '999px', padding: '3px 7px', fontWeight: 800 }}>
          {artifact.status.replace(/_/g, ' ')}
        </span>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '10px' }}>
        <EvidenceBadge>{artifact.deterministic ? 'deterministic' : 'non-deterministic'}</EvidenceBadge>
        <EvidenceBadge>{artifact.sandboxed ? `${artifact.sandbox_mode ?? 'process'} sandbox` : 'not sandboxed'}</EvidenceBadge>
        {artifact.command_redacted && <EvidenceBadge>command redacted</EvidenceBadge>}
        {artifact.output_limit_exceeded && <EvidenceBadge>output limit hit</EvidenceBadge>}
        {artifact.timed_out && <EvidenceBadge>timed out</EvidenceBadge>}
      </div>

      <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '11px', lineHeight: 1.5, color: '#334155', background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '6px', padding: '8px', overflowX: 'auto', marginBottom: '10px' }}>
        {commandText}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '8px', fontSize: '12px', color: '#475569' }}>
        <div><strong style={{ color: '#0f172a' }}>Target:</strong> {artifact.target}</div>
        <div><strong style={{ color: '#0f172a' }}>Resolved:</strong> {artifact.resolved_target ?? 'not recorded'}</div>
        <div><strong style={{ color: '#0f172a' }}>Policy:</strong> {artifact.policy_decision ?? 'allowed'}</div>
        <div><strong style={{ color: '#0f172a' }}>Network:</strong> {artifact.network_mode ?? 'not recorded'}</div>
        <div><strong style={{ color: '#0f172a' }}>Container:</strong> {artifact.container_image ?? 'not used'}</div>
        <div><strong style={{ color: '#0f172a' }}>Exit:</strong> {artifact.returncode ?? 'not recorded'}</div>
        <div><strong style={{ color: '#0f172a' }}>Duration:</strong> {formatDuration(artifact.duration_ms)}</div>
        <div><strong style={{ color: '#0f172a' }}>Stdout:</strong> {formatBytes(artifact.stdout_bytes)}</div>
        <div><strong style={{ color: '#0f172a' }}>Max runtime:</strong> {artifact.max_runtime_seconds ? `${artifact.max_runtime_seconds}s` : 'not recorded'}</div>
      </div>

      {artifact.stderr_summary && (
        <div style={{ marginTop: '10px', fontSize: '12px', color: '#92400e', background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '6px', padding: '8px' }}>
          {artifact.stderr_summary}
        </div>
      )}
    </div>
  );
}

function ScanFindingSummary({ finding }: { finding: ScanFinding }) {
  const cveText = finding.cve_ids.length > 0 ? ` · ${finding.cve_ids.join(', ')}` : '';
  const tagText = finding.tags.length > 0 ? ` · ${finding.tags.slice(0, 4).join(', ')}` : '';
  return (
    <li style={{ fontSize: '12px', color: '#475569', lineHeight: 1.5 }}>
      <strong style={{ color: '#111827' }}>{finding.template_name || finding.template_id}</strong>
      {' '}· {finding.severity}{cveText}{tagText}
    </li>
  );
}

function ValidationRunbookSummary({ runbook }: { runbook: ValidationRunbookResponse }) {
  const coverage = runbook.coverage;
  const visibleThreats = runbook.mapped_threats.slice(0, 4);
  const visibleUnbound = runbook.unbound_findings.slice(0, 4);
  return (
    <div style={{ border: '1px solid #dbe4f0', borderRadius: '8px', padding: '12px', background: '#fbfdff' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px', marginBottom: '10px' }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827' }}>Validation Runbook</div>
          <div style={{ fontSize: '12px', color: '#64748b', lineHeight: 1.5, marginTop: '2px' }}>
            {runbook.executive_summary}
          </div>
        </div>
        <span style={{ fontSize: '11px', color: '#334155', background: '#e2e8f0', borderRadius: '999px', padding: '3px 7px', fontWeight: 800, whiteSpace: 'nowrap' }}>
          {formatBinding(coverage.target_binding)}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px', marginBottom: '12px' }}>
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '9px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Validated</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{coverage.validated_threat_count}</div>
        </div>
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '9px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Indicated</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{coverage.indicated_threat_count}</div>
        </div>
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '9px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Unbound</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{coverage.unbound_finding_count}</div>
        </div>
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '9px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Untested</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{coverage.untested_threat_count}</div>
        </div>
      </div>

      {runbook.gaps.length > 0 && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827', marginBottom: '6px' }}>Coverage Gaps</div>
          <ul style={{ margin: 0, paddingLeft: '18px' }}>
            {runbook.gaps.slice(0, 4).map(gap => (
              <li key={gap} style={{ fontSize: '12px', color: '#475569', lineHeight: 1.5 }}>{gap}</li>
            ))}
          </ul>
        </div>
      )}

      {visibleThreats.length > 0 && (
        <div style={{ marginBottom: visibleUnbound.length > 0 ? '12px' : 0 }}>
          <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827', marginBottom: '6px' }}>Threat Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {visibleThreats.map(threat => {
              const style = confidenceStyle(threat.confidence_label);
              return (
                <div key={threat.threat_id} style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '7px', padding: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', alignItems: 'center', marginBottom: '4px' }}>
                    <strong style={{ fontSize: '12px', color: '#111827' }}>{threat.threat_display_id} · {threat.stride_category}</strong>
                    <span style={{ fontSize: '11px', color: style.color, background: style.background, borderRadius: '999px', padding: '2px 7px', fontWeight: 800 }}>
                      {threat.confidence_label}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: '#475569', lineHeight: 1.45 }}>{threat.explanation}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {visibleUnbound.length > 0 && (
        <div>
          <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827', marginBottom: '6px' }}>Unbound Evidence</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {visibleUnbound.map(finding => (
              <div key={finding.finding_id} style={{ background: '#fff', border: '1px solid #fde68a', borderRadius: '7px', padding: '8px' }}>
                <div style={{ fontSize: '12px', color: '#111827', fontWeight: 800 }}>{finding.title}</div>
                <div style={{ fontSize: '12px', color: '#64748b', lineHeight: 1.45 }}>
                  {validationToolLabel(finding.tool_name ?? 'tool')} · {finding.severity} · {finding.matched_at}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function EvidenceLedger({ job, detail, runbook, loading, error, onRetry }: EvidenceLedgerProps) {
  const artifacts = detail?.execution_artifacts ?? [];
  const findings = detail?.findings ?? [];
  const threatResults = detail?.threat_results ?? [];
  const hiddenFindings = Math.max(0, findings.length - 5);

  return (
    <div style={{ marginTop: '12px', borderTop: '1px solid #e2e8f0', paddingTop: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px', marginBottom: '10px' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 800, color: '#111827' }}>
            Validation Evidence Ledger
          </div>
          <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
            Sanitized execution provenance, mapped findings, and threat correlation for this scan.
          </div>
        </div>
        <button
          type="button"
          onClick={onRetry}
          disabled={loading}
          className="btn-export btn-export-quiet"
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '8px', marginBottom: '12px' }}>
        <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Findings</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{detail?.finding_count ?? job.finding_count}</div>
        </div>
        <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Threat Mapping</div>
          <div style={{ fontSize: '12px', color: '#111827', fontWeight: 700 }}>{detail ? summarizeThreatResults(threatResults) : 'Load details to inspect'}</div>
        </div>
        <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Artifacts</div>
          <div style={{ fontSize: '17px', color: '#111827', fontWeight: 800 }}>{detail ? artifacts.length : '...'}</div>
        </div>
        <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, textTransform: 'uppercase' }}>Completed</div>
          <div style={{ fontSize: '12px', color: '#111827', fontWeight: 700 }}>{formatDateTime(detail?.completed_at ?? job.completed_at)}</div>
        </div>
      </div>

      <div style={{ fontSize: '12px', color: '#475569', marginBottom: '12px' }}>
        <strong style={{ color: '#111827' }}>Targets:</strong> {formatTargets(detail?.targets ?? job.targets)}
      </div>

      {error && (
        <div style={{ padding: '8px 10px', marginBottom: '12px', borderRadius: '6px', background: '#fef2f2', color: '#b91c1c', fontSize: '12px' }}>
          {error}
        </div>
      )}

      {!detail && !loading && !error && (
        <div style={{ padding: '10px', borderRadius: '6px', background: '#f8fafc', color: '#64748b', fontSize: '12px' }}>
          Open this ledger to load the detailed scan evidence.
        </div>
      )}

      {loading && (
        <div style={{ padding: '10px', borderRadius: '6px', background: '#f8fafc', color: '#64748b', fontSize: '12px' }}>
          Loading scan artifacts and mapped evidence...
        </div>
      )}

      {detail && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {runbook && <ValidationRunbookSummary runbook={runbook} />}

          <div>
            <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827', marginBottom: '8px' }}>Execution Provenance</div>
            {artifacts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {artifacts.map(artifact => (
                  <ScanArtifactRow key={artifact.id} artifact={artifact} />
                ))}
              </div>
            ) : (
              <div style={{ padding: '10px', borderRadius: '6px', background: '#f8fafc', color: '#64748b', fontSize: '12px' }}>
                No execution artifact was captured for this scan. Older scans and some imported evidence may only have normalized findings.
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '12px', fontWeight: 800, color: '#111827', marginBottom: '8px' }}>Normalized Findings</div>
            {findings.length > 0 ? (
              <>
                <ol style={{ margin: 0, paddingLeft: '18px' }}>
                  {findings.slice(0, 5).map(finding => (
                    <ScanFindingSummary key={finding.id} finding={finding} />
                  ))}
                </ol>
                {hiddenFindings > 0 && (
                  <div style={{ marginTop: '6px', fontSize: '12px', color: '#64748b' }}>
                    +{hiddenFindings} more finding{hiddenFindings !== 1 ? 's' : ''} retained in the scan detail.
                  </div>
                )}
              </>
            ) : (
              <div style={{ padding: '10px', borderRadius: '6px', background: '#f8fafc', color: '#64748b', fontSize: '12px' }}>
                No normalized findings were produced by this validation run.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function ScanPanel({ threatModelId, onScanComplete }: ScanPanelProps) {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [jobDetails, setJobDetails] = useState<Record<string, ScanJobDetail>>({});
  const [jobRunbooks, setJobRunbooks] = useState<Record<string, ValidationRunbookResponse | null>>({});
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [detailsLoadingJobId, setDetailsLoadingJobId] = useState<string | null>(null);
  const [detailsError, setDetailsError] = useState<{ jobId: string; message: string } | null>(null);
  const [validationTools, setValidationTools] = useState<ValidationToolInventoryItem[]>([]);
  const [dfdNodes, setDfdNodes] = useState<DFDNodeResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authAcknowledged, setAuthAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollingJobId, setPollingJobId] = useState<string | null>(null);
  const [showValidationModal, setShowValidationModal] = useState(false);
  const [validationMode, setValidationMode] = useState<'run' | 'import'>('import');
  const [validationToolName, setValidationToolName] = useState('semgrep');
  const [validationTargetType, setValidationTargetType] = useState<ValidationTargetType>('repository_path');
  const [validationTarget, setValidationTarget] = useState('');
  const [validationTargetNodeId, setValidationTargetNodeId] = useState('');
  const [validationRawOutput, setValidationRawOutput] = useState('');
  const [validationAuthorized, setValidationAuthorized] = useState(false);
  const [validationSubmitting, setValidationSubmitting] = useState(false);

  // S2: scan type + credential selection
  const [scanType, setScanType] = useState<'unauthenticated' | 'authenticated'>('unauthenticated');
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [credentials, setCredentials] = useState<ScanCredential[]>([]);
  const [showCredManager, setShowCredManager] = useState(false);

  const importSources = useMemo(
    () => [
      ...validationTools.map(tool => ({
        name: tool.name,
        label: validationToolLabel(tool.name),
        supported_targets: tool.supported_targets as ValidationTargetType[],
        proof_mode: tool.proof_mode,
        safety_boundary: tool.safety_boundary,
      })),
      ...IMPORT_ONLY_SOURCES,
    ],
    [validationTools],
  );
  const selectableSources = validationMode === 'import' ? importSources : validationTools;
  const selectedValidationTool = validationTools.find(tool => tool.name === validationToolName) ?? validationTools[0];
  const selectedImportSource = importSources.find(source => source.name === validationToolName);
  const selectedSource = validationMode === 'import' ? selectedImportSource : selectedValidationTool;
  const selectedTargetTypes = selectedSource?.supported_targets.length
    ? selectedSource.supported_targets as ValidationTargetType[]
    : ['repository_path'];

  const fetchJobs = useCallback(async () => {
    try {
      const res = await fetch(`/api/threat-models/${threatModelId}/scans`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (res.ok) {
        const data: ScanJob[] = await res.json();
        setJobs(data);
        return data;
      }
    } catch {
      // non-blocking
    }
    return null;
  }, [threatModelId]);

  const fetchCredentials = useCallback(async () => {
    try {
      const res = await fetch(`/api/threat-models/${threatModelId}/scan-credentials`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (res.ok) {
        const data: ScanCredential[] = await res.json();
        setCredentials(data);
        return data;
      }
    } catch {
      // non-blocking
    }
    return null;
  }, [threatModelId]);

  const fetchValidationTools = useCallback(async () => {
    try {
      const data = await api.getValidationTools();
      setValidationTools(data.tools);
      return data.tools;
    } catch {
      return null;
    }
  }, []);

  const fetchDfdNodes = useCallback(async () => {
    try {
      const dfd = await api.getDFD(threatModelId);
      setDfdNodes(dfd.nodes);
      return dfd.nodes;
    } catch {
      return null;
    }
  }, [threatModelId]);

  const loadJobDetail = useCallback(async (jobId: string, force = false) => {
    if (!force && jobDetails[jobId] && jobRunbooks[jobId] !== undefined) return;
    setDetailsLoadingJobId(jobId);
    setDetailsError(null);
    try {
      const [detail, runbook] = await Promise.all([
        api.getScan(threatModelId, jobId),
        api.getScanRunbook(threatModelId, jobId).catch(() => null),
      ]);
      setJobDetails(prev => ({ ...prev, [jobId]: detail }));
      setJobRunbooks(prev => ({ ...prev, [jobId]: runbook }));
      setJobs(prev => prev.map(job => (job.id === detail.id ? { ...job, ...detail } : job)));
    } catch (e: unknown) {
      setDetailsError({
        jobId,
        message: e instanceof Error ? e.message : 'Could not load scan evidence',
      });
    } finally {
      setDetailsLoadingJobId(current => (current === jobId ? null : current));
    }
  }, [jobDetails, jobRunbooks, threatModelId]);

  const toggleJobDetail = async (jobId: string) => {
    if (expandedJobId === jobId) {
      setExpandedJobId(null);
      return;
    }
    setExpandedJobId(jobId);
    await loadJobDetail(jobId);
  };

  useEffect(() => {
    void fetchJobs();
    void fetchCredentials();
    void fetchValidationTools();
    void fetchDfdNodes();
  }, [fetchJobs, fetchCredentials, fetchValidationTools, fetchDfdNodes]);

  useEffect(() => {
    if (validationMode === 'import' && validationTools.length === 0 && validationToolName === 'semgrep') return;
    if (!selectableSources.length) return;
    const current = selectableSources.find(source => source.name === validationToolName);
    const nextSource = current ?? selectableSources.find(source => source.name !== 'nuclei') ?? selectableSources[0];
    if (!nextSource) return;
    if (!current) {
      setValidationToolName(nextSource.name);
    }
    const supportedTargets = nextSource.supported_targets as ValidationTargetType[];
    const nextTargetType = supportedTargets[0];
    if (nextTargetType && !supportedTargets.includes(validationTargetType)) {
      setValidationTargetType(nextTargetType);
    }
  }, [selectableSources, validationMode, validationTools.length, validationToolName, validationTargetType]);

  // Poll while a job is running
  useEffect(() => {
    if (!pollingJobId) return;
    const interval = setInterval(async () => {
      const fresh = await fetchJobs();
      if (!fresh) return;
      const job = fresh.find(j => j.id === pollingJobId);
      if (job && !['pending', 'running'].includes(job.status)) {
        setPollingJobId(null);
        onScanComplete?.();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [pollingJobId, fetchJobs, onScanComplete]);

  const startScan = async () => {
    if (!authAcknowledged) return;
    if (scanType === 'authenticated' && !selectedCredentialId) return;
    setLoading(true);
    setError(null);
    try {
      const body: ScanCreateRequest = {
        scan_type: scanType,
        scope: 'external',
        tool_name: 'nuclei',
        target_type: 'url',
        authorization_acknowledged: true,
        credential_id: scanType === 'authenticated' ? selectedCredentialId : null,
      };
      const res = await fetch(`/api/threat-models/${threatModelId}/scans`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => null);
        throw new Error((err?.detail) || `Scan failed to start (HTTP ${res.status})`);
      }
      const newJob: ScanJob = await res.json();
      setJobs(prev => [newJob, ...prev]);
      setPollingJobId(newJob.id);
      setShowAuthModal(false);
      setAuthAcknowledged(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const resetValidationModal = () => {
    setShowValidationModal(false);
    setValidationAuthorized(false);
    setValidationRawOutput('');
  };

  const submitValidationTool = async () => {
    if (!validationTarget.trim()) return;
    if (validationMode === 'run' && !validationAuthorized) return;
    if (validationMode === 'import' && !validationRawOutput.trim()) return;
    setValidationSubmitting(true);
    setError(null);
    try {
      if (validationMode === 'import') {
        const detail = await api.ingestScanEvidence(threatModelId, {
          tool_name: validationToolName,
          target_type: validationTargetType,
          target: validationTarget.trim(),
          raw_output: validationRawOutput,
          target_node_id: validationTargetNodeId.trim() || null,
        });
        setJobs(prev => [detail, ...prev.filter(job => job.id !== detail.id)]);
        setJobDetails(prev => ({ ...prev, [detail.id]: detail }));
        try {
          const runbook = await api.getScanRunbook(threatModelId, detail.id);
          setJobRunbooks(prev => ({ ...prev, [detail.id]: runbook }));
        } catch {
          setJobRunbooks(prev => ({ ...prev, [detail.id]: null }));
          // Detailed evidence remains usable even if runbook generation is unavailable.
        }
        setExpandedJobId(detail.id);
        onScanComplete?.();
      } else {
        const job = await api.runValidationTool(threatModelId, {
          tool_name: validationToolName,
          target_type: validationTargetType,
          target: validationTarget.trim(),
          target_node_id: validationTargetNodeId.trim() || null,
          scope: 'external',
          authorization_acknowledged: true,
        });
        setJobs(prev => [job, ...prev]);
        setPollingJobId(job.id);
      }
      resetValidationModal();
      void fetchJobs();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Validation failed');
    } finally {
      setValidationSubmitting(false);
    }
  };

  const cancelScan = async (jobId: string) => {
    await fetch(`/api/threat-models/${threatModelId}/scans/${jobId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token()}` },
    });
    void fetchJobs();
  };

  const canStartScan = scanType === 'unauthenticated' || (scanType === 'authenticated' && !!selectedCredentialId);

  return (
    <div style={{ padding: '16px', background: '#f9fafb', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: '#111827' }}>
          Threat Validation Scan
        </h3>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setShowCredManager(v => !v)}
            title="Manage saved authenticated scan credentials for this model"
            className={`btn-export ${showCredManager ? 'btn-export-accent' : 'btn-export-quiet'}`}
          >
            Credentials
          </button>
          <button
            onClick={() => setShowValidationModal(true)}
            title="Import captured evidence or queue a policy-gated validation tool"
            className="btn-export btn-export-quiet"
          >
            Evidence
          </button>
          <button
            onClick={() => setShowAuthModal(true)}
            disabled={loading}
            title="Start a validation scan against the current model targets"
            className="btn-create"
          >
            Run Scan
          </button>
        </div>
      </div>

      <p style={{ margin: '0 0 14px', fontSize: '13px', lineHeight: 1.5, color: '#4b5563' }}>
        Optional live validation for the threat model. ThreatGenix scans the target URLs attached
        to your DFD nodes, then maps the results back to threats so you can tell which ones were
        confirmed, mitigated, not found, or still unverifiable. It does not generate the threat
        list by itself.
      </p>

      {validationTools.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '14px' }}>
          {validationTools.map(tool => {
            const status = validationToolStatus(tool);
            const targetText = tool.supported_targets.map(target => target.replace(/_/g, ' ')).join(', ');
            return (
              <span
                key={tool.name}
                title={`${compactCategory(tool.category)} · ${targetText} · ${tool.safety_boundary}`}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '5px 8px',
                  borderRadius: '999px',
                  background: status.background,
                  color: status.color,
                  fontSize: '11px',
                  fontWeight: 700,
                }}
              >
                {validationToolLabel(tool.name)}
                <span style={{ fontWeight: 600 }}>{status.label}</span>
              </span>
            );
          })}
        </div>
      )}

      {/* Credential manager (collapsible) */}
      {showCredManager && (
        <div style={{ marginBottom: '16px', padding: '14px', background: 'white', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <CredentialManager
            threatModelId={threatModelId}
            onCredentialsChange={() => void fetchCredentials()}
          />
        </div>
      )}

      {error && (
        <div style={{ padding: '8px 12px', background: '#fee2e2', color: '#dc2626', borderRadius: '6px', fontSize: '13px', marginBottom: '12px' }}>
          {error}
        </div>
      )}

      {/* Job list */}
      {jobs.length === 0 ? (
        <p style={{ color: '#6b7280', fontSize: '13px', margin: 0 }}>
          No scans yet. Add scan target URLs to DFD nodes, then run a scan.
        </p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {jobs.map(job => {
            const isExpanded = expandedJobId === job.id;
            const jobTool = validationTools.find(tool => tool.name === job.tool_name);
            return (
              <div key={job.id} style={{ padding: '10px 12px', background: 'white', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                  <div>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: STATUS_COLORS[job.status] || '#374151' }}>
                      {job.status.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '12px', color: '#6b7280', marginLeft: '10px' }}>
                      {validationToolLabel(job.tool_name ?? 'nuclei')} · {job.target_type?.replace(/_/g, ' ') ?? 'url'} · {job.scan_type} · {job.scope}
                    </span>
                    {jobTool && (
                      <span style={{ fontSize: '11px', color: '#475569', marginLeft: '8px', background: '#eef2ff', borderRadius: '999px', padding: '2px 6px', fontWeight: 700 }}>
                        {jobTool.deterministic ? 'deterministic' : 'non-deterministic'}
                      </span>
                    )}
                    {job.status === 'completed' && (
                      <span style={{ fontSize: '12px', color: '#374151', marginLeft: '10px' }}>
                        {job.finding_count} finding{job.finding_count !== 1 ? 's' : ''}
                      </span>
                    )}
                    {job.error_message && (
                      <div style={{ fontSize: '11px', color: '#ef4444', marginTop: '2px' }}>{job.error_message}</div>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      onClick={() => { void toggleJobDetail(job.id); }}
                      title="Inspect normalized findings and sanitized validation execution evidence"
                      className="btn-export btn-export-quiet"
                    >
                      {isExpanded ? 'Hide Evidence' : 'View Evidence'}
                    </button>
                    {['pending', 'running'].includes(job.status) && (
                      <button
                        onClick={() => cancelScan(job.id)}
                        title="Cancel this running validation scan"
                        className="btn-export btn-export-quiet"
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                </div>
                {isExpanded && (
                  <EvidenceLedger
                    job={job}
                    detail={jobDetails[job.id]}
                    runbook={jobRunbooks[job.id] ?? undefined}
                    loading={detailsLoadingJobId === job.id}
                    error={detailsError?.jobId === job.id ? detailsError.message : null}
                    onRetry={() => { void loadJobDetail(job.id, true); }}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      {showValidationModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
          <div style={{ background: 'white', borderRadius: '12px', padding: '24px', maxWidth: '680px', width: '92%', maxHeight: '88vh', overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.3)' }}>
            <h2 style={{ margin: '0 0 16px', fontSize: '16px', fontWeight: 700, color: '#111827' }}>
              Validation Evidence
            </h2>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              {(['import', 'run'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => setValidationMode(mode)}
                  className={`btn-export ${validationMode === mode ? 'btn-export-accent scan-panel-mode-button-active' : 'btn-export-quiet'}`}
                >
                  {mode === 'import' ? 'Import Output' : 'Run Tool'}
                </button>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', fontWeight: 600, color: '#374151' }}>
                {validationMode === 'import' ? 'Tool or Source' : 'Tool'}
                <select
                  value={validationToolName}
                  onChange={event => {
                    const nextTool = selectableSources.find(source => source.name === event.target.value);
                    setValidationToolName(event.target.value);
                    const nextTarget = nextTool?.supported_targets[0] as ValidationTargetType | undefined;
                    if (nextTarget) setValidationTargetType(nextTarget);
                  }}
                  className="scan-panel-select"
                >
                  {selectableSources.map(tool => (
                    <option key={tool.name} value={tool.name}>
                      {'label' in tool ? tool.label : validationToolLabel(tool.name)}
                    </option>
                  ))}
                </select>
              </label>

              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', fontWeight: 600, color: '#374151' }}>
                Target Type
                <select
                  value={validationTargetType}
                  onChange={event => setValidationTargetType(event.target.value as ValidationTargetType)}
                  className="scan-panel-select"
                >
                  {selectedTargetTypes.map(targetType => (
                    <option key={targetType} value={targetType}>
                      {targetType.replace(/_/g, ' ')}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {selectedSource && (
              <div style={{ padding: '8px 10px', marginBottom: '12px', borderRadius: '6px', background: '#f8fafc', color: '#475569', fontSize: '12px', lineHeight: 1.45 }}>
                <strong style={{ color: '#111827' }}>{selectedSource.proof_mode}</strong>
                {' '}· {selectedSource.safety_boundary}
              </div>
            )}

            <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', fontWeight: 600, color: '#374151', marginBottom: '12px' }}>
              Target
              <input
                value={validationTarget}
                onChange={event => setValidationTarget(event.target.value)}
                placeholder={
                  validationTargetType === 'url'
                    ? 'https://api.example.com'
                    : validationTargetType === 'ai_system'
                      ? '/path/to/ai-system-redteam.json'
                    : '/path/to/repository'
                }
                className="scan-panel-select"
              />
            </label>

            <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', fontWeight: 600, color: '#374151', marginBottom: '12px' }}>
              DFD Node Binding
              <select
                aria-label="DFD Node Binding"
                value={validationTargetNodeId}
                onChange={event => setValidationTargetNodeId(event.target.value)}
                className="scan-panel-select"
              >
                <option value="">No DFD node binding</option>
                {dfdNodes.map(node => (
                  <option key={node.id} value={node.id}>
                    {node.name} ({node.node_type.replace(/_/g, ' ')})
                  </option>
                ))}
              </select>
              <span style={{ fontSize: '11px', color: '#64748b', fontWeight: 500 }}>
                Imported evidence validates semantic threats best when bound to the affected component.
              </span>
            </label>

            {validationMode === 'import' ? (
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', fontWeight: 600, color: '#374151', marginBottom: '14px' }}>
                Evidence Output
                <textarea
                  value={validationRawOutput}
                  onChange={event => setValidationRawOutput(event.target.value)}
                  maxLength={10_000_000}
                  rows={10}
                  placeholder="Paste JSON, JSONL, or text findings from a scanner, security platform, or pentest report"
                  style={{ border: '1px solid #d1d5db', borderRadius: '6px', padding: '10px', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '12px', resize: 'vertical' }}
                />
              </label>
            ) : (
              <label style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', cursor: 'pointer', marginBottom: '16px' }}>
                <input
                  type="checkbox"
                  checked={validationAuthorized}
                  onChange={event => setValidationAuthorized(event.target.checked)}
                  style={{ marginTop: '2px' }}
                />
                <span style={{ fontSize: '13px', color: '#111827', fontWeight: 500 }}>
                  I confirm I am authorized to validate this target.
                </span>
              </label>
            )}

            {validationMode === 'run' && selectedValidationTool && !selectedValidationTool.execution_enabled && (
              <div style={{ padding: '8px 10px', marginBottom: '14px', borderRadius: '6px', background: '#f8fafc', color: '#475569', fontSize: '12px' }}>
                {validationToolLabel(selectedValidationTool.name)} execution is currently disabled by validation policy.
              </div>
            )}
            {validationMode === 'run' && selectedValidationTool?.execution_enabled && !selectedValidationTool.available && (
              <div style={{ padding: '8px 10px', marginBottom: '14px', borderRadius: '6px', background: '#fef3c7', color: '#92400e', fontSize: '12px' }}>
                {validationToolLabel(selectedValidationTool.name)} is not installed on this runner.
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={resetValidationModal}
                className="btn-export btn-export-quiet"
              >
                Cancel
              </button>
              <button
                onClick={submitValidationTool}
                disabled={
                  validationSubmitting ||
                  !validationTarget.trim() ||
                  (validationMode === 'import' && !validationRawOutput.trim()) ||
                  (validationMode === 'run' && (!validationAuthorized || !selectedValidationTool?.execution_enabled || !selectedValidationTool?.available))
                }
                className="btn-create"
              >
                {validationSubmitting ? 'Submitting\u2026' : validationMode === 'import' ? 'Import Evidence' : 'Run Validation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Authorization + scan-type modal */}
      {showAuthModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
          <div style={{ background: 'white', borderRadius: '12px', padding: '28px', maxWidth: '540px', width: '90%', boxShadow: '0 20px 60px rgba(0,0,0,0.3)' }}>
            <h2 style={{ margin: '0 0 16px', fontSize: '16px', fontWeight: 700, color: '#111827' }}>
              Authorization Required
            </h2>
            <p style={{ fontSize: '13px', color: '#374151', lineHeight: '1.6', marginBottom: '16px' }}>
              {AUTHORIZATION_TEXT}
            </p>

            {/* Scan type selector */}
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#374151', marginBottom: '8px' }}>Scan Type</div>
              <div style={{ display: 'flex', gap: '8px' }}>
                {(['unauthenticated', 'authenticated'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setScanType(t)}
                    title={t === 'authenticated' ? 'Use stored credentials during the scan' : 'Run without credentials against externally reachable targets'}
                    className={`btn-export ${scanType === t ? 'btn-export-accent scan-panel-mode-button-active' : 'btn-export-quiet'}`}
                  >
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Credential selector (authenticated only) */}
            {scanType === 'authenticated' && (
              <div style={{ marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: '#374151', marginBottom: '6px' }}>
                  Credential
                </div>
                {credentials.length === 0 ? (
                  <div style={{ fontSize: '12px', color: '#dc2626', padding: '8px', background: '#fef2f2', borderRadius: '6px' }}>
                    No credentials saved. Close this dialog, click Credentials, and add one first.
                  </div>
                ) : (
                  <select
                    value={selectedCredentialId ?? ''}
                    onChange={e => setSelectedCredentialId(e.target.value || null)}
                    className="scan-panel-select"
                    title="Select the saved credential to use for this authenticated scan"
                  >
                    <option value="">— select a credential —</option>
                    {credentials.map(c => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.credential_type.replace(/_/g, ' ')})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            )}

            {/* Authorization checkbox */}
            <label style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', cursor: 'pointer', marginBottom: '20px' }}>
              <input
                type="checkbox"
                checked={authAcknowledged}
                onChange={e => setAuthAcknowledged(e.target.checked)}
                style={{ marginTop: '2px' }}
              />
              <span style={{ fontSize: '13px', color: '#111827', fontWeight: 500 }}>
                I confirm I am authorized to scan all targets listed in this threat model.
              </span>
            </label>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => { setShowAuthModal(false); setAuthAcknowledged(false); }}
                title="Close the scan authorization dialog without starting a scan"
                className="btn-export btn-export-quiet"
              >
                Cancel
              </button>
              <button
                onClick={startScan}
                disabled={!authAcknowledged || !canStartScan || loading}
                title="Confirm authorization and launch the selected validation scan"
                className="btn-create"
              >
                {loading ? 'Starting\u2026' : 'I Confirm \u2014 Start Scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
