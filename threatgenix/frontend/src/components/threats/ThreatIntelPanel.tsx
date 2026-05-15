import type {
  ThreatIntelAdvisoryRef,
  ThreatIntelCriControlRef,
  ThreatIntelKevRef,
  ThreatIntelPatternRef,
  ThreatIntelResponse,
  ThreatIntelSeveritySignal,
  ThreatIntelTechniqueRef,
  ThreatIntelWeaknessRef,
} from "../../types/api";

interface ThreatIntelPanelProps {
  intel: ThreatIntelResponse | null;
  loading: boolean;
  error: string | null;
}

function severityTone(severity: string | null | undefined): string {
  switch (severity) {
    case "Critical":
      return "threat-intel-severity-critical";
    case "High":
      return "threat-intel-severity-high";
    case "Medium":
      return "threat-intel-severity-medium";
    case "Low":
      return "threat-intel-severity-low";
    default:
      return "threat-intel-severity-unknown";
  }
}

function matchTone(matchType: string): string {
  return matchType === "semantic"
    ? "threat-intel-match-semantic"
    : "threat-intel-match-exact";
}

function SeveritySignalCard({ signal }: { signal: ThreatIntelSeveritySignal }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{signal.source}</span>
        <span className={`threat-intel-pill ${severityTone(signal.normalized_severity)}`}>
          {signal.normalized_severity ?? signal.value}
        </span>
      </div>
      <div className="threat-intel-card-title">{signal.label}</div>
      <div className="threat-intel-card-meta">{signal.reference_id}</div>
      {signal.note && <p className="threat-intel-card-copy">{signal.note}</p>}
    </div>
  );
}

function TechniqueCard({ technique }: { technique: ThreatIntelTechniqueRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{technique.technique_id}</span>
        <span className={`threat-intel-pill ${matchTone(technique.match_type)}`}>
          {technique.match_type === "semantic" ? "Inferred" : "Exact"}
        </span>
      </div>
      <div className="threat-intel-card-title">{technique.name}</div>
      <div className="threat-intel-card-meta">{technique.tactic}</div>
      {technique.description && (
        <p className="threat-intel-card-copy">{technique.description}</p>
      )}
      {technique.url && (
        <a
          className="threat-intel-link"
          href={technique.url}
          target="_blank"
          rel="noreferrer"
        >
          Open ATT&CK reference
        </a>
      )}
    </div>
  );
}

function PatternCard({ pattern }: { pattern: ThreatIntelPatternRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{pattern.capec_id}</span>
        <div className="threat-intel-card-pill-row">
          {pattern.severity && (
            <span className={`threat-intel-pill ${severityTone(pattern.severity)}`}>
              {pattern.severity}
            </span>
          )}
          <span className={`threat-intel-pill ${matchTone(pattern.match_type)}`}>
            {pattern.match_type === "semantic" ? "Inferred" : "Exact"}
          </span>
        </div>
      </div>
      <div className="threat-intel-card-title">{pattern.name}</div>
      <div className="threat-intel-card-meta">
        {pattern.likelihood ? `Likelihood: ${pattern.likelihood}` : "CAPEC pattern"}
      </div>
      {pattern.description && <p className="threat-intel-card-copy">{pattern.description}</p>}
      {(pattern.related_cwe_ids.length > 0 || pattern.related_attack_ids.length > 0) && (
        <div className="threat-intel-chip-group">
          {pattern.related_cwe_ids.map((cweId) => (
            <span key={cweId} className="threat-intel-chip">
              {cweId}
            </span>
          ))}
          {pattern.related_attack_ids.map((attackId) => (
            <span key={attackId} className="threat-intel-chip">
              {attackId}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function WeaknessCard({ weakness }: { weakness: ThreatIntelWeaknessRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{weakness.cwe_id}</span>
        <div className="threat-intel-card-pill-row">
          {weakness.is_top_25 && (
            <span className="threat-intel-pill threat-intel-pill-emphasis">Top 25</span>
          )}
          <span className={`threat-intel-pill ${matchTone(weakness.match_type)}`}>
            {weakness.match_type === "semantic" ? "Inferred" : "Exact"}
          </span>
        </div>
      </div>
      <div className="threat-intel-card-title">{weakness.name}</div>
      {weakness.description && (
        <p className="threat-intel-card-copy">{weakness.description}</p>
      )}
      {weakness.consequences && (
        <div className="threat-intel-card-meta">Consequences: {weakness.consequences}</div>
      )}
    </div>
  );
}

function AdvisoryCard({ advisory }: { advisory: ThreatIntelAdvisoryRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{advisory.advisory_id}</span>
        <div className="threat-intel-card-pill-row">
          {advisory.severity && (
            <span className={`threat-intel-pill ${severityTone(advisory.severity)}`}>
              {advisory.severity}
            </span>
          )}
          <span className={`threat-intel-pill ${matchTone(advisory.match_type)}`}>
            {advisory.match_type === "semantic" ? "Inferred" : "Exact"}
          </span>
        </div>
      </div>
      <div className="threat-intel-card-title">{advisory.title}</div>
      {advisory.published_date && (
        <div className="threat-intel-card-meta">
          Published {new Date(advisory.published_date).toLocaleDateString()}
        </div>
      )}
      {advisory.summary && <p className="threat-intel-card-copy">{advisory.summary}</p>}
      {(advisory.referenced_cves.length > 0 || advisory.referenced_attack_ids.length > 0) && (
        <div className="threat-intel-chip-group">
          {advisory.referenced_cves.map((cveId) => (
            <span key={cveId} className="threat-intel-chip">
              {cveId}
            </span>
          ))}
          {advisory.referenced_attack_ids.map((attackId) => (
            <span key={attackId} className="threat-intel-chip">
              {attackId}
            </span>
          ))}
        </div>
      )}
      {advisory.url && (
        <a
          className="threat-intel-link"
          href={advisory.url}
          target="_blank"
          rel="noreferrer"
        >
          Open advisory
        </a>
      )}
    </div>
  );
}

function KevCard({ kev }: { kev: ThreatIntelKevRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{kev.cve_id}</span>
        <div className="threat-intel-card-pill-row">
          <span className="threat-intel-pill threat-intel-pill-emphasis">KEV</span>
          <span className={`threat-intel-pill ${kev.match_type === "scan_cve" ? "threat-intel-match-exact" : "threat-intel-match-semantic"}`}>
            {kev.match_type === "scan_cve" ? "From scan" : "Context match"}
          </span>
        </div>
      </div>
      <div className="threat-intel-card-title">{kev.vulnerability_name}</div>
      <div className="threat-intel-card-meta">
        {kev.vendor_project} / {kev.product}
      </div>
      {kev.date_added && (
        <div className="threat-intel-card-meta">
          Added to KEV {new Date(kev.date_added).toLocaleDateString()}
        </div>
      )}
      {kev.known_ransomware_use && (
        <p className="threat-intel-card-copy">
          Known ransomware use: {kev.known_ransomware_use}
        </p>
      )}
    </div>
  );
}

function CriCard({ control }: { control: ThreatIntelCriControlRef }) {
  return (
    <div className="threat-intel-card">
      <div className="threat-intel-card-topline">
        <span className="threat-intel-card-kicker">{control.cri_control_id}</span>
        <span className="threat-intel-pill threat-intel-pill-subtle">
          {control.attack_technique_id}
        </span>
      </div>
      <div className="threat-intel-card-title">{control.cri_control_name}</div>
      <div className="threat-intel-card-meta">
        {control.cri_function} · {control.mapping_type}
      </div>
    </div>
  );
}

function IntelSection<T>({
  title,
  subtitle,
  items,
  renderItem,
}: {
  title: string;
  subtitle: string;
  items: T[];
  renderItem: (item: T) => JSX.Element;
}) {
  if (items.length === 0) {
    return null;
  }

  return (
    <section className="threat-intel-section">
      <div className="threat-intel-section-header">
        <div>
          <h5>{title}</h5>
          <p>{subtitle}</p>
        </div>
        <span className="threat-intel-section-count">{items.length}</span>
      </div>
      <div className="threat-intel-grid">{items.map(renderItem)}</div>
    </section>
  );
}

export function ThreatIntelPanel({ intel, loading, error }: ThreatIntelPanelProps) {
  if (loading) {
    return (
      <div className="threat-intel-loading">
        <div className="dfd-spinner" style={{ width: 18, height: 18 }} />
        <span>Loading external threat intelligence…</span>
      </div>
    );
  }

  if (error) {
    return <p className="threat-intel-error">Failed to load threat intel: {error}</p>;
  }

  if (!intel) {
    return (
      <p className="threat-intel-empty">
        No threat intel available for this record yet.
      </p>
    );
  }

  const hasAnyIntel =
    intel.scan_cve_ids.length > 0 ||
    intel.severity_signals.length > 0 ||
    intel.attack_techniques.length > 0 ||
    intel.attack_patterns.length > 0 ||
    intel.weaknesses.length > 0 ||
    intel.advisories.length > 0 ||
    intel.kev_entries.length > 0 ||
    intel.cri_controls.length > 0;

  return (
    <div className="threat-intel-panel">
      <div className="threat-intel-summary">
        <div className="threat-intel-summary-card">
          <div className="threat-intel-summary-label">Local severity</div>
          <div className={`threat-intel-summary-value ${severityTone(intel.local_severity)}`}>
            {intel.local_severity}
          </div>
          <p>The current workflow severity on this threat.</p>
        </div>
        <div className="threat-intel-summary-card">
          <div className="threat-intel-summary-label">Highest external signal</div>
          <div
            className={`threat-intel-summary-value ${severityTone(
              intel.highest_external_severity
            )}`}
          >
            {intel.highest_external_severity ?? "None yet"}
          </div>
          <p>External intel is additive and does not overwrite the stored severity.</p>
        </div>
        <div className="threat-intel-summary-card">
          <div className="threat-intel-summary-label">Match confidence</div>
          <div className="threat-intel-summary-value threat-intel-severity-unknown">
            {intel.semantic_matches_inferred ? "Exact + inferred" : "Exact only"}
          </div>
          <p>
            {intel.semantic_matches_inferred
              ? "Some mappings were inferred from threat wording and system context."
              : "Current mappings come from exact IDs or direct scan evidence."}
          </p>
        </div>
      </div>

      {intel.unavailable_reason && (
        <div className="threat-intel-banner threat-intel-banner-warning">
          {/NoCredentials|Error|Traceback|failed:/i.test(intel.unavailable_reason)
            ? "No external threat-database matches were found yet. You can still use local severity, notes, and AI guidance on this threat."
            : intel.unavailable_reason}
        </div>
      )}

      {intel.scan_cve_ids.length > 0 && (
        <section className="threat-intel-section">
          <div className="threat-intel-section-header">
            <div>
              <h5>Scan Evidence</h5>
              <p>CVEs observed in the latest linked scan result for this threat.</p>
            </div>
          </div>
          <div className="threat-intel-chip-group">
            {intel.scan_cve_ids.map((cveId) => (
              <span key={cveId} className="threat-intel-chip">
                {cveId}
              </span>
            ))}
          </div>
        </section>
      )}

      <IntelSection
        title="Severity Signals"
        subtitle="External severity or exploitation signals related to this threat."
        items={intel.severity_signals}
        renderItem={(signal) => (
          <SeveritySignalCard
            key={`${signal.source}-${signal.reference_id}-${signal.label}`}
            signal={signal}
          />
        )}
      />

      <IntelSection
        title="MITRE ATT&CK"
        subtitle="Techniques mapped directly or inferred from the threat description."
        items={intel.attack_techniques}
        renderItem={(technique) => (
          <TechniqueCard key={technique.technique_id} technique={technique} />
        )}
      />

      <IntelSection
        title="CAPEC Attack Patterns"
        subtitle="Attack patterns that help ground abuse cases and expected severity."
        items={intel.attack_patterns}
        renderItem={(pattern) => <PatternCard key={pattern.capec_id} pattern={pattern} />}
      />

      <IntelSection
        title="CWEs"
        subtitle="Underlying weakness classes connected to this threat."
        items={intel.weaknesses}
        renderItem={(weakness) => <WeaknessCard key={weakness.cwe_id} weakness={weakness} />}
      />

      <IntelSection
        title="Advisories"
        subtitle="Relevant external advisories and defensive writeups."
        items={intel.advisories}
        renderItem={(advisory) => (
          <AdvisoryCard key={advisory.advisory_id} advisory={advisory} />
        )}
      />

      <IntelSection
        title="Known Exploited Vulnerabilities"
        subtitle="KEV entries linked by scan CVEs or contextual mappings."
        items={intel.kev_entries}
        renderItem={(kev) => <KevCard key={`${kev.cve_id}-${kev.match_type}`} kev={kev} />}
      />

      <IntelSection
        title="CRI Controls"
        subtitle="Controls mapped from ATT&CK techniques for mitigation planning."
        items={intel.cri_controls}
        renderItem={(control) => (
          <CriCard key={`${control.cri_control_id}-${control.attack_technique_id}`} control={control} />
        )}
      />

      {!hasAnyIntel && (
        <p className="threat-intel-empty">
          No external threat-database matches were found yet. You can still use local severity,
          notes, and AI guidance on this threat.
        </p>
      )}
    </div>
  );
}
