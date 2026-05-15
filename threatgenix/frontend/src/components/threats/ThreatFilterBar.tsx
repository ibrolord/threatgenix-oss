import type { ThreatResponse, ThreatScanStatus } from "../../types/api";

export interface ThreatFilters {
  stride: string | null;
  severity: string | null;
  status: string | null;
  source: string | null;
  scanStatus: ThreatScanStatus | "unscanned" | null;
  notes: "with_notes" | null;
  search: string | null;
}

interface ThreatFilterBarProps {
  threats: ThreatResponse[];
  filters: ThreatFilters;
  visibleCount: number;
  onChange: (filters: ThreatFilters) => void;
}

const STRIDE_OPTIONS = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
] as const;

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"] as const;
const STATUS_OPTIONS = ["Open", "In Progress", "Mitigated", "Accepted", "Dismissed"] as const;
const SOURCE_OPTIONS = ["Rules", "AI", "AI+Rules", "Manual"] as const;
const SCAN_OPTIONS: Array<{ value: ThreatFilters["scanStatus"]; label: string }> = [
  { value: "confirmed", label: "Confirmed" },
  { value: "mitigated", label: "Mitigated" },
  { value: "not_found", label: "Not Found" },
  { value: "unverifiable", label: "Unverifiable" },
  { value: "unscanned", label: "No verdict" },
];

function threatHasNotes(threat: ThreatResponse): boolean {
  return Boolean(
    threat.mitigation_notes?.trim() ||
      threat.mitigation_plan?.trim() ||
      threat.dismiss_reason?.trim()
  );
}

function countBy<T extends string>(
  threats: ThreatResponse[],
  getValue: (threat: ThreatResponse) => T | null | undefined
): Map<T, number> {
  const counts = new Map<T, number>();
  for (const threat of threats) {
    const value = getValue(threat);
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function optionLabel(label: string, count: number): string {
  return `${label} (${count})`;
}

export function ThreatFilterBar({
  threats,
  filters,
  visibleCount,
  onChange,
}: ThreatFilterBarProps) {
  const strideCounts = countBy(threats, (threat) => threat.stride_category);
  const severityCounts = countBy(threats, (threat) => threat.severity);
  const statusCounts = countBy(threats, (threat) => threat.status);
  const sourceCounts = countBy(threats, (threat) => threat.source);
  const scanCounts = countBy(threats, (threat) => threat.scan_status ?? "unscanned");
  const notesCount = threats.filter(threatHasNotes).length;

  const updateFilter = <K extends keyof ThreatFilters>(key: K, value: ThreatFilters[K]) => {
    onChange({
      ...filters,
      [key]: value,
    });
  };

  const hasActiveFilters = Object.values(filters).some((value) => value !== null);

  return (
    <div className="threat-filter-bar">
      <div className="threat-filter-bar-header">
        <div>
          <div className="threat-filter-bar-title">Show only</div>
          <div className="threat-filter-bar-subtitle">
            {visibleCount} of {threats.length} threats visible
          </div>
        </div>
        <button
          type="button"
          className="threat-filter-clear"
          onClick={() =>
            onChange({
              stride: null,
              severity: null,
              status: null,
              source: null,
              scanStatus: null,
              notes: null,
              search: null,
            })
          }
          disabled={!hasActiveFilters}
        >
          Clear filters
        </button>
      </div>

      <div className="threat-filter-search">
        <input
          type="search"
          placeholder="Search threats, ATT&CK IDs, rule IDs…"
          value={filters.search ?? ""}
          onChange={(event) => updateFilter("search", event.target.value || null)}
          className="threat-filter-search-input"
        />
      </div>

      <div className="threat-filter-grid">
        <label className="threat-filter-field">
          <span>STRIDE</span>
          <select
            value={filters.stride ?? ""}
            onChange={(event) => updateFilter("stride", event.target.value || null)}
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            {STRIDE_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {optionLabel(option, strideCounts.get(option) ?? 0)}
              </option>
            ))}
          </select>
        </label>

        <label className="threat-filter-field">
          <span>Severity</span>
          <select
            value={filters.severity ?? ""}
            onChange={(event) => updateFilter("severity", event.target.value || null)}
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            {SEVERITY_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {optionLabel(option, severityCounts.get(option) ?? 0)}
              </option>
            ))}
          </select>
        </label>

        <label className="threat-filter-field">
          <span>Status</span>
          <select
            value={filters.status ?? ""}
            onChange={(event) => updateFilter("status", event.target.value || null)}
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            {STATUS_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {optionLabel(option, statusCounts.get(option) ?? 0)}
              </option>
            ))}
          </select>
        </label>

        <label className="threat-filter-field">
          <span>Source</span>
          <select
            value={filters.source ?? ""}
            onChange={(event) => updateFilter("source", event.target.value || null)}
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            {SOURCE_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {optionLabel(option, sourceCounts.get(option) ?? 0)}
              </option>
            ))}
          </select>
        </label>

        <label className="threat-filter-field">
          <span>Scan</span>
          <select
            value={filters.scanStatus ?? ""}
            onChange={(event) =>
              updateFilter(
                "scanStatus",
                (event.target.value as ThreatFilters["scanStatus"]) || null
              )
            }
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            {SCAN_OPTIONS.map((option) => (
              <option key={option.value} value={option.value ?? ""}>
                {optionLabel(option.label, scanCounts.get(option.value ?? "unscanned") ?? 0)}
              </option>
            ))}
          </select>
        </label>

        <label className="threat-filter-field">
          <span>Notes</span>
          <select
            value={filters.notes ?? ""}
            onChange={(event) =>
              updateFilter("notes", (event.target.value as ThreatFilters["notes"]) || null)
            }
          >
            <option value="">{threats.length > 0 ? `All (${threats.length})` : "All"}</option>
            <option value="with_notes">{optionLabel("With notes", notesCount)}</option>
          </select>
        </label>
      </div>
    </div>
  );
}
