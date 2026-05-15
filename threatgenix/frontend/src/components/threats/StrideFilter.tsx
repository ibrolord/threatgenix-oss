import type { ThreatResponse } from "../../types/api";

interface StrideFilterProps {
  threats: ThreatResponse[];
  activeFilter: string | null;
  onFilterChange: (category: string | null) => void;
}

const STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
] as const;

export function StrideFilter({ threats, activeFilter, onFilterChange }: StrideFilterProps) {
  const counts = new Map<string, number>();
  for (const t of threats) {
    counts.set(t.stride_category, (counts.get(t.stride_category) ?? 0) + 1);
  }

  return (
    <div className="stride-filter">
      <button
        className={`stride-filter-pill ${activeFilter === null ? "stride-filter-pill-active" : ""}`}
        onClick={() => onFilterChange(null)}
      >
        All ({threats.length})
      </button>
      {STRIDE_CATEGORIES.map((cat) => (
        <button
          key={cat}
          className={`stride-filter-pill ${activeFilter === cat ? "stride-filter-pill-active" : ""}`}
          onClick={() => onFilterChange(activeFilter === cat ? null : cat)}
        >
          {cat} ({counts.get(cat) ?? 0})
        </button>
      ))}
    </div>
  );
}
