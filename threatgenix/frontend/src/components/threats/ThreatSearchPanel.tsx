import { useState, useEffect, useRef, useCallback } from "react";
import type { DFDNodeResponse, ThreatCatalogEntry, ThreatResponse } from "../../types/api";
import { api } from "../../api/client";

const STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
] as const;

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#22c55e",
};

interface ThreatSearchPanelProps {
  threatModelId: string;
  onThreatAdded: (threat: ThreatResponse) => void;
}

export function ThreatSearchPanel({ threatModelId, onThreatAdded }: ThreatSearchPanelProps) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"catalog" | "custom">("catalog");
  const [query, setQuery] = useState("");
  const [strideFilter, setStrideFilter] = useState<string | null>(null);
  const [catalog, setCatalog] = useState<ThreatCatalogEntry[]>([]);
  const [nodes, setNodes] = useState<DFDNodeResponse[]>([]);
  const [nodesLoading, setNodesLoading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [addingId, setAddingId] = useState<string | null>(null);
  const [addedIds, setAddedIds] = useState<Set<string>>(new Set());
  const [customSubtype, setCustomSubtype] = useState("");
  const [customDescription, setCustomDescription] = useState("");
  const [customSeverity, setCustomSeverity] = useState("Medium");
  const [customStrideCategory, setCustomStrideCategory] = useState<string>("Tampering");
  const [customAffectedNodeIds, setCustomAffectedNodeIds] = useState<Set<string>>(new Set());
  const [customSaving, setCustomSaving] = useState(false);
  const [customError, setCustomError] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchCatalog = useCallback(async (q: string, stride: string | null) => {
    setLoading(true);
    try {
      const results = await api.getThreatCatalog(q || undefined, stride || undefined);
      setCatalog(results);
    } catch {
      // Silent failure — catalog is non-critical
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchNodes = useCallback(async () => {
    setNodesLoading(true);
    try {
      const dfd = await api.getDFD(threatModelId);
      setNodes(dfd.nodes);
    } catch {
      setNodes([]);
    } finally {
      setNodesLoading(false);
    }
  }, [threatModelId]);

  // Initial load when panel opens
  useEffect(() => {
    if (open) {
      fetchCatalog(query, strideFilter);
      void fetchNodes();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Debounced search
  useEffect(() => {
    if (!open) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      fetchCatalog(query, strideFilter);
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, strideFilter, open, fetchCatalog]);

  const handleAdd = async (entry: ThreatCatalogEntry) => {
    setAddingId(entry.rule_id);
    try {
      const threat = await api.createManualThreat(threatModelId, {
        rule_id: entry.rule_id,
      });
      onThreatAdded(threat);
      setAddedIds((prev) => new Set(prev).add(entry.rule_id));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to add threat";
      alert(msg);
    } finally {
      setAddingId(null);
    }
  };

  const handleToggleCustomNode = (nodeId: string) => {
    setCustomAffectedNodeIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  };

  const handleCreateCustomThreat = async () => {
    const subtype = customSubtype.trim();
    const description = customDescription.trim();

    if (!subtype) {
      setCustomError("A short threat title is required.");
      return;
    }
    if (!description) {
      setCustomError("A threat description is required.");
      return;
    }

    setCustomSaving(true);
    setCustomError(null);
    try {
      const threat = await api.createManualThreat(threatModelId, {
        threat_subtype: subtype,
        description,
        severity: customSeverity,
        stride_category: customStrideCategory,
        affected_node_ids: Array.from(customAffectedNodeIds),
      });
      onThreatAdded(threat);
      setCustomSubtype("");
      setCustomDescription("");
      setCustomSeverity("Medium");
      setCustomStrideCategory("Tampering");
      setCustomAffectedNodeIds(new Set());
      setMode("catalog");
    } catch (e) {
      setCustomError(e instanceof Error ? e.message : "Failed to create custom threat");
    } finally {
      setCustomSaving(false);
    }
  };

  return (
    <div className="threat-search-panel">
      <button
        className="threat-search-toggle"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        title={open ? "Hide the threat catalog and custom threat form" : "Browse the threat catalog or add a custom threat"}
      >
        {open ? "Hide Threat Catalog" : "Browse & Add Threats"}
        <span className="threat-search-toggle-icon">{open ? "\u25B2" : "\u25BC"}</span>
      </button>

      {open && (
        <div className="threat-search-body">
          <div className="threat-search-mode-toggle" role="tablist" aria-label="Threat creation mode">
            <button
              type="button"
              className={`threat-search-mode-btn ${mode === "catalog" ? "threat-search-mode-btn-active" : ""}`}
              onClick={() => setMode("catalog")}
              title="Browse reusable catalog threats and add them to the current model"
            >
              Catalog
            </button>
            <button
              type="button"
              className={`threat-search-mode-btn ${mode === "custom" ? "threat-search-mode-btn-active" : ""}`}
              onClick={() => setMode("custom")}
              title="Author a one-off custom threat directly in this model"
            >
              Custom
            </button>
          </div>

          {mode === "catalog" ? (
            <>
              <input
                type="text"
                className="threat-search-input"
                placeholder="Search threats... (e.g. encryption, spoofing, injection)"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                autoFocus
                title="Search the built-in threat catalog by keyword"
              />

              <div className="stride-filter" style={{ marginTop: 8 }}>
                <button
                  className={`stride-filter-pill ${strideFilter === null ? "stride-filter-pill-active" : ""}`}
                  onClick={() => setStrideFilter(null)}
                  title="Show all STRIDE categories"
                >
                  All
                </button>
                {STRIDE_CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    className={`stride-filter-pill ${strideFilter === cat ? "stride-filter-pill-active" : ""}`}
                    onClick={() => setStrideFilter(strideFilter === cat ? null : cat)}
                    title={`Filter the catalog to ${cat} threats`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              <div className="threat-catalog-results">
                {loading && (
                  <div className="threat-catalog-loading">
                    <div className="dfd-spinner" style={{ width: 20, height: 20 }} />
                    <span>Loading catalog...</span>
                  </div>
                )}

                {!loading && catalog.length === 0 && (
                  <p className="threat-catalog-empty">No matching threats found.</p>
                )}

                {!loading &&
                  catalog.map((entry) => (
                    <div key={entry.rule_id} className="threat-catalog-card">
                      <div className="threat-catalog-card-header">
                        <span className="threat-catalog-rule-id">{entry.rule_id}</span>
                        <span
                          className="threat-catalog-severity"
                          style={{ color: SEVERITY_COLORS[entry.severity] ?? "#888" }}
                        >
                          {entry.severity}
                        </span>
                        <span className="threat-catalog-stride">{entry.stride_category}</span>
                      </div>
                      <div className="threat-catalog-subtype">{entry.threat_subtype}</div>
                      <p className="threat-catalog-desc">{entry.description_template}</p>
                      <button
                        className="threat-catalog-add-btn"
                        onClick={() => handleAdd(entry)}
                        disabled={addingId === entry.rule_id || addedIds.has(entry.rule_id)}
                        title={`Add ${entry.rule_id} to the current threat model`}
                      >
                        {addedIds.has(entry.rule_id)
                          ? "Added"
                          : addingId === entry.rule_id
                            ? "Adding..."
                            : "Add to Model"}
                      </button>
                    </div>
                  ))}
              </div>
            </>
          ) : (
            <div className="threat-custom-form">
              <div className="threat-custom-grid">
                <label className="threat-custom-field">
                  <span>Threat Title</span>
                  <input
                    type="text"
                    className="threat-search-input"
                    placeholder="e.g. Treasury approval bypass"
                    value={customSubtype}
                    onChange={(event) => setCustomSubtype(event.target.value)}
                    autoFocus
                  />
                </label>

                <label className="threat-custom-field">
                  <span>STRIDE Category</span>
                  <select
                    className="threat-custom-select"
                    value={customStrideCategory}
                    onChange={(event) => setCustomStrideCategory(event.target.value)}
                  >
                    {STRIDE_CATEGORIES.map((category) => (
                      <option key={category} value={category}>
                        {category}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="threat-custom-field">
                  <span>Severity</span>
                  <select
                    className="threat-custom-select"
                    value={customSeverity}
                    onChange={(event) => setCustomSeverity(event.target.value)}
                  >
                    {["Critical", "High", "Medium", "Low"].map((severity) => (
                      <option key={severity} value={severity}>
                        {severity}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <label className="threat-custom-field">
                <span>Description</span>
                <textarea
                  className="threat-custom-textarea"
                  placeholder="Describe the abuse case, attacker action, and impacted workflow."
                  value={customDescription}
                  onChange={(event) => setCustomDescription(event.target.value)}
                  rows={4}
                />
              </label>

              <div className="threat-custom-field">
                <span>Affected Nodes</span>
                <p className="threat-custom-hint">
                  Select the components this custom threat applies to. Leave blank if it is broader than a single node.
                </p>
                <div className="threat-custom-node-list">
                  {nodesLoading ? (
                    <div className="threat-custom-node-empty">Loading DFD nodes…</div>
                  ) : nodes.length === 0 ? (
                    <div className="threat-custom-node-empty">No components found. Upload an architecture document or add components manually to begin threat modeling.</div>
                  ) : (
                    nodes.map((node) => (
                      <label key={node.id} className="threat-custom-node-option">
                        <input
                          type="checkbox"
                          checked={customAffectedNodeIds.has(node.id)}
                          onChange={() => handleToggleCustomNode(node.id)}
                        />
                        <span>{node.name}</span>
                      </label>
                    ))
                  )}
                </div>
              </div>

              {customError && <p className="threat-custom-error">{customError}</p>}

              <div className="threat-custom-actions">
                <button
                  type="button"
                  className="threat-catalog-add-btn"
                  onClick={handleCreateCustomThreat}
                  disabled={customSaving}
                  title="Create a custom threat directly in this model"
                >
                  {customSaving ? "Creating..." : "Add Custom Threat"}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
