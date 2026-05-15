import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import { ThreatModelInspectorRail } from "../components/ThreatModelInspectorRail";
import type {
  DFDQualityGateSummary,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";

type ReviewTab =
  | "review"
  | "findings"
  | "compliance"
  | "modelHealth"
  | "report";

function isReviewTab(value: string | null): value is ReviewTab {
  return (
    value === "review" ||
    value === "findings" ||
    value === "compliance" ||
    value === "modelHealth" ||
    value === "report"
  );
}

function repositoryEvidenceSummary(model: ThreatModelResponse): string {
  const repository = model.repository_evidence;
  if (!repository) {
    return "No repository evidence attached";
  }

  const connection = repository.connection;
  const source = connection
    ? `${connection.repository}@${connection.ref || "default branch"}`
    : repository.reference || repository.filename;
  const dfdSeedCount = repository.dfd_seed_suggestions?.length ?? 0;
  const details = [
    `${repository.file_count} files`,
    repository.languages.slice(0, 2).join(", "),
    repository.frameworks.slice(0, 2).join(", "),
    repository.pull_request
      ? `${repository.pull_request.changed_file_count} PR files changed`
      : null,
    dfdSeedCount > 0 ? `${dfdSeedCount} DFD seeds` : null,
  ].filter(Boolean);

  return `Repo evidence captured: ${source}${details.length > 0 ? ` · ${details.join(" · ")}` : ""}`;
}

function SecurityReviewPage() {
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = useMemo<ReviewTab>(() => {
    const nextTab = searchParams.get("tab");
    return isReviewTab(nextTab) ? nextTab : "review";
  }, [searchParams]);

  const [model, setModel] = useState<ThreatModelResponse | null>(null);
  const [threats, setThreats] = useState<ThreatResponse[]>([]);
  const [qualitySummary, setQualitySummary] =
    useState<DFDQualityGateSummary | null>(null);
  const [hasDfdContent, setHasDfdContent] = useState<boolean | null>(null);
  const [qualityLoading, setQualityLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshQualityGates = useCallback(async () => {
    if (!id) return;
    setQualityLoading(true);
    try {
      const summary = await api.getDFDQualityGates(id);
      setQualitySummary(summary);
    } catch {
      setQualitySummary(null);
    } finally {
      setQualityLoading(false);
    }
  }, [id]);

  const handleReviewTabChange = useCallback(
    (nextTab: ReviewTab) => {
      setSearchParams(
        (currentParams) => {
          const nextParams = new URLSearchParams(currentParams);
          if (nextTab === "review") {
            nextParams.delete("tab");
          } else {
            nextParams.set("tab", nextTab);
          }
          return nextParams;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    void Promise.all([
      api.getThreatModel(id),
      api.getThreats(id),
      api.getDFD(id),
    ])
      .then(
        ([nextModel, nextThreats, nextDfd]) => {
          if (cancelled) return;
          setModel(nextModel);
          setThreats(nextThreats);
          setHasDfdContent(
            nextDfd.nodes.length > 0 ||
              nextDfd.edges.length > 0 ||
              nextDfd.trust_boundaries.length > 0,
          );
        },
      )
      .catch((nextError: Error) => {
        if (cancelled) return;
        setError(nextError.message);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    if (!id) return;
    void refreshQualityGates();
  }, [id, refreshQualityGates]);

  if (!id) {
    return (
      <div className="page-loading">
        <span>Threat model not found.</span>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="dfd-spinner" />
        <span>Loading security review…</span>
      </div>
    );
  }

  if (error || !model) {
    const isNotFound = !model || error?.includes("403") || error?.includes("404");
    return (
      <div className="not-found-page">
        <div className="not-found-card">
          <h2 className="not-found-code">{isNotFound ? "404" : "Error"}</h2>
          <h3 className="not-found-title">
            {isNotFound ? "Security review not found" : "Security review failed to load"}
          </h3>
          <p className="not-found-copy">
            {isNotFound
              ? "This review may have been deleted or you may not have access to it."
              : "We could not load this security review. Please try again or return to the dashboard."}
          </p>
          <Link to="/dashboard" className="btn-create not-found-link">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="tm-review-page">
      <section className="tm-review-page-header-card">
        <div className="tm-review-page-header-topline">
          <Link to={`/threat-models/${id}`} className="tm-back-link">
            ← Back to Review Workspace
          </Link>
          <span className="tm-review-page-kicker">Dedicated Workspace</span>
        </div>
        <div className="tm-review-page-heading">
          <div>
            <h2>Security Review</h2>
            <p>
              Work through findings, compliance evidence, model health, and
              grounded copilot actions without squeezing the workflow into the
              inspector rail.
            </p>
          </div>
          <div className="tm-review-page-meta">
            <strong>{model.system_name}</strong>
            <span>{threats.length} findings in current review scope</span>
            <span>{repositoryEvidenceSummary(model)}</span>
          </div>
        </div>
      </section>

      <ThreatModelInspectorRail
        threatModelId={id}
        model={model}
        threats={threats}
        layout="page"
        initialTab={initialTab}
        onTabChange={handleReviewTabChange}
        initialSummary={null}
        initialFindingsResponse={null}
        queuedAssistantRequest={null}
        qualitySummary={qualitySummary}
        qualityLoading={qualityLoading}
        hasDfdContent={hasDfdContent}
        pendingAssumptionAnchor={null}
        onPendingAnchorConsumed={() => {}}
        onThreatUpdated={(nextThreat) =>
          setThreats((current) =>
            current.map((item) =>
              item.id === nextThreat.id ? nextThreat : item,
            ),
          )
        }
      />
    </div>
  );
}

export default SecurityReviewPage;
