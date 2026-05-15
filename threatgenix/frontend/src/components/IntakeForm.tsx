import { useMemo, useState } from "react";
import type {
  DeploymentModel,
  RegulatoryFramework,
  ThreatModelCreate,
  ThreatModelResponse,
} from "../types/api";
import { api } from "../api/client";

interface IntakeFormProps {
  onSuccess: (model: ThreatModelResponse) => void;
}

interface GitHubReviewTarget {
  repository: string;
  ref?: string;
  reference?: string;
  pullRequestNumber?: number;
  pullRequestUrl?: string;
}

const REGULATORY_FRAMEWORKS: { value: RegulatoryFramework; label: string }[] = [
  { value: "OSFI B-13", label: "OSFI B-13 (Technology & Cyber Risk)" },
  { value: "PCI DSS", label: "PCI DSS (Payment Card Industry)" },
  { value: "PIPEDA", label: "PIPEDA (Personal Information Protection)" },
  { value: "FINTRAC", label: "FINTRAC (Anti-Money Laundering)" },
  { value: "NIST", label: "NIST Cybersecurity Framework" },
  { value: "ISO 27001", label: "ISO 27001 (Information Security)" },
];

const DEPLOYMENT_MODELS: { value: DeploymentModel; label: string }[] = [
  { value: "cloud", label: "Cloud" },
  { value: "on-prem", label: "On-Premises" },
  { value: "hybrid", label: "Hybrid" },
];
const REVIEW_INTENTS = [
  "Repo/Application Review",
  "Pull Request Review",
  "Customer Security Review",
  "Formal Threat Model",
  "Cloud/IaC Change Review",
] as const;
const DESCRIPTION_MAX_LENGTH = 500;

function parseGitHubReviewTarget(rawTarget: string, rawRef: string): GitHubReviewTarget | null {
  const target = rawTarget.trim();
  const ref = rawRef.trim();
  if (!target) {
    return null;
  }

  const githubUrlMatch = target.match(
    /^https?:\/\/(?:www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+)(?:\/pull\/(\d+))?/i,
  );
  if (githubUrlMatch) {
    const [, owner, repoName, pullNumber] = githubUrlMatch;
    const cleanRepo = repoName!.replace(/\.git$/i, "");
    if (pullNumber && !ref) {
      return {
        repository: `${owner}/${cleanRepo}`,
        ref: `refs/pull/${pullNumber}/head`,
        reference: `Pull request #${pullNumber}`,
        pullRequestNumber: Number(pullNumber),
        pullRequestUrl: `https://github.com/${owner}/${cleanRepo}/pull/${pullNumber}`,
      };
    }
    return {
      repository: `${owner}/${cleanRepo}`,
      ref: ref || undefined,
      reference: pullNumber ? `Pull request #${pullNumber}` : undefined,
      pullRequestNumber: pullNumber ? Number(pullNumber) : undefined,
      pullRequestUrl: pullNumber
        ? `https://github.com/${owner}/${cleanRepo}/pull/${pullNumber}`
        : undefined,
    };
  }

  const slugMatch = target.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (!slugMatch) {
    return {
      repository: target,
      ref: ref || undefined,
    };
  }

  return {
    repository: `${slugMatch[1]!}/${slugMatch[2]!.replace(/\.git$/i, "")}`,
    ref: ref || undefined,
  };
}

function IntakeForm({ onSuccess }: IntakeFormProps) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdModel, setCreatedModel] = useState<ThreatModelResponse | null>(null);
  const [selectedFrameworks, setSelectedFrameworks] = useState<RegulatoryFramework[]>([]);
  const [reviewIntent, setReviewIntent] = useState<(typeof REVIEW_INTENTS)[number]>(
    REVIEW_INTENTS[0],
  );
  const [githubToken, setGithubToken] = useState("");
  const [descriptionLength, setDescriptionLength] = useState(0);
  const totalSummaryLength =
    reviewIntent.length + (descriptionLength > 0 ? 2 : 0) + descriptionLength;
  const showRepositoryTarget = useMemo(
    () =>
      reviewIntent === "Repo/Application Review" ||
      reviewIntent === "Pull Request Review",
    [reviewIntent],
  );

  function toggleFramework(fw: RegulatoryFramework) {
    setSelectedFrameworks((prev) =>
      prev.includes(fw) ? prev.filter((f) => f !== fw) : [...prev, fw]
    );
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setCreatedModel(null);
    setSubmitting(true);

    const form = e.currentTarget;
    const formData = new FormData(form);
    const deploymentModel = formData.get("deployment_model") as string;
    const reviewIntent =
      ((formData.get("review_intent") as string) || REVIEW_INTENTS[0]).trim();
    const description = ((formData.get("description") as string) || "").trim();
    const repositoryTarget = parseGitHubReviewTarget(
      (formData.get("repository_target") as string) || "",
      (formData.get("repository_ref") as string) || "",
    );
    const oneTimeGitHubToken = githubToken.trim();
    const scopedDescription = description
      ? `${reviewIntent}: ${description}`
      : reviewIntent;

    if (scopedDescription.length > DESCRIPTION_MAX_LENGTH) {
      setError(
        `Review summary must be ${DESCRIPTION_MAX_LENGTH} characters or fewer. Add full architecture detail through evidence upload after starting the review.`
      );
      setSubmitting(false);
      return;
    }

    const data: ThreatModelCreate = {
      system_name: formData.get("system_name") as string,
      description: scopedDescription,
      data_classification: formData.get("data_classification") as ThreatModelCreate["data_classification"],
      regulatory_scope: selectedFrameworks.length > 0 ? selectedFrameworks : undefined,
      deployment_model: deploymentModel ? (deploymentModel as DeploymentModel) : null,
    };

    try {
      const model = await api.createThreatModel(data);
      if (!repositoryTarget) {
        onSuccess(model);
        return;
      }

      try {
        const evidence = await api.importRepositoryEvidenceFromGitHub(model.id, {
          repository: repositoryTarget.repository,
          ref: repositoryTarget.ref,
          reference: repositoryTarget.reference ?? reviewIntent,
          pull_request_number: repositoryTarget.pullRequestNumber,
          pull_request_url: repositoryTarget.pullRequestUrl,
        }, oneTimeGitHubToken || undefined);
        setGithubToken("");
        onSuccess({ ...model, ...evidence });
      } catch (repoError: unknown) {
        setGithubToken("");
        const message =
          repoError instanceof Error ? repoError.message : "Repository ingestion failed";
        setCreatedModel(model);
        setError(
          `Review was created, but repository evidence could not be imported: ${message}. Re-enter the token in Environment Setup or open the review without repository evidence.`
        );
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "An unexpected error occurred";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="intake-form" onSubmit={handleSubmit}>
      <div className="form-field">
        <label htmlFor="system_name">Application or PR Name</label>
        <input
          id="system_name"
          name="system_name"
          type="text"
          required
          maxLength={255}
          placeholder="e.g., Online Banking Portal"
        />
      </div>
      <div className="form-field">
        <label htmlFor="review_intent">Review Goal</label>
        <select
          id="review_intent"
          name="review_intent"
          value={reviewIntent}
          onChange={(event) =>
            setReviewIntent(event.currentTarget.value as (typeof REVIEW_INTENTS)[number])
          }
        >
          {REVIEW_INTENTS.map((intent) => (
            <option key={intent} value={intent}>
              {intent}
            </option>
          ))}
        </select>
      </div>
      {showRepositoryTarget && (
        <div className="form-field">
          <label htmlFor="repository_target">GitHub Repo or PR</label>
          <input
            id="repository_target"
            name="repository_target"
            type="text"
            placeholder="owner/repo or https://github.com/owner/repo/pull/123"
          />
          <p className="form-hint" style={{ margin: "6px 0 0", fontSize: "0.8rem", color: "#64748b" }}>
            Public repos import without a token. Private repo tokens are used once for intake and are not stored.
          </p>
        </div>
      )}
      {showRepositoryTarget && (
        <div className="form-field">
          <label htmlFor="repository_ref">Branch, Tag, or Commit</label>
          <input
            id="repository_ref"
            name="repository_ref"
            type="text"
            placeholder="main, release/v1, or commit SHA"
          />
        </div>
      )}
      {showRepositoryTarget && (
        <div className="form-field">
          <label htmlFor="github_token">GitHub Access Token</label>
          <input
            id="github_token"
            name="github_token"
            type="password"
            autoComplete="off"
            value={githubToken}
            onChange={(event) => setGithubToken(event.currentTarget.value)}
            placeholder="Optional for private repositories"
          />
          <p className="form-hint" style={{ margin: "6px 0 0", fontSize: "0.8rem", color: "#64748b" }}>
            Fine-grained read-only repository tokens work best. The token is not saved with the review.
          </p>
        </div>
      )}
      <div className="form-field">
        <label htmlFor="description">Review Summary</label>
        <textarea
          id="description"
          name="description"
          maxLength={DESCRIPTION_MAX_LENGTH}
          aria-describedby="description-helper"
          onChange={(event) => setDescriptionLength(event.currentTarget.value.length)}
          placeholder="Describe what must be reviewed and the decision you need..."
          rows={3}
        />
        <div id="description-helper" className="form-hint-row">
          <span>
            Keep this summary under 500 characters including the review goal. Upload full evidence after starting the review.
          </span>
          <span>
            {totalSummaryLength}/{DESCRIPTION_MAX_LENGTH}
          </span>
        </div>
      </div>
      <div className="form-field">
        <label htmlFor="data_classification">Data Classification</label>
        <select id="data_classification" name="data_classification" defaultValue="Confidential">
          <option value="Public">Public</option>
          <option value="Internal">Internal</option>
          <option value="Confidential">Confidential</option>
          <option value="Restricted">Restricted</option>
        </select>
      </div>
      <div className="form-field">
        <label>Regulatory Scope</label>
        <p className="form-hint" style={{ margin: "0 0 8px", fontSize: "0.8rem", color: "#64748b" }}>
          Select applicable frameworks to shape evidence and control expectations.
        </p>
        <div className="checkbox-group">
          {REGULATORY_FRAMEWORKS.map((fw) => (
            <label key={fw.value} className="checkbox-label">
              <input
                type="checkbox"
                checked={selectedFrameworks.includes(fw.value)}
                onChange={() => toggleFramework(fw.value)}
              />
              {fw.label}
            </label>
          ))}
        </div>
      </div>
      <div className="form-field">
        <label htmlFor="deployment_model">Deployment Model</label>
        <select id="deployment_model" name="deployment_model" defaultValue="">
          <option value="">Not specified</option>
          {DEPLOYMENT_MODELS.map((dm) => (
            <option key={dm.value} value={dm.value}>
              {dm.label}
            </option>
          ))}
        </select>
      </div>
      {error && <p className="form-error">{error}</p>}
      {createdModel && (
        <button
          type="button"
          className="btn-export"
          onClick={() => onSuccess(createdModel)}
          style={{ width: "100%", marginTop: "8px", padding: "10px 0", fontSize: "0.95rem" }}
        >
          Open Review Without Repository Evidence
        </button>
      )}
      <button type="submit" className="btn-create" disabled={submitting} style={{ width: "100%", marginTop: "8px", padding: "10px 0", fontSize: "0.95rem" }}>
        {submitting ? "Starting..." : "Start Security Review"}
      </button>
    </form>
  );
}

export default IntakeForm;
