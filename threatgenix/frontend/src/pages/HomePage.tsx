import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { ThreatModelListItem, ThreatModelResponse } from "../types/api";
import { api } from "../api/client";
import IntakeForm from "../components/IntakeForm";

function HomePage() {
  const [models, setModels] = useState<ThreatModelListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .getThreatModels()
      .then(setModels)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  function handleSuccess(model: ThreatModelResponse) {
    navigate(`/threat-models/${model.id}/review`);
  }

  if (loading) return <p>Loading security reviews...</p>;
  if (error) return <p className="error">Failed to load reviews: {error}</p>;

  return (
    <div style={{ maxWidth: "720px", margin: "0 auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <h2 style={{ margin: 0 }}>Start Security Review</h2>
        {showForm ? (
          <button
            onClick={() => setShowForm(false)}
            style={{
              background: "transparent",
              border: "1px solid #94a3b8",
              color: "#64748b",
              padding: "6px 16px",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "0.875rem",
            }}
          >
            Cancel
          </button>
        ) : (
          <button className="btn-create" onClick={() => setShowForm(true)}>
            Start New Review
          </button>
        )}
      </div>
      {showForm && <IntakeForm onSuccess={handleSuccess} />}
      {!showForm && models.length === 0 && (
        <p style={{ color: "#64748b" }}>No security reviews yet. Start with a repo, PR, architecture document, or formal review scope.</p>
      )}
      {!showForm && models.length > 0 && (
        <ul className="model-list">
          {models.map((m) => (
            <li key={m.id}>
              <Link to={`/threat-models/${m.id}`}>
                <strong>{m.system_name}</strong> — {m.data_classification}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default HomePage;
