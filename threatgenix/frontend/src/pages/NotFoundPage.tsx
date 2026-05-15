import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="not-found-page">
      <div className="not-found-card">
        <h2 className="not-found-code">404</h2>
        <h3 className="not-found-title">Page not found</h3>
        <p className="not-found-copy">
          The page you are looking for does not exist or has been moved.
        </p>
        <Link to="/dashboard" className="btn-create not-found-link">
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
