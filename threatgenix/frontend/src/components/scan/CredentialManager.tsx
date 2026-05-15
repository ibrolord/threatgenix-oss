/**
 * CredentialManager — CRUD UI for scan credentials.
 *
 * Rules:
 *  - Secret is WRITE-ONLY: entered on create/rotate, never displayed afterwards.
 *  - List shows name + type + header_name only.
 *  - Delete is immediate (no undo).
 */
import { useState, useEffect, useCallback } from 'react';
import { ScanCredential, ScanCredentialCreate, CredentialType } from '../../types/api';

interface Props {
  threatModelId: string;
  onCredentialsChange?: () => void;
}

const CRED_TYPE_LABELS: Record<CredentialType, string> = {
  bearer_token: 'Bearer Token',
  api_key_header: 'API Key (Header)',
  basic_auth: 'Basic Auth',
  cookie: 'Cookie',
};

const CRED_TYPE_HINTS: Record<CredentialType, string> = {
  bearer_token: 'Injects: Authorization: Bearer <token>',
  api_key_header: 'Injects: <header-name>: <key>',
  basic_auth: 'Secret format: username:password',
  cookie: 'Injects: Cookie: <value>',
};

const token = () => localStorage.getItem('tg_token') ?? '';

export function CredentialManager({ threatModelId, onCredentialsChange }: Props) {
  const [creds, setCreds] = useState<ScanCredential[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState('');
  const [credType, setCredType] = useState<CredentialType>('bearer_token');
  const [headerName, setHeaderName] = useState('');
  const [secret, setSecret] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // rotate: which credential ID is being rotated
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [rotateSecret, setRotateSecret] = useState('');
  const [rotateSaving, setRotateSaving] = useState(false);

  const fetchCreds = useCallback(async () => {
    try {
      const res = await fetch(
        `/api/threat-models/${threatModelId}/scan-credentials`,
        { headers: { Authorization: `Bearer ${token()}` } },
      );
      if (res.ok) setCreds(await res.json());
    } catch {
      // non-blocking
    }
  }, [threatModelId]);

  useEffect(() => { void fetchCreds(); }, [fetchCreds]);

  const resetForm = () => {
    setName(''); setCredType('bearer_token'); setHeaderName(''); setSecret('');
    setError(null); setShowForm(false);
  };

  const createCredential = async () => {
    if (!name.trim() || !secret.trim()) {
      setError('Name and secret are required.');
      return;
    }
    if (credType === 'api_key_header' && !headerName.trim()) {
      setError('Header name is required for API Key type.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const body: ScanCredentialCreate = {
        name: name.trim(),
        credential_type: credType,
        header_name: credType === 'api_key_header' ? headerName.trim() : null,
        secret: secret,
      };
      const res = await fetch(
        `/api/threat-models/${threatModelId}/scan-credentials`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token()}`,
          },
          body: JSON.stringify(body),
        },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => null);
        throw new Error(err?.detail ?? `HTTP ${res.status}`);
      }
      resetForm();
      await fetchCreds();
      onCredentialsChange?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save credential');
    } finally {
      setSaving(false);
    }
  };

  const deleteCredential = async (id: string) => {
    await fetch(
      `/api/threat-models/${threatModelId}/scan-credentials/${id}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${token()}` } },
    );
    await fetchCreds();
    onCredentialsChange?.();
  };

  const rotateCredentialSecret = async (id: string) => {
    if (!rotateSecret.trim()) return;
    setRotateSaving(true);
    try {
      await fetch(
        `/api/threat-models/${threatModelId}/scan-credentials/${id}`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token()}`,
          },
          body: JSON.stringify({ secret: rotateSecret }),
        },
      );
      setRotatingId(null);
      setRotateSecret('');
    } finally {
      setRotateSaving(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#374151' }}>Scan Credentials</span>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            style={{ fontSize: '12px', padding: '4px 10px', background: '#f3f4f6', border: '1px solid #d1d5db', borderRadius: '5px', cursor: 'pointer' }}
          >
            + Add
          </button>
        )}
      </div>

      {/* Create form */}
      {showForm && (
        <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: '8px', padding: '14px', marginBottom: '12px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div>
              <label style={labelStyle}>Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Prod API Key"
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Type</label>
              <select value={credType} onChange={e => setCredType(e.target.value as CredentialType)} style={inputStyle}>
                {(Object.keys(CRED_TYPE_LABELS) as CredentialType[]).map(t => (
                  <option key={t} value={t}>{CRED_TYPE_LABELS[t]}</option>
                ))}
              </select>
              <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '3px' }}>{CRED_TYPE_HINTS[credType]}</div>
            </div>
            {credType === 'api_key_header' && (
              <div>
                <label style={labelStyle}>Header Name</label>
                <input
                  value={headerName}
                  onChange={e => setHeaderName(e.target.value)}
                  placeholder="e.g. X-API-Key"
                  style={inputStyle}
                />
              </div>
            )}
            <div>
              <label style={labelStyle}>Secret</label>
              <input
                type="password"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="Enter secret (write-only)"
                style={inputStyle}
              />
              <div style={{ fontSize: '11px', color: '#9ca3af', marginTop: '2px' }}>
                Never shown again after saving.
              </div>
            </div>
            {error && <div style={{ fontSize: '12px', color: '#dc2626' }}>{error}</div>}
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button onClick={resetForm} style={{ ...btnStyle, background: '#f3f4f6', color: '#374151' }}>
                Cancel
              </button>
              <button
                onClick={createCredential}
                disabled={saving}
                style={{ ...btnStyle, background: '#1d4ed8', color: 'white', opacity: saving ? 0.6 : 1 }}
              >
                {saving ? 'Saving…' : 'Save Credential'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Credential list */}
      {creds.length === 0 && !showForm && (
        <p style={{ fontSize: '12px', color: '#9ca3af', margin: '0' }}>
          No credentials saved. Add one to enable authenticated scans.
        </p>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {creds.map(cred => (
          <div key={cred.id} style={{ background: 'white', border: '1px solid #e5e7eb', borderRadius: '6px', padding: '10px 12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#111827' }}>{cred.name}</div>
                <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '2px' }}>
                  {CRED_TYPE_LABELS[cred.credential_type]}
                  {cred.header_name && ` · header: ${cred.header_name}`}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  onClick={() => { setRotatingId(cred.id); setRotateSecret(''); }}
                  style={{ ...btnStyle, fontSize: '11px', padding: '3px 8px', background: '#f3f4f6', color: '#374151' }}
                >
                  Rotate
                </button>
                <button
                  onClick={() => deleteCredential(cred.id)}
                  style={{ ...btnStyle, fontSize: '11px', padding: '3px 8px', background: '#fef2f2', color: '#dc2626' }}
                >
                  Delete
                </button>
              </div>
            </div>
            {/* Inline rotate form */}
            {rotatingId === cred.id && (
              <div style={{ marginTop: '10px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                <input
                  type="password"
                  value={rotateSecret}
                  onChange={e => setRotateSecret(e.target.value)}
                  placeholder="New secret"
                  style={{ ...inputStyle, flex: 1 }}
                />
                <button
                  onClick={() => rotateCredentialSecret(cred.id)}
                  disabled={rotateSaving || !rotateSecret.trim()}
                  style={{ ...btnStyle, background: '#1d4ed8', color: 'white', opacity: rotateSaving || !rotateSecret.trim() ? 0.6 : 1 }}
                >
                  {rotateSaving ? '…' : 'Save'}
                </button>
                <button
                  onClick={() => { setRotatingId(null); setRotateSecret(''); }}
                  style={{ ...btnStyle, background: '#f3f4f6', color: '#374151' }}
                >
                  ✕
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const labelStyle: React.CSSProperties = { display: 'block', fontSize: '12px', fontWeight: 500, color: '#374151', marginBottom: '4px' };
const inputStyle: React.CSSProperties = { width: '100%', padding: '7px 10px', fontSize: '13px', border: '1px solid #d1d5db', borderRadius: '6px', boxSizing: 'border-box', outline: 'none' };
const btnStyle: React.CSSProperties = { padding: '6px 12px', fontSize: '13px', fontWeight: 500, border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' };
