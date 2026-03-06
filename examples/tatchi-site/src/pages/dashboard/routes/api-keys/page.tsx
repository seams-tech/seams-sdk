import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardApiKey,
  listDashboardApiKeys,
  revokeDashboardApiKey,
  rotateDashboardApiKey,
  type DashboardConsoleApiKey,
} from './consoleApiKeysApi';

const DEFAULT_SCOPES = 'wallets:read,billing:read';
const API_KEY_SCOPE_PRESETS = [
  {
    key: 'registration',
    label: 'Registration bootstrap',
    description: 'Scopes for /registration/bootstrap',
    scopes: ['accounts.create', 'accounts.sync'],
  },
  {
    key: 'console-readonly',
    label: 'Console readonly',
    description: 'Read-only wallet and billing console access',
    scopes: ['wallets:read', 'billing:read'],
  },
  {
    key: 'session-refresh',
    label: 'Session refresh',
    description: 'Scope for session refresh operations',
    scopes: ['sessions.refresh'],
  },
] as const;

function parseCsvValues(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const piece of String(raw || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)) {
    const key = piece.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(piece);
  }
  return out;
}

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function buildRegistrationBootstrapSnippet(secret: string, environmentId: string): string {
  const envScope = String(environmentId || '').trim() || '<environment-id>';
  return [
    "curl -X POST \"$RELAYER_URL/registration/bootstrap\" \\",
    `  -H "Authorization: Bearer ${secret}" \\`,
    `  -H "X-Tatchi-Environment-Id: ${envScope}" \\`,
    '  -H "Content-Type: application/json" \\',
    '  -d \'{',
    '    "new_account_id": "alice.testnet",',
    '    "rp_id": "localhost",',
    '    "account": { "type": "passkey" }',
    "  }'",
  ].join('\n');
}

export function ApiKeyManagementPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedEnvironmentId = String(selectedContext.environment || '').trim();
  const [apiKeys, setApiKeys] = React.useState<DashboardConsoleApiKey[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [creating, setCreating] = React.useState<boolean>(false);
  const [busyApiKeyId, setBusyApiKeyId] = React.useState<string>('');
  const [nameInput, setNameInput] = React.useState<string>('');
  const [scopesInput, setScopesInput] = React.useState<string>(DEFAULT_SCOPES);
  const [ipAllowlistInput, setIpAllowlistInput] = React.useState<string>('');
  const [environmentInput, setEnvironmentInput] = React.useState<string>('');
  const [revealedSecret, setRevealedSecret] = React.useState<{
    action: 'created' | 'rotated';
    keyId: string;
    secret: string;
  } | null>(null);
  const [copySecretStatus, setCopySecretStatus] = React.useState<string>('');

  React.useEffect(() => {
    if (!selectedEnvironmentId) return;
    setEnvironmentInput(selectedEnvironmentId);
  }, [selectedEnvironmentId]);

  const loadApiKeys = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setApiKeys([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardApiKeys()
      .then((next) => {
        if (cancelled) return;
        setApiKeys(next);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setApiKeys([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadApiKeys();
    return cleanup;
  }, [loadApiKeys, session.loading]);

  const visibleApiKeys = React.useMemo(() => {
    const filtered = selectedEnvironmentId
      ? apiKeys.filter((entry) => entry.environmentId === selectedEnvironmentId)
      : apiKeys;
    return [...filtered].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [apiKeys, selectedEnvironmentId]);

  const onCreateApiKey = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const name = String(nameInput || '').trim();
      const scopes = parseCsvValues(scopesInput);
      const ipAllowlist = parseCsvValues(ipAllowlistInput);
      const environmentId = String(selectedEnvironmentId || environmentInput || '').trim();
      if (!name) {
        setMutationError('Name is required.');
        return;
      }
      if (!environmentId) {
        setMutationError('Environment ID is required.');
        return;
      }
      if (scopes.length === 0) {
        setMutationError('At least one scope is required.');
        return;
      }
      setCreating(true);
      setMutationError('');
      try {
        const created = await createDashboardApiKey({
          name,
          environmentId,
          scopes,
          ...(ipAllowlist.length > 0 ? { ipAllowlist } : {}),
        });
        setRevealedSecret({
          action: 'created',
          keyId: created.apiKey.id,
          secret: created.secret,
        });
        setNameInput('');
        setIpAllowlistInput('');
        setScopesInput(DEFAULT_SCOPES);
        setCopySecretStatus('');
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreating(false);
      }
    },
    [
      environmentInput,
      ipAllowlistInput,
      loadApiKeys,
      nameInput,
      scopesInput,
      selectedEnvironmentId,
      session.claims,
      session.errorMessage,
    ],
  );

  const onRotateApiKey = React.useCallback(
    async (apiKeyId: string) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setBusyApiKeyId(apiKeyId);
      setMutationError('');
      try {
        const rotated = await rotateDashboardApiKey({
          apiKeyId,
          reason: 'dashboard manual rotation',
        });
        setRevealedSecret({
          action: 'rotated',
          keyId: rotated.apiKey.id,
          secret: rotated.secret,
        });
        setCopySecretStatus('');
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyApiKeyId('');
      }
    },
    [loadApiKeys, session.claims, session.errorMessage],
  );

  const onRevokeApiKey = React.useCallback(
    async (apiKeyId: string) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!window.confirm(`Revoke API key ${apiKeyId}? This cannot be undone.`)) return;
      setBusyApiKeyId(apiKeyId);
      setMutationError('');
      try {
        await revokeDashboardApiKey({ apiKeyId });
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyApiKeyId('');
      }
    },
    [loadApiKeys, session.claims, session.errorMessage],
  );

  return (
    <div className="dashboard-view" aria-label="API key management page">
      <section className="dashboard-view__section" aria-label="API key controls">
        <h2>Create API key</h2>
        <p>
          {selectedEnvironmentId
            ? `Context scope: environment ${selectedEnvironmentId}.`
            : 'No environment selected in topbar. Provide environment ID manually.'}
        </p>

        {revealedSecret ? (
          <div className="dashboard-secret-banner">
            <p>
              Secret {revealedSecret.action} for <strong>{revealedSecret.keyId}</strong> (shown once):
              {' '}
              <code>{revealedSecret.secret}</code>
            </p>
            <div className="dashboard-form-actions">
              <button
                type="button"
                className="dashboard-pagination-button"
                onClick={async () => {
                  try {
                    await window.navigator?.clipboard?.writeText(revealedSecret.secret);
                    setCopySecretStatus('Secret copied to clipboard.');
                  } catch {
                    setCopySecretStatus('Clipboard copy failed. Copy manually.');
                  }
                }}
              >
                Copy secret
              </button>
            </div>
            {copySecretStatus ? <p className="dashboard-pagination-note">{copySecretStatus}</p> : null}
          </div>
        ) : null}

        {revealedSecret ? (
          <section className="dashboard-view__section" aria-label="Registration bootstrap snippet">
            <h3>Registration bootstrap snippet</h3>
            <p>
              Use this API key for initial account registration calls. Replace
              {' '}
              <code>$RELAYER_URL</code> with your relay base URL.
            </p>
            <pre className="dashboard-table-row">
              <code>
                {buildRegistrationBootstrapSnippet(
                  revealedSecret.secret,
                  selectedEnvironmentId || environmentInput,
                )}
              </code>
            </pre>
          </section>
        ) : null}

        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateApiKey}>
          <label className="dashboard-form-field">
            <span>Name</span>
            <input
              className="dashboard-input"
              value={nameInput}
              onChange={(event) => setNameInput(event.target.value)}
              placeholder="server-key"
            />
          </label>

          <label className="dashboard-form-field">
            <span>Environment ID</span>
            <input
              className="dashboard-input"
              value={selectedEnvironmentId || environmentInput}
              onChange={(event) => setEnvironmentInput(event.target.value)}
              placeholder="project-1:prod"
              disabled={Boolean(selectedEnvironmentId)}
            />
          </label>

          <label className="dashboard-form-field">
            <span>Scopes (comma separated)</span>
            <input
              className="dashboard-input"
              value={scopesInput}
              onChange={(event) => setScopesInput(event.target.value)}
              placeholder="wallets:read,billing:read"
            />
            <span className="dashboard-table-limit">Quick presets</span>
            <div className="dashboard-form-actions">
              {API_KEY_SCOPE_PRESETS.map((preset) => (
                <button
                  key={preset.key}
                  type="button"
                  className="dashboard-inline-link"
                  title={preset.description}
                  onClick={() => setScopesInput(preset.scopes.join(','))}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </label>

          <label className="dashboard-form-field">
            <span>IP allowlist (optional, comma separated)</span>
            <input
              className="dashboard-input"
              value={ipAllowlistInput}
              onChange={(event) => setIpAllowlistInput(event.target.value)}
              placeholder="203.0.113.10/32,2001:db8::/64"
            />
          </label>

          <div className="dashboard-form-actions">
            <button type="submit" className="dashboard-pagination-button" disabled={creating}>
              {creating ? 'Creating...' : 'Create key'}
            </button>
          </div>
        </form>
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      <section className="dashboard-table-wrapper" aria-label="API keys table">
        <div className="dashboard-table-header" role="row">
          <span>Name</span>
          <span>Key ID</span>
          <span>Environment</span>
          <span>Status</span>
          <span>Secret</span>
          <span>Scopes</span>
          <span>Last used</span>
          <span>Actions</span>
        </div>
        {session.loading || loading ? (
          <p className="dashboard-table-limit">Loading API keys...</p>
        ) : !session.claims ? (
          <p className="dashboard-table-limit">
            API keys unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">API keys unavailable: {errorMessage}</p>
        ) : visibleApiKeys.length === 0 ? (
          <p className="dashboard-table-limit">No API keys found for current scope.</p>
        ) : (
          <>
            {visibleApiKeys.map((apiKey) => (
              <div className="dashboard-table-row" key={apiKey.id} role="row">
                <span title={apiKey.name}>{apiKey.name}</span>
                <span title={apiKey.id}>{apiKey.id}</span>
                <span title={apiKey.environmentId}>{apiKey.environmentId || '-'}</span>
                <span>{apiKey.status}</span>
                <span title={apiKey.secretPreview}>{apiKey.secretPreview || '-'}</span>
                <span title={apiKey.scopes.join(', ')}>{apiKey.scopes.join(', ') || '-'}</span>
                <span>{formatTimestamp(apiKey.lastUsedAt)}</span>
                <span>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onRotateApiKey(apiKey.id)}
                    disabled={busyApiKeyId === apiKey.id || apiKey.status === 'REVOKED'}
                  >
                    Rotate
                  </button>{' '}
                  <button
                    type="button"
                    className="dashboard-inline-link dashboard-inline-link--danger"
                    onClick={() => onRevokeApiKey(apiKey.id)}
                    disabled={busyApiKeyId === apiKey.id || apiKey.status === 'REVOKED'}
                  >
                    Revoke
                  </button>
                </span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              Showing {visibleApiKeys.length} key{visibleApiKeys.length === 1 ? '' : 's'}.
            </p>
          </>
        )}
      </section>
    </div>
  );
}

export default ApiKeyManagementPage;
