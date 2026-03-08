import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardApiKey,
  deleteRevokedDashboardApiKey,
  listDashboardApiKeys,
  revokeDashboardApiKey,
  rotateDashboardApiKey,
  updateDashboardApiKey,
  type CreateDashboardApiKeyInput,
  type DashboardConsoleApiKey,
} from './consoleApiKeysApi';
import {
  getDashboardAppSettings,
  type DashboardAppSettings,
} from '../app-settings/consoleSettingsApi';
import { FRONTEND_CONFIG } from '../../../../config';
import { UriListEditor } from '../../components/UriListEditor';

const DEFAULT_SECRET_SCOPES = 'accounts.create,accounts.sync';
const DEFAULT_BUCKET = 'default';

const SECRET_KEY_SCOPE_PRESETS = [
  {
    key: 'registration',
    label: 'Registration bootstrap',
    description: 'Scopes for backend /registration/bootstrap requests',
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

type DashboardCredentialKind = DashboardConsoleApiKey['kind'];

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

function parseEditableList(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of Array.isArray(values) ? values : []) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseOptionalJsonObject(raw: string, label: string): Record<string, unknown> | undefined {
  const value = String(raw || '').trim();
  if (!value) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return { ...(parsed as Record<string, unknown>) };
}

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function normalizeOrigin(value: string): string {
  return String(value || '').trim().toLowerCase();
}

function toDateTimeLocalValue(value: string | null): string {
  const iso = String(value || '').trim();
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const offsetMs = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

function parseOptionalDateTimeLocalValue(raw: string): string | null | undefined {
  const value = String(raw || '').trim();
  if (!value) return null;
  const parsedMs = Date.parse(value);
  if (!Number.isFinite(parsedMs)) {
    throw new Error('Credential expiry must be a valid timestamp.');
  }
  return new Date(parsedMs).toISOString();
}

function buildSecretKeyServerSnippet(credential: string, environmentId: string): string {
  const envScope = String(environmentId || '').trim() || '<environment-id>';
  return [
    "curl -X POST \"$RELAYER_URL/registration/bootstrap\" \\",
    `  -H "Authorization: Bearer ${credential}" \\`,
    `  -H "X-Tatchi-Environment-Id: ${envScope}" \\`,
    '  -H "Content-Type: application/json" \\',
    '  -d \'{',
    '    "new_account_id": "alice.testnet",',
    '    "rp_id": "localhost",',
    '    "account": { "type": "passkey" }',
    "  }'",
  ].join('\n');
}

function buildPublishableKeyManagedSnippet(
  credential: string,
  environmentId: string,
  allowedOrigins: string[],
): string {
  const envScope = String(environmentId || '').trim() || '<environment-id>';
  const allowedOrigin = allowedOrigins[0] || 'https://app.example.com';
  return [
    "import { TatchiPasskey } from '@tatchi-xyz/sdk';",
    '',
    'const tatchi = new TatchiPasskey({',
    "  relayer: { url: '$RELAYER_URL' },",
    '  registration: {',
    "    mode: 'managed',",
    `    environmentId: '${envScope}',`,
    `    publishableKey: '${credential}',`,
    "    brokerUrl: '$BROKER_URL',",
    '  },',
    '});',
    '',
    '// publishable_key is browser-safe but cannot call the relay directly.',
    '// The managed broker validates origin/quota and returns a one-time bootstrap_token.',
    `// Example allowed origin: ${allowedOrigin}`,
    `// Environment scope: ${envScope}`,
  ].join('\n');
}

function describeCredentialMode(kind: DashboardCredentialKind): {
  title: string;
  summary: string;
} {
  if (kind === 'publishable_key') {
    return {
      title: 'Browser publishable_key',
      summary:
        'Browser-safe key for managed bootstrap flows. Direct relay calls with publishable_key are rejected.',
    };
  }
  return {
    title: 'Server secret_key',
    summary:
      'Server-only key for backend relay bootstrap calls. Keep it off the frontend and send it only from your backend.',
  };
}

function describeCredentialDetails(apiKey: DashboardConsoleApiKey): { short: string; title: string } {
  if (apiKey.kind === 'publishable_key') {
    const parts: string[] = [];
    parts.push(
      apiKey.allowedOrigins.length > 0
        ? `origins: ${apiKey.allowedOrigins.join(', ')}`
        : 'origins: -',
    );
    if (apiKey.rateLimitBucket) parts.push(`rate=${apiKey.rateLimitBucket}`);
    if (apiKey.quotaBucket) parts.push(`quota=${apiKey.quotaBucket}`);
    const text = parts.join(' · ');
    return { short: text, title: text };
  }
  const parts: string[] = [];
  parts.push(apiKey.scopes.length > 0 ? `scopes: ${apiKey.scopes.join(', ')}` : 'scopes: -');
  if (apiKey.ipAllowlist.length > 0) {
    parts.push(`ip: ${apiKey.ipAllowlist.join(', ')}`);
  }
  const text = parts.join(' · ');
  return { short: text, title: text };
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
  const [credentialKindInput, setCredentialKindInput] =
    React.useState<DashboardCredentialKind>('secret_key');
  const [nameInput, setNameInput] = React.useState<string>('');
  const [scopesInput, setScopesInput] = React.useState<string>(DEFAULT_SECRET_SCOPES);
  const [ipAllowlistInput, setIpAllowlistInput] = React.useState<string>('');
  const [rateLimitBucketInput, setRateLimitBucketInput] = React.useState<string>(DEFAULT_BUCKET);
  const [quotaBucketInput, setQuotaBucketInput] = React.useState<string>(DEFAULT_BUCKET);
  const [riskPolicyInput, setRiskPolicyInput] = React.useState<string>('');
  const [paymentPolicyInput, setPaymentPolicyInput] = React.useState<string>('');
  const [environmentInput, setEnvironmentInput] = React.useState<string>('');
  const [environmentAppSettings, setEnvironmentAppSettings] = React.useState<DashboardAppSettings | null>(
    null,
  );
  const [environmentAppSettingsLoading, setEnvironmentAppSettingsLoading] =
    React.useState<boolean>(false);
  const [environmentAppSettingsError, setEnvironmentAppSettingsError] = React.useState<string>('');
  const [isCreateModalOpen, setIsCreateModalOpen] = React.useState<boolean>(false);
  const [revealedCredential, setRevealedCredential] = React.useState<{
    action: 'created' | 'rotated';
    apiKey: DashboardConsoleApiKey;
    credential: string;
  } | null>(null);
  const [copyCredentialStatus, setCopyCredentialStatus] = React.useState<string>('');
  const [editingApiKeyId, setEditingApiKeyId] = React.useState<string>('');
  const [editingNameInput, setEditingNameInput] = React.useState<string>('');
  const [editingScopesInput, setEditingScopesInput] = React.useState<string>('');
  const [editingIpAllowlistInput, setEditingIpAllowlistInput] = React.useState<string>('');
  const [editingAllowedOriginsInput, setEditingAllowedOriginsInput] = React.useState<string[]>([]);
  const [editingRateLimitBucketInput, setEditingRateLimitBucketInput] = React.useState<string>('');
  const [editingQuotaBucketInput, setEditingQuotaBucketInput] = React.useState<string>('');
  const [editingRiskPolicyInput, setEditingRiskPolicyInput] = React.useState<string>('');
  const [editingPaymentPolicyInput, setEditingPaymentPolicyInput] = React.useState<string>('');
  const [editingExpiresAtInput, setEditingExpiresAtInput] = React.useState<string>('');
  const [editingBusy, setEditingBusy] = React.useState<boolean>(false);
  const [editingError, setEditingError] = React.useState<string>('');
  const walletOriginHint = React.useMemo(
    () => String(FRONTEND_CONFIG.walletOrigin || 'https://localhost:8443').trim(),
    [],
  );

  React.useEffect(() => {
    if (!selectedEnvironmentId) return;
    setEnvironmentInput(selectedEnvironmentId);
  }, [selectedEnvironmentId]);

  const policyEnvironmentId = React.useMemo(
    () => String(selectedEnvironmentId || environmentInput || '').trim(),
    [environmentInput, selectedEnvironmentId],
  );

  React.useEffect(() => {
    if (!session.claims) {
      setEnvironmentAppSettings(null);
      setEnvironmentAppSettingsError('');
      setEnvironmentAppSettingsLoading(false);
      return;
    }
    if (!policyEnvironmentId) {
      setEnvironmentAppSettings(null);
      setEnvironmentAppSettingsError('');
      setEnvironmentAppSettingsLoading(false);
      return;
    }
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      setEnvironmentAppSettingsLoading(true);
      setEnvironmentAppSettingsError('');
      getDashboardAppSettings(policyEnvironmentId)
        .then((next) => {
          if (cancelled) return;
          setEnvironmentAppSettings(next);
        })
        .catch((error: unknown) => {
          if (cancelled) return;
          setEnvironmentAppSettings(null);
          setEnvironmentAppSettingsError(error instanceof Error ? error.message : String(error));
        })
        .finally(() => {
          if (cancelled) return;
          setEnvironmentAppSettingsLoading(false);
        });
    }, selectedEnvironmentId ? 0 : 250);

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [policyEnvironmentId, selectedEnvironmentId, session.claims]);

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

  const editingApiKey = React.useMemo(
    () => visibleApiKeys.find((entry) => entry.id === editingApiKeyId) || null,
    [editingApiKeyId, visibleApiKeys],
  );

  const activeMode = describeCredentialMode(credentialKindInput);

  const onOpenCreateModal = React.useCallback(() => {
    setEditingApiKeyId('');
    setIsCreateModalOpen(true);
    setMutationError('');
  }, []);

  const onCloseCreateModal = React.useCallback(() => {
    if (creating) return;
    setIsCreateModalOpen(false);
    setMutationError('');
  }, [creating]);

  const onOpenEditApiKey = React.useCallback((apiKey: DashboardConsoleApiKey) => {
    setIsCreateModalOpen(false);
    setEditingApiKeyId(apiKey.id);
    setEditingNameInput(apiKey.name || '');
    setEditingScopesInput(apiKey.kind === 'secret_key' ? apiKey.scopes.join(',') : '');
    setEditingIpAllowlistInput(apiKey.kind === 'secret_key' ? apiKey.ipAllowlist.join(',') : '');
    setEditingAllowedOriginsInput(
      apiKey.kind === 'publishable_key' ? [...apiKey.allowedOrigins] : [],
    );
    setEditingRateLimitBucketInput(
      apiKey.kind === 'publishable_key' ? String(apiKey.rateLimitBucket || '') : '',
    );
    setEditingQuotaBucketInput(
      apiKey.kind === 'publishable_key' ? String(apiKey.quotaBucket || '') : '',
    );
    setEditingRiskPolicyInput(
      apiKey.kind === 'publishable_key' && Object.keys(apiKey.riskPolicy || {}).length > 0
        ? JSON.stringify(apiKey.riskPolicy, null, 2)
        : '',
    );
    setEditingPaymentPolicyInput(
      apiKey.kind === 'publishable_key' && Object.keys(apiKey.paymentPolicy || {}).length > 0
        ? JSON.stringify(apiKey.paymentPolicy, null, 2)
        : '',
    );
    setEditingExpiresAtInput(toDateTimeLocalValue(apiKey.expiresAt));
    setEditingError('');
  }, []);

  const onCloseEditApiKey = React.useCallback(() => {
    if (editingBusy) return;
    setEditingApiKeyId('');
    setEditingError('');
  }, [editingBusy]);

  const onCreateApiKey = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const name = String(nameInput || '').trim();
      const environmentId = String(selectedEnvironmentId || environmentInput || '').trim();
      if (!name) {
        setMutationError('Name is required.');
        return;
      }
      if (!environmentId) {
        setMutationError('Environment ID is required.');
        return;
      }

      let payload: CreateDashboardApiKeyInput;
      try {
        if (credentialKindInput === 'publishable_key') {
          const policySettings =
            environmentAppSettings && environmentAppSettings.environmentId === environmentId
              ? environmentAppSettings
              : await getDashboardAppSettings(environmentId);
          const allowedOrigins = Array.isArray(policySettings.allowedOrigins)
            ? [...policySettings.allowedOrigins]
            : [];
          const rateLimitBucket = String(rateLimitBucketInput || '').trim();
          const quotaBucket = String(quotaBucketInput || '').trim();
          const riskPolicy = parseOptionalJsonObject(riskPolicyInput, 'Risk policy');
          const paymentPolicy = parseOptionalJsonObject(paymentPolicyInput, 'Payment policy');
          if (allowedOrigins.length === 0) {
            setMutationError(
              'Configure at least one allowed origin in Credential policy before creating a publishable_key.',
            );
            return;
          }
          if (
            walletOriginHint &&
            !allowedOrigins.some(
              (origin) => normalizeOrigin(origin) === normalizeOrigin(walletOriginHint),
            )
          ) {
            setMutationError(
              `Allowed origins are missing the wallet origin ${walletOriginHint}. Managed registration runs from that origin, so add it in Credential policy before creating a publishable_key.`,
            );
            return;
          }
          if (!rateLimitBucket) {
            setMutationError('Rate-limit bucket is required.');
            return;
          }
          if (!quotaBucket) {
            setMutationError('Quota bucket is required.');
            return;
          }
          payload = {
            kind: 'publishable_key',
            name,
            environmentId,
            allowedOrigins,
            rateLimitBucket,
            quotaBucket,
            ...(riskPolicy ? { riskPolicy } : {}),
            ...(paymentPolicy ? { paymentPolicy } : {}),
          };
        } else {
          const scopes = parseCsvValues(scopesInput);
          const ipAllowlist = parseCsvValues(ipAllowlistInput);
          if (scopes.length === 0) {
            setMutationError('At least one scope is required.');
            return;
          }
          payload = {
            kind: 'secret_key',
            name,
            environmentId,
            scopes,
            ...(ipAllowlist.length > 0 ? { ipAllowlist } : {}),
          };
        }
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
        return;
      }

      setCreating(true);
      setMutationError('');
      try {
        const created = await createDashboardApiKey(payload);
        setRevealedCredential({
          action: 'created',
          apiKey: created.apiKey,
          credential: created.credential,
        });
        setNameInput('');
        setIpAllowlistInput('');
        setScopesInput(DEFAULT_SECRET_SCOPES);
        setRateLimitBucketInput(DEFAULT_BUCKET);
        setQuotaBucketInput(DEFAULT_BUCKET);
        setRiskPolicyInput('');
        setPaymentPolicyInput('');
        setCopyCredentialStatus('');
        setIsCreateModalOpen(false);
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreating(false);
      }
    },
    [
      credentialKindInput,
      environmentAppSettings,
      environmentInput,
      ipAllowlistInput,
      loadApiKeys,
      nameInput,
      paymentPolicyInput,
      quotaBucketInput,
      rateLimitBucketInput,
      riskPolicyInput,
      scopesInput,
      selectedEnvironmentId,
      session.claims,
      session.errorMessage,
      walletOriginHint,
    ],
  );

  const onSaveApiKeyEdits = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setEditingError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!editingApiKey) {
        setEditingError('Credential was not found.');
        return;
      }

      try {
        const name = String(editingNameInput || '').trim();
        if (!name) {
          setEditingError('Name is required.');
          return;
        }
        const expiresAt = parseOptionalDateTimeLocalValue(editingExpiresAtInput);
        setEditingBusy(true);
        setEditingError('');

        if (editingApiKey.kind === 'publishable_key') {
          const allowedOrigins = parseEditableList(editingAllowedOriginsInput);
          const rateLimitBucket = String(editingRateLimitBucketInput || '').trim();
          const quotaBucket = String(editingQuotaBucketInput || '').trim();
          const riskPolicy = parseOptionalJsonObject(editingRiskPolicyInput, 'Risk policy');
          const paymentPolicy = parseOptionalJsonObject(editingPaymentPolicyInput, 'Payment policy');
          if (allowedOrigins.length === 0) {
            setEditingError('Add at least one allowed origin.');
            return;
          }
          if (!rateLimitBucket) {
            setEditingError('Rate-limit bucket is required.');
            return;
          }
          if (!quotaBucket) {
            setEditingError('Quota bucket is required.');
            return;
          }
          await updateDashboardApiKey({
            apiKeyId: editingApiKey.id,
            name,
            allowedOrigins,
            rateLimitBucket,
            quotaBucket,
            ...(riskPolicy ? { riskPolicy } : {}),
            ...(paymentPolicy ? { paymentPolicy } : {}),
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          });
        } else {
          const scopes = parseCsvValues(editingScopesInput);
          if (scopes.length === 0) {
            setEditingError('At least one scope is required.');
            return;
          }
          await updateDashboardApiKey({
            apiKeyId: editingApiKey.id,
            name,
            scopes,
            ipAllowlist: parseCsvValues(editingIpAllowlistInput),
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          });
        }

        await loadApiKeys();
        setEditingApiKeyId('');
      } catch (error: unknown) {
        setEditingError(error instanceof Error ? error.message : String(error));
      } finally {
        setEditingBusy(false);
      }
    },
    [
      editingAllowedOriginsInput,
      editingApiKey,
      editingExpiresAtInput,
      editingIpAllowlistInput,
      editingNameInput,
      editingPaymentPolicyInput,
      editingQuotaBucketInput,
      editingRateLimitBucketInput,
      editingRiskPolicyInput,
      editingScopesInput,
      loadApiKeys,
      session.claims,
      session.errorMessage,
    ],
  );

  const onRotateApiKey = React.useCallback(
    async (apiKey: DashboardConsoleApiKey) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setBusyApiKeyId(apiKey.id);
      setMutationError('');
      try {
        const rotated = await rotateDashboardApiKey({
          apiKeyId: apiKey.id,
          reason: 'dashboard manual rotation',
        });
        setRevealedCredential({
          action: 'rotated',
          apiKey: rotated.apiKey,
          credential: rotated.credential,
        });
        setCopyCredentialStatus('');
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
    async (apiKey: DashboardConsoleApiKey) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!window.confirm(`Revoke ${apiKey.kind} ${apiKey.id}? This cannot be undone.`)) return;
      setBusyApiKeyId(apiKey.id);
      setMutationError('');
      try {
        await revokeDashboardApiKey({ apiKeyId: apiKey.id });
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyApiKeyId('');
      }
    },
    [loadApiKeys, session.claims, session.errorMessage],
  );

  const onDeleteRevokedApiKey = React.useCallback(
    async (apiKey: DashboardConsoleApiKey) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (apiKey.status !== 'REVOKED') {
        setMutationError('Only revoked credentials can be deleted.');
        return;
      }
      if (
        !window.confirm(
          `Delete revoked ${apiKey.kind} ${apiKey.id}? This permanently removes it from this environment.`,
        )
      ) {
        return;
      }
      setBusyApiKeyId(apiKey.id);
      setMutationError('');
      try {
        await deleteRevokedDashboardApiKey({ apiKeyId: apiKey.id });
        if (revealedCredential?.apiKey.id === apiKey.id) {
          setRevealedCredential(null);
          setCopyCredentialStatus('');
        }
        loadApiKeys();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyApiKeyId('');
      }
    },
    [loadApiKeys, revealedCredential?.apiKey.id, session.claims, session.errorMessage],
  );

  return (
    <div className="dashboard-view dashboard-inline-modal-host" aria-label="Credential management page">
      <section
        className="dashboard-view__section dashboard-view__section--toolbar"
        aria-label="Credential controls"
      >
        <div className="dashboard-section-toolbar">
          <div className="dashboard-section-toolbar__copy">
            <h2>Credentials</h2>
            <p className="dashboard-form-hint">
              Create and manage <code>secret_key</code> and <code>publishable_key</code>{' '}
              credentials for the selected environment.
            </p>
          </div>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={onOpenCreateModal}
            disabled={creating}
          >
            Create credential
          </button>
        </div>
      </section>

      {mutationError && !isCreateModalOpen ? (
        <p className="dashboard-form-alert" role="alert">
          {mutationError}
        </p>
      ) : null}

      {revealedCredential ? (
        <div className="dashboard-secret-banner">
          <p>
            <code>{revealedCredential.apiKey.kind}</code> {revealedCredential.action} for{' '}
            <strong>{revealedCredential.apiKey.id}</strong> (shown once):{' '}
            <code>{revealedCredential.credential}</code>
          </p>
          <div className="dashboard-form-actions">
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={async () => {
                try {
                  await window.navigator?.clipboard?.writeText(revealedCredential.credential);
                  setCopyCredentialStatus(`${revealedCredential.apiKey.kind} copied to clipboard.`);
                } catch {
                  setCopyCredentialStatus('Clipboard copy failed. Copy manually.');
                }
              }}
            >
              Copy {revealedCredential.apiKey.kind}
            </button>
          </div>
          {copyCredentialStatus ? (
            <p className="dashboard-pagination-note">{copyCredentialStatus}</p>
          ) : null}
        </div>
      ) : null}

      {revealedCredential ? (
        <section className="dashboard-view__section" aria-label="Credential integration snippet">
          <h3>
            {revealedCredential.apiKey.kind === 'publishable_key'
              ? 'Managed browser bootstrap snippet'
              : 'Server bootstrap snippet'}
          </h3>
          <p>
            {revealedCredential.apiKey.kind === 'publishable_key'
              ? 'Use this publishable_key in browser-safe SDK config. A managed broker must exchange it for a one-time bootstrap_token before the relay is called.'
              : 'Use this secret_key from your backend only. Do not store it in frontend config or browser bundles.'}
          </p>
          <pre className="dashboard-code-block">
            <code>
              {revealedCredential.apiKey.kind === 'publishable_key'
                ? buildPublishableKeyManagedSnippet(
                    revealedCredential.credential,
                    revealedCredential.apiKey.environmentId,
                    revealedCredential.apiKey.allowedOrigins,
                  )
                : buildSecretKeyServerSnippet(
                    revealedCredential.credential,
                    revealedCredential.apiKey.environmentId,
                  )}
            </code>
          </pre>
        </section>
      ) : null}

      <section className="dashboard-table-wrapper" aria-label="Credentials table">
        <div className="dashboard-table-header" role="row">
          <span>Name</span>
          <span>Kind</span>
          <span>Environment</span>
          <span>Status</span>
          <span>Preview</span>
          <span>Details</span>
          <span>Last used</span>
          <span>Actions</span>
        </div>
        {session.loading || loading ? (
          <p className="dashboard-table-limit">Loading credentials...</p>
        ) : !session.claims ? (
          <p className="dashboard-table-limit">
            Credentials unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">Credentials unavailable: {errorMessage}</p>
        ) : visibleApiKeys.length === 0 ? (
          <p className="dashboard-table-limit">No credentials found for current scope.</p>
        ) : (
          <>
            {visibleApiKeys.map((apiKey) => {
              const details = describeCredentialDetails(apiKey);
              return (
                <div className="dashboard-table-row" key={apiKey.id} role="row">
                  <span title={apiKey.name}>{apiKey.name}</span>
                  <span title={apiKey.kind}>{apiKey.kind}</span>
                  <span title={apiKey.environmentId}>{apiKey.environmentId || '-'}</span>
                  <span>{apiKey.status}</span>
                  <span title={apiKey.credentialPreview}>{apiKey.credentialPreview || '-'}</span>
                  <span title={details.title}>{details.short || '-'}</span>
                  <span>{formatTimestamp(apiKey.lastUsedAt)}</span>
                  <span className="dashboard-credential-table__actions">
                    <button
                      type="button"
                      className="dashboard-inline-link"
                      onClick={() => onOpenEditApiKey(apiKey)}
                      disabled={busyApiKeyId === apiKey.id}
                    >
                      Edit
                    </button>{' '}
                    <button
                      type="button"
                      className="dashboard-inline-link"
                      onClick={() => onRotateApiKey(apiKey)}
                      disabled={busyApiKeyId === apiKey.id || apiKey.status === 'REVOKED'}
                    >
                      Rotate
                    </button>{' '}
                    {apiKey.status === 'REVOKED' ? (
                      <button
                        type="button"
                        className="dashboard-inline-link dashboard-inline-link--danger"
                        onClick={() => onDeleteRevokedApiKey(apiKey)}
                        disabled={busyApiKeyId === apiKey.id}
                      >
                        Delete
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="dashboard-inline-link dashboard-inline-link--danger"
                        onClick={() => onRevokeApiKey(apiKey)}
                        disabled={busyApiKeyId === apiKey.id}
                      >
                        Revoke
                      </button>
                    )}
                  </span>
                </div>
              );
            })}
            <p className="dashboard-table-limit">
              Showing {visibleApiKeys.length} credential{visibleApiKeys.length === 1 ? '' : 's'}.
            </p>
          </>
        )}
      </section>

      {isCreateModalOpen ? (
        <div
          className="dashboard-inline-modal-backdrop"
          role="presentation"
          onClick={onCloseCreateModal}
        >
          <section
            className="dashboard-modal dashboard-modal--wide"
            role="dialog"
            aria-modal="true"
            aria-label="Create credential modal"
            onClick={(event) => event.stopPropagation()}
          >
            <h2>Create credential</h2>
            <p className="dashboard-pagination-note">
              Context scope: environment <strong>{policyEnvironmentId || 'not selected'}</strong>.
            </p>
            <ul className="dashboard-view-list">
              <li>
                <code>secret_key</code>: server-only credential for backend relay bootstrap calls.
              </li>
              <li>
                <code>publishable_key</code>: browser-safe credential for managed broker flows.
                Direct relay calls are rejected.
              </li>
            </ul>

            <div className="dashboard-mode-toggle" aria-label="Credential kind">
              {(['secret_key', 'publishable_key'] as DashboardCredentialKind[]).map((kind) => {
                const mode = describeCredentialMode(kind);
                return (
                  <button
                    key={kind}
                    type="button"
                    aria-pressed={credentialKindInput === kind}
                    className={[
                      'dashboard-mode-toggle__button',
                      credentialKindInput === kind ? 'dashboard-mode-toggle__button--active' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    onClick={() => setCredentialKindInput(kind)}
                    disabled={creating}
                  >
                    <strong>{mode.title}</strong>
                    <span>{mode.summary}</span>
                  </button>
                );
              })}
            </div>

            <p className="dashboard-form-hint">{activeMode.summary}</p>

            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateApiKey}>
              <label className="dashboard-form-field">
                <span>Name</span>
                <input
                  className="dashboard-input"
                  value={nameInput}
                  onChange={(event) => setNameInput(event.target.value)}
                  placeholder={credentialKindInput === 'publishable_key' ? 'frontend-app' : 'server-key'}
                  disabled={creating}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Environment ID</span>
                <input
                  className="dashboard-input"
                  value={environmentInput}
                  onChange={(event) => setEnvironmentInput(event.target.value)}
                  placeholder="org_x:proj_y:dev"
                  disabled={creating}
                />
              </label>

              {credentialKindInput === 'publishable_key' ? (
                <>
                  <div className="dashboard-view-card dashboard-form-field--full">
                    <div className="dashboard-uri-list-editor__header">
                      <strong>Allowed origins</strong>
                      <div className="dashboard-uri-list-editor__description">
                        <p>
                          This <code>publishable_key</code> inherits its origin policy from{' '}
                          <a className="dashboard-inline-link" href="/dashboard/app-settings">
                            Credential policy
                          </a>
                          .
                        </p>
                        <p>
                          Managed registration runs from the wallet origin. Include{' '}
                          <code>{walletOriginHint}</code> for local development.
                        </p>
                      </div>
                    </div>
                    {environmentAppSettingsLoading ? (
                      <p className="dashboard-pagination-note">Loading allowed origins...</p>
                    ) : environmentAppSettingsError ? (
                      <p className="dashboard-form-hint dashboard-form-hint--error">
                        Allowed origins unavailable: {environmentAppSettingsError}
                      </p>
                    ) : environmentAppSettings?.allowedOrigins?.length ? (
                      <ul className="dashboard-view-list">
                        {environmentAppSettings.allowedOrigins.map((origin) => (
                          <li key={origin}>
                            <code>{origin}</code>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="dashboard-form-hint dashboard-form-hint--error">
                        Configure at least one allowed origin in Credential policy before creating a{' '}
                        <code>publishable_key</code>.
                      </p>
                    )}
                  </div>

                  <label className="dashboard-form-field">
                    <span>Rate-limit bucket</span>
                    <input
                      className="dashboard-input"
                      value={rateLimitBucketInput}
                      onChange={(event) => setRateLimitBucketInput(event.target.value)}
                      placeholder="default"
                      disabled={creating}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Quota bucket</span>
                    <input
                      className="dashboard-input"
                      value={quotaBucketInput}
                      onChange={(event) => setQuotaBucketInput(event.target.value)}
                      placeholder="default"
                      disabled={creating}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Risk policy JSON (optional)</span>
                    <textarea
                      className="dashboard-input dashboard-textarea"
                      value={riskPolicyInput}
                      onChange={(event) => setRiskPolicyInput(event.target.value)}
                      placeholder='{"captcha":"standard"}'
                      disabled={creating}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Payment policy JSON (optional)</span>
                    <textarea
                      className="dashboard-input dashboard-textarea"
                      value={paymentPolicyInput}
                      onChange={(event) => setPaymentPolicyInput(event.target.value)}
                      placeholder='{"mode":"quota_then_x402"}'
                      disabled={creating}
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="dashboard-form-field">
                    <span>Scopes (comma separated)</span>
                    <input
                      className="dashboard-input"
                      value={scopesInput}
                      onChange={(event) => setScopesInput(event.target.value)}
                      placeholder="accounts.create,accounts.sync"
                      disabled={creating}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>IP allowlist (optional, comma separated)</span>
                    <input
                      className="dashboard-input"
                      value={ipAllowlistInput}
                      onChange={(event) => setIpAllowlistInput(event.target.value)}
                      placeholder="203.0.113.10/32,2001:db8::/64"
                      disabled={creating}
                    />
                  </label>

                  <div className="dashboard-form-field dashboard-form-field--full">
                    <span>Quick presets</span>
                    <div className="dashboard-form-actions">
                      {SECRET_KEY_SCOPE_PRESETS.map((preset) => (
                        <button
                          key={preset.key}
                          type="button"
                          className="dashboard-inline-link"
                          onClick={() => setScopesInput(preset.scopes.join(','))}
                          disabled={creating}
                          title={preset.description}
                        >
                          {preset.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {mutationError ? <p className="dashboard-form-alert">{mutationError}</p> : null}

              <div className="dashboard-form-actions">
                <button
                  type="button"
                  className="dashboard-pagination-button dashboard-pagination-button--secondary"
                  onClick={onCloseCreateModal}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button type="submit" className="dashboard-pagination-button" disabled={creating}>
                  {creating ? 'Creating...' : `Create ${credentialKindInput}`}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {editingApiKey ? (
        <div
          className="dashboard-inline-modal-backdrop"
          role="presentation"
          onClick={onCloseEditApiKey}
        >
          <section
            className="dashboard-modal dashboard-modal--wide"
            role="dialog"
            aria-modal="true"
            aria-label="Edit credential modal"
            onClick={(event) => event.stopPropagation()}
          >
            <h2>Edit credential</h2>
            <p className="dashboard-pagination-note">
              <code>{editingApiKey.kind}</code> {editingApiKey.id}
            </p>
            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSaveApiKeyEdits}>
              <label className="dashboard-form-field">
                <span>Name</span>
                <input
                  className="dashboard-input"
                  value={editingNameInput}
                  onChange={(event) => setEditingNameInput(event.target.value)}
                  placeholder="frontend-app"
                  disabled={editingBusy}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Expires at (optional)</span>
                <input
                  className="dashboard-input"
                  type="datetime-local"
                  value={editingExpiresAtInput}
                  onChange={(event) => setEditingExpiresAtInput(event.target.value)}
                  disabled={editingBusy}
                />
              </label>

              {editingApiKey.kind === 'publishable_key' ? (
                <>
                  <div className="dashboard-form-field dashboard-form-field--full">
                    <UriListEditor
                      label="Allowed origins"
                      description={
                        <>
                          <p className="dashboard-pagination-note">
                            These origins are stored on this specific <code>publishable_key</code>.
                          </p>
                          <p className="dashboard-pagination-note">
                            For local managed registration, include <code>{walletOriginHint}</code>.
                          </p>
                        </>
                      }
                      values={editingAllowedOriginsInput}
                      onChange={setEditingAllowedOriginsInput}
                      placeholder="https://app.example.com"
                      addLabel="Add URI"
                      disabled={editingBusy}
                    />
                  </div>

                  <label className="dashboard-form-field">
                    <span>Rate-limit bucket</span>
                    <input
                      className="dashboard-input"
                      value={editingRateLimitBucketInput}
                      onChange={(event) => setEditingRateLimitBucketInput(event.target.value)}
                      placeholder="default"
                      disabled={editingBusy}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Quota bucket</span>
                    <input
                      className="dashboard-input"
                      value={editingQuotaBucketInput}
                      onChange={(event) => setEditingQuotaBucketInput(event.target.value)}
                      placeholder="default"
                      disabled={editingBusy}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Risk policy JSON (optional)</span>
                    <textarea
                      className="dashboard-input dashboard-textarea"
                      value={editingRiskPolicyInput}
                      onChange={(event) => setEditingRiskPolicyInput(event.target.value)}
                      placeholder='{"captcha":"adaptive"}'
                      disabled={editingBusy}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>Payment policy JSON (optional)</span>
                    <textarea
                      className="dashboard-input dashboard-textarea"
                      value={editingPaymentPolicyInput}
                      onChange={(event) => setEditingPaymentPolicyInput(event.target.value)}
                      placeholder='{"mode":"quota_then_x402"}'
                      disabled={editingBusy}
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="dashboard-form-field">
                    <span>Scopes (comma separated)</span>
                    <input
                      className="dashboard-input"
                      value={editingScopesInput}
                      onChange={(event) => setEditingScopesInput(event.target.value)}
                      placeholder="accounts.create,accounts.sync"
                      disabled={editingBusy}
                    />
                  </label>

                  <label className="dashboard-form-field">
                    <span>IP allowlist (optional, comma separated)</span>
                    <input
                      className="dashboard-input"
                      value={editingIpAllowlistInput}
                      onChange={(event) => setEditingIpAllowlistInput(event.target.value)}
                      placeholder="203.0.113.10/32"
                      disabled={editingBusy}
                    />
                  </label>
                </>
              )}

              {editingError ? <p className="dashboard-form-alert">{editingError}</p> : null}

              <div className="dashboard-form-actions">
                <button
                  type="button"
                  className="dashboard-pagination-button dashboard-pagination-button--secondary"
                  onClick={onCloseEditApiKey}
                  disabled={editingBusy}
                >
                  Cancel
                </button>
                <button type="submit" className="dashboard-pagination-button" disabled={editingBusy}>
                  {editingBusy ? 'Saving...' : 'Save changes'}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </div>
  );
}

export default ApiKeyManagementPage;
