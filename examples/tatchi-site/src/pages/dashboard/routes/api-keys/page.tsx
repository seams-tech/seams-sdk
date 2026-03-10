import React from 'react';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableFooter,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
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
import { FRONTEND_CONFIG } from '../../../../config';
import { UriListEditor } from '../../components/UriListEditor';
import { ScopePicker, type DashboardScopeOption } from '../../components/ScopePicker';

const DEFAULT_RATE_LIMIT_BUCKET = 'default_web_v1';
const DEFAULT_QUOTA_BUCKET = 'free_registrations_v1';
const DEFAULT_RISK_POLICY: Record<string, unknown> = { captcha: 'adaptive' };
const DEFAULT_PAYMENT_PRODUCT_ID = 'wallet_registration_v1';

type PublishablePaymentPolicyValue = 'disabled' | 'quota_then_x402' | 'always_x402';

interface PublishableChoiceOption<TValue extends string> {
  value: TValue;
  label: string;
  description: string;
}

const PAYMENT_POLICY_OPTIONS: readonly PublishableChoiceOption<PublishablePaymentPolicyValue>[] = [
  {
    value: 'disabled',
    label: 'Stop when quota is exhausted',
    description: 'Reject new managed registrations after the included quota is used up.',
  },
  {
    value: 'quota_then_x402',
    label: 'Use paid overage after quota',
    description: 'Use included quota first, then require x402 payment for extra registrations.',
  },
  {
    value: 'always_x402',
    label: 'Always require x402',
    description: 'Require x402 payment for every managed registration request.',
  },
] as const;

const SECRET_KEY_SCOPE_OPTIONS: readonly DashboardScopeOption[] = [
  {
    value: 'accounts.create',
    label: 'Create accounts',
    description: 'Allows backend bootstrap flows to create accounts.',
  },
  {
    value: 'accounts.sync',
    label: 'Sync accounts',
    description: 'Allows backend bootstrap flows to sync account state.',
  },
  {
    value: 'wallets:read',
    label: 'Read wallets',
    description: 'Allows read-only wallet access in console APIs.',
  },
  {
    value: 'billing:read',
    label: 'Read billing',
    description: 'Allows read-only billing access in console APIs.',
  },
  {
    value: 'sessions.refresh',
    label: 'Refresh sessions',
    description: 'Allows session refresh operations.',
  },
] as const;
const API_KEYS_TABLE_COLUMNS = dashboardTableColumns(1.15, 0.9, 0.9, 0.65, 0.95, 1.2, 0.85, 1.2);
const DEFAULT_SECRET_SCOPES = ['accounts.create', 'accounts.sync'];

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

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function normalizeOrigin(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function normalizePaymentPolicyValue(
  raw: Record<string, unknown> | null | undefined,
): PublishablePaymentPolicyValue {
  const mode = String(raw?.mode || '').trim();
  if (mode === 'always_x402') return 'always_x402';
  if (mode === 'quota_then_x402') return 'quota_then_x402';
  return 'disabled';
}

function toPaymentPolicyObject(value: PublishablePaymentPolicyValue): Record<string, unknown> {
  if (value === 'disabled') return { mode: 'disabled' };
  return {
    mode: value,
    productId: DEFAULT_PAYMENT_PRODUCT_ID,
  };
}

function describePublishablePaymentPolicy(
  value: Record<string, unknown> | null | undefined,
): string {
  const normalized = normalizePaymentPolicyValue(value);
  return (
    PAYMENT_POLICY_OPTIONS.find((option) => option.value === normalized)?.label ||
    PAYMENT_POLICY_OPTIONS[0].label
  );
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
    'curl -X POST "$RELAYER_URL/registration/bootstrap" \\',
    `  -H "Authorization: Bearer ${credential}" \\`,
    `  -H "X-Tatchi-Environment-Id: ${envScope}" \\`,
    '  -H "Content-Type: application/json" \\',
    "  -d '{",
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

function PublishablePaymentPolicyField(props: {
  value: PublishablePaymentPolicyValue;
  onChange(next: PublishablePaymentPolicyValue): void;
  disabled?: boolean;
}): React.JSX.Element {
  const { value, onChange, disabled = false } = props;
  const selectedOption =
    PAYMENT_POLICY_OPTIONS.find((option) => option.value === value) || PAYMENT_POLICY_OPTIONS[0];
  return (
    <label className="dashboard-form-field">
      <span>Overage behavior</span>
      <select
        className="dashboard-input dashboard-scope-picker__select"
        value={value}
        onChange={(event) => onChange(event.target.value as PublishablePaymentPolicyValue)}
        disabled={disabled}
        aria-label="Overage behavior"
      >
        {PAYMENT_POLICY_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <p className="dashboard-pagination-note">{selectedOption.description}</p>
    </label>
  );
}

function describeCredentialDetails(apiKey: DashboardConsoleApiKey): {
  short: string;
  title: string;
} {
  if (apiKey.kind === 'publishable_key') {
    const parts: string[] = [];
    parts.push(
      apiKey.allowedOrigins.length > 0
        ? `origins: ${apiKey.allowedOrigins.join(', ')}`
        : 'origins: -',
    );
    parts.push(`overage: ${describePublishablePaymentPolicy(apiKey.paymentPolicy)}`);
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
  const walletOriginHint = React.useMemo(
    () => String(FRONTEND_CONFIG.walletOrigin || 'https://localhost:8443').trim(),
    [],
  );
  const defaultPublishableOrigins = React.useMemo(
    () => parseEditableList(['https://localhost', walletOriginHint]),
    [walletOriginHint],
  );
  const [apiKeys, setApiKeys] = React.useState<DashboardConsoleApiKey[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [creating, setCreating] = React.useState<boolean>(false);
  const [busyApiKeyId, setBusyApiKeyId] = React.useState<string>('');
  const [credentialKindInput, setCredentialKindInput] =
    React.useState<DashboardCredentialKind>('secret_key');
  const [nameInput, setNameInput] = React.useState<string>('');
  const [scopesInput, setScopesInput] = React.useState<string[]>(DEFAULT_SECRET_SCOPES);
  const [ipAllowlistInput, setIpAllowlistInput] = React.useState<string>('');
  const [allowedOriginsInput, setAllowedOriginsInput] =
    React.useState<string[]>(defaultPublishableOrigins);
  const [paymentPolicyInput, setPaymentPolicyInput] =
    React.useState<PublishablePaymentPolicyValue>('disabled');
  const [isCreateModalOpen, setIsCreateModalOpen] = React.useState<boolean>(false);
  const [revealedCredential, setRevealedCredential] = React.useState<{
    action: 'created' | 'rotated';
    apiKey: DashboardConsoleApiKey;
    credential: string;
  } | null>(null);
  const [copyCredentialStatus, setCopyCredentialStatus] = React.useState<string>('');
  const [editingApiKeyId, setEditingApiKeyId] = React.useState<string>('');
  const [editingNameInput, setEditingNameInput] = React.useState<string>('');
  const [editingScopesInput, setEditingScopesInput] = React.useState<string[]>([]);
  const [editingIpAllowlistInput, setEditingIpAllowlistInput] = React.useState<string>('');
  const [editingAllowedOriginsInput, setEditingAllowedOriginsInput] = React.useState<string[]>([]);
  const [editingPaymentPolicyInput, setEditingPaymentPolicyInput] =
    React.useState<PublishablePaymentPolicyValue>('disabled');
  const [editingExpiresAtInput, setEditingExpiresAtInput] = React.useState<string>('');
  const [editingBusy, setEditingBusy] = React.useState<boolean>(false);
  const [editingError, setEditingError] = React.useState<string>('');

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
  const apiKeysPagination = useDashboardTablePagination(visibleApiKeys, {
    disabled: session.loading || loading,
    itemLabel: 'credential',
    itemLabelPlural: 'credentials',
  });

  const onOpenCreateModal = React.useCallback(() => {
    setEditingApiKeyId('');
    setAllowedOriginsInput(defaultPublishableOrigins);
    setIsCreateModalOpen(true);
    setMutationError('');
  }, [defaultPublishableOrigins]);

  const onCloseCreateModal = React.useCallback(() => {
    if (creating) return;
    setIsCreateModalOpen(false);
    setMutationError('');
  }, [creating]);

  const onOpenEditApiKey = React.useCallback((apiKey: DashboardConsoleApiKey) => {
    setIsCreateModalOpen(false);
    setEditingApiKeyId(apiKey.id);
    setEditingNameInput(apiKey.name || '');
    setEditingScopesInput(apiKey.kind === 'secret_key' ? [...apiKey.scopes] : []);
    setEditingIpAllowlistInput(apiKey.kind === 'secret_key' ? apiKey.ipAllowlist.join(',') : '');
    setEditingAllowedOriginsInput(
      apiKey.kind === 'publishable_key' ? [...apiKey.allowedOrigins] : [],
    );
    setEditingPaymentPolicyInput(
      apiKey.kind === 'publishable_key'
        ? normalizePaymentPolicyValue(apiKey.paymentPolicy)
        : 'disabled',
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
      const environmentId = selectedEnvironmentId;
      if (!name) {
        setMutationError('Name is required.');
        return;
      }
      if (!environmentId) {
        setMutationError('Select an environment from the top bar before creating a credential.');
        return;
      }

      let payload: CreateDashboardApiKeyInput;
      try {
        if (credentialKindInput === 'publishable_key') {
          const allowedOrigins = parseEditableList(allowedOriginsInput);
          if (allowedOrigins.length === 0) {
            setMutationError('Add at least one allowed origin.');
            return;
          }
          if (
            walletOriginHint &&
            !allowedOrigins.some(
              (origin) => normalizeOrigin(origin) === normalizeOrigin(walletOriginHint),
            )
          ) {
            setMutationError(
              `Allowed origins are missing the wallet origin ${walletOriginHint}. Managed registration runs from that origin, so add it to this publishable_key.`,
            );
            return;
          }
          payload = {
            kind: 'publishable_key',
            name,
            environmentId,
            allowedOrigins,
            rateLimitBucket: DEFAULT_RATE_LIMIT_BUCKET,
            quotaBucket: DEFAULT_QUOTA_BUCKET,
            riskPolicy: DEFAULT_RISK_POLICY,
            paymentPolicy: toPaymentPolicyObject(paymentPolicyInput),
          };
        } else {
          const scopes = parseEditableList(scopesInput);
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
        setScopesInput([...DEFAULT_SECRET_SCOPES]);
        setAllowedOriginsInput(defaultPublishableOrigins);
        setPaymentPolicyInput('disabled');
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
      allowedOriginsInput,
      credentialKindInput,
      defaultPublishableOrigins,
      ipAllowlistInput,
      loadApiKeys,
      nameInput,
      paymentPolicyInput,
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
          if (allowedOrigins.length === 0) {
            setEditingError('Add at least one allowed origin.');
            return;
          }
          if (
            walletOriginHint &&
            !allowedOrigins.some(
              (origin) => normalizeOrigin(origin) === normalizeOrigin(walletOriginHint),
            )
          ) {
            setEditingError(
              `Allowed origins are missing the wallet origin ${walletOriginHint}. Managed registration runs from that origin, so add it to this publishable_key.`,
            );
            return;
          }
          await updateDashboardApiKey({
            apiKeyId: editingApiKey.id,
            name,
            allowedOrigins,
            rateLimitBucket:
              String(editingApiKey.rateLimitBucket || '').trim() || DEFAULT_RATE_LIMIT_BUCKET,
            quotaBucket: String(editingApiKey.quotaBucket || '').trim() || DEFAULT_QUOTA_BUCKET,
            riskPolicy:
              Object.keys(editingApiKey.riskPolicy || {}).length > 0
                ? editingApiKey.riskPolicy
                : DEFAULT_RISK_POLICY,
            paymentPolicy: toPaymentPolicyObject(editingPaymentPolicyInput),
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          });
        } else {
          const scopes = parseEditableList(editingScopesInput);
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
      editingScopesInput,
      loadApiKeys,
      session.claims,
      session.errorMessage,
      walletOriginHint,
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
    <div className="dashboard-view" aria-label="Credential management page">
      <section
        className="dashboard-view__section dashboard-view__section--toolbar"
        aria-label="Credential controls"
      >
        <div className="dashboard-section-toolbar">
          <div className="dashboard-section-toolbar__copy">
            <h2>Credentials</h2>
            <p className="dashboard-form-hint">
              Create and manage <code>secret_key</code> and <code>publishable_key</code> credentials
              for the selected environment.
            </p>
          </div>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={onOpenCreateModal}
            disabled={creating || !selectedEnvironmentId}
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

      <DashboardTable
        ariaLabel="Credentials table"
        className="dashboard-credential-table"
        columns={API_KEYS_TABLE_COLUMNS}
        pagination={apiKeysPagination.pagination}
      >
        <DashboardTableHeader>
          <DashboardTableHeaderCell>Name</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Kind</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Environment</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Preview</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Details</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Last used</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {session.loading || loading ? (
          <DashboardTableState>Loading credentials...</DashboardTableState>
        ) : !session.claims ? (
          <DashboardTableState>
            Credentials unavailable: {session.errorMessage || 'unauthorized'}.
          </DashboardTableState>
        ) : errorMessage ? (
          <DashboardTableState>Credentials unavailable: {errorMessage}</DashboardTableState>
        ) : visibleApiKeys.length === 0 ? (
          <DashboardTableState>No credentials found for current scope.</DashboardTableState>
        ) : (
          <>
            {apiKeysPagination.rows.map((apiKey) => {
              const details = describeCredentialDetails(apiKey);
              return (
                <DashboardTableRow key={apiKey.id}>
                  <DashboardTableCell title={apiKey.name}>{apiKey.name}</DashboardTableCell>
                  <DashboardTableCell title={apiKey.kind}>{apiKey.kind}</DashboardTableCell>
                  <DashboardTableCell title={apiKey.environmentId}>
                    {apiKey.environmentId || '-'}
                  </DashboardTableCell>
                  <DashboardTableCell>{apiKey.status}</DashboardTableCell>
                  <DashboardTableCell title={apiKey.credentialPreview}>
                    {apiKey.credentialPreview || '-'}
                  </DashboardTableCell>
                  <DashboardTableCell title={details.title}>
                    {details.short || '-'}
                  </DashboardTableCell>
                  <DashboardTableCell truncate>
                    {formatTimestamp(apiKey.lastUsedAt)}
                  </DashboardTableCell>
                  <DashboardTableCell>
                    <DashboardTableActionGroup>
                      <DashboardTableActionButton
                        onClick={() => onOpenEditApiKey(apiKey)}
                        disabled={busyApiKeyId === apiKey.id}
                      >
                        Edit
                      </DashboardTableActionButton>
                      <DashboardTableActionButton
                        onClick={() => onRotateApiKey(apiKey)}
                        disabled={busyApiKeyId === apiKey.id || apiKey.status === 'REVOKED'}
                      >
                        Rotate
                      </DashboardTableActionButton>
                      {apiKey.status === 'REVOKED' ? (
                        <DashboardTableActionButton
                          tone="danger"
                          onClick={() => onDeleteRevokedApiKey(apiKey)}
                          disabled={busyApiKeyId === apiKey.id}
                        >
                          Delete
                        </DashboardTableActionButton>
                      ) : (
                        <DashboardTableActionButton
                          tone="danger"
                          onClick={() => onRevokeApiKey(apiKey)}
                          disabled={busyApiKeyId === apiKey.id}
                        >
                          Revoke
                        </DashboardTableActionButton>
                      )}
                    </DashboardTableActionGroup>
                  </DashboardTableCell>
                </DashboardTableRow>
              );
            })}
            <DashboardTableFooter>
              Showing {visibleApiKeys.length} credential{visibleApiKeys.length === 1 ? '' : 's'}.
            </DashboardTableFooter>
          </>
        )}
      </DashboardTable>

      <DashboardInlineModal
        isOpen={isCreateModalOpen}
        ariaLabel="Create credential modal"
        onRequestClose={onCloseCreateModal}
        className="dashboard-modal--wide"
      >
        <h2>Create credential</h2>

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

        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateApiKey}>
          <label className="dashboard-form-field dashboard-form-field--full">
            <span>Name</span>
            <input
              className="dashboard-input"
              value={nameInput}
              onChange={(event) => setNameInput(event.target.value)}
              placeholder={credentialKindInput === 'publishable_key' ? 'frontend-app' : 'server-key'}
              disabled={creating}
            />
          </label>

          {credentialKindInput === 'publishable_key' ? (
            <>
              <div className="dashboard-form-field dashboard-form-field--full">
                <UriListEditor
                  label="Allowed origins"
                  description={
                    <>
                      <p>
                        Use exact browser origins only. Managed registration runs from the wallet
                        origin, not the app origin.
                      </p>
                      <p>
                        In this local dev setup, include <code>{walletOriginHint}</code>.
                      </p>
                    </>
                  }
                  values={allowedOriginsInput}
                  onChange={setAllowedOriginsInput}
                  placeholder="https://app.example.com"
                  addLabel="Add URI"
                  disabled={creating}
                />
              </div>

              <PublishablePaymentPolicyField
                value={paymentPolicyInput}
                onChange={setPaymentPolicyInput}
                disabled={creating}
              />
            </>
          ) : (
            <>
              <div className="dashboard-form-field dashboard-form-field--full">
                <ScopePicker
                  label="Scopes"
                  options={SECRET_KEY_SCOPE_OPTIONS}
                  values={scopesInput}
                  onChange={setScopesInput}
                  disabled={creating}
                />
              </div>

              <label className="dashboard-form-field">
                <span>IP allowlist (optional, comma separated)</span>
                <input
                  className="dashboard-input"
                  value={ipAllowlistInput}
                  onChange={(event) => setIpAllowlistInput(event.target.value)}
                  placeholder="198.51.100.24/32,198.51.100.0/24"
                  disabled={creating}
                />
              </label>
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
      </DashboardInlineModal>

      <DashboardInlineModal
        isOpen={editingApiKey !== null}
        ariaLabel="Edit credential modal"
        onRequestClose={onCloseEditApiKey}
        className="dashboard-modal--wide"
      >
        {editingApiKey ? (
          <>
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
                            Use exact browser origins only.
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

                  <PublishablePaymentPolicyField
                    value={editingPaymentPolicyInput}
                    onChange={setEditingPaymentPolicyInput}
                    disabled={editingBusy}
                  />
                </>
              ) : (
                <>
                  <div className="dashboard-form-field dashboard-form-field--full">
                    <ScopePicker
                      label="Scopes"
                      options={SECRET_KEY_SCOPE_OPTIONS}
                      values={editingScopesInput}
                      onChange={setEditingScopesInput}
                      disabled={editingBusy}
                    />
                  </div>

                  <label className="dashboard-form-field">
                    <span>IP allowlist (optional, comma separated)</span>
                    <input
                      className="dashboard-input"
                      value={editingIpAllowlistInput}
                      onChange={(event) => setEditingIpAllowlistInput(event.target.value)}
                      placeholder="198.51.100.24/32"
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
          </>
        ) : null}
      </DashboardInlineModal>
    </div>
  );
}

export default ApiKeyManagementPage;
