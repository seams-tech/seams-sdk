import type { DashboardRoute } from '../types';

export type DashboardChecklistCard = {
  title: string;
  items: readonly string[];
};

export type DashboardKpiMetric = {
  label: string;
  value: string;
  hint: string;
};

type DashboardSearchFilterControl = {
  kind: 'select' | 'action';
  value: string;
};

type DashboardSearchModel = {
  title: string;
  items: readonly string[];
};

type CardDashboardRoute = Exclude<
  DashboardRoute,
  '/dashboard/wallets-list' | '/dashboard/wallets-search'
>;

export const USER_WALLETS_LIST_KPIS = [
  {
    label: 'Total assets',
    value: '$12.4M',
    hint: 'Across all tracked wallets',
  },
  {
    label: 'Total wallets',
    value: '24,581',
    hint: 'Includes EOA and smart wallets',
  },
  {
    label: 'Funded wallets',
    value: '9,742',
    hint: '39.6% funded ratio',
  },
  {
    label: 'Activity (7d)',
    value: '18,902 tx',
    hint: '24h and 7d windows available',
  },
] as const satisfies readonly DashboardKpiMetric[];

export const USER_WALLETS_TABLE_COLUMNS = [
  'Wallet ID',
  'Address',
  'Chain',
  'Owner/User',
  'Policy',
  'Balance',
  'Status',
  'Updated',
] as const;

export const USER_WALLETS_TABLE_NOTE =
  'Row actions: view details, view activity, assign policy, and freeze/unfreeze where supported.';

export const SEARCH_USER_WALLETS_PLACEHOLDER =
  'Search by wallet address, wallet ID, user ID, or external reference ID';

export const SEARCH_USER_WALLETS_FILTER_CONTROLS = [
  { kind: 'select', value: 'All chains' },
  { kind: 'select', value: 'Any policy' },
  { kind: 'select', value: 'EOA + Smart' },
  { kind: 'action', value: 'Sort' },
] as const satisfies readonly DashboardSearchFilterControl[];

export const SEARCH_USER_WALLETS_MODEL = {
  title: 'Search and filter model',
  items: [
    'Filter by chain, policy, key quorum, wallet type, status, and date range.',
    'Sort by balance, last activity, and creation time.',
    'Persist filter state in URL query params for shareable views.',
    'Return empty/loading/error states with retry actions.',
  ],
} as const satisfies DashboardSearchModel;

export const DASHBOARD_CARD_PAGE_CONTENT = {
  '/dashboard/policy-engine': [
    {
      title: 'Policy model',
      items: [
        'Allowed actions: transfer, swap, approve, contract call, key export.',
        'Allowed chains and networks by environment.',
        'Limits by transaction, daily windows, and policy segments.',
        'Contract and method allow/deny lists.',
        'Approval rules for MFA, admin approvals, and signer quorum.',
      ],
    },
    {
      title: 'Lifecycle controls',
      items: [
        'Draft to staged to published policy states.',
        'Simulation endpoint before execution.',
        'Version history with rollback support.',
        'Immutable audit trail for create/update/publish/assign.',
      ],
    },
  ],
  '/dashboard/gas-smart-wallets': [
    {
      title: 'Gas sponsorship controls',
      items: [
        'Enable/disable at org, environment, policy, and wallet segment scope.',
        'Budget and quota controls by chain and billing period.',
        'Alert thresholds for overspend and budget exhaustion.',
      ],
    },
    {
      title: 'Smart wallet controls',
      items: [
        'Account abstraction mode and account type selection.',
        'Paymaster mode and fallback behavior.',
        'Telemetry for sponsored tx count, spend, and failures.',
      ],
    },
  ],
  '/dashboard/export-keys': [
    {
      title: 'Export policy modes',
      items: ['Disabled', 'Approval required', 'Allowed with scoped constraints'],
    },
    {
      title: 'Approval and audit controls',
      items: [
        'Constraints by role, chain, wallet type, and environment.',
        'Step-up requirements with MFA and reason capture.',
        'Immutable logs for who, what, when, why, and approval chain.',
      ],
    },
  ],
  '/dashboard/api-keys': [
    {
      title: 'Key lifecycle',
      items: [
        'Create, revoke, and rotate API keys with scoped permissions.',
        'Environment scoping and optional IP restrictions.',
        'Secrets visible once at creation and never retrievable.',
      ],
    },
    {
      title: 'Usage and anomaly monitoring',
      items: [
        'Last-used timestamp and endpoint distribution.',
        'Anomaly flags for suspicious usage patterns.',
        'Audit logging for create/revoke/rotate actions.',
      ],
    },
  ],
  '/dashboard/webhooks': [
    {
      title: 'Endpoint and signing setup',
      items: [
        'Register endpoints with event subscriptions.',
        'Signed payloads with rotating secrets.',
        'Subscription scopes: wallet, policy, auth, tx lifecycle.',
      ],
    },
    {
      title: 'Delivery operations',
      items: [
        'Backoff retries and dead-letter queue handling.',
        'Delivery logs with request and response metadata.',
        'Replay actions for failed webhook deliveries.',
      ],
    },
  ],
  '/dashboard/app-settings': [
    {
      title: 'Origins and session configuration',
      items: [
        'Environment-scoped allowed origins/domains with strict validation.',
        'Cookie mode controls: HttpOnly, Secure, SameSite.',
        'Guardrails for risky changes with warnings and confirmations.',
      ],
    },
    {
      title: 'JWT and optional controls',
      items: [
        'Issuer, audience, key IDs, token TTL, and refresh TTL.',
        'Optional IP allowlist configuration.',
        'Optional SSO metadata fields by environment.',
      ],
    },
  ],
} as const satisfies Record<CardDashboardRoute, readonly DashboardChecklistCard[]>;

export function getDashboardChecklistCards(
  route: CardDashboardRoute,
): readonly DashboardChecklistCard[] {
  return DASHBOARD_CARD_PAGE_CONTENT[route];
}
