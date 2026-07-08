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

type DashboardSearchModel = {
  title: string;
  items: readonly string[];
};

type CardDashboardRoute = Exclude<
  DashboardRoute,
  | '/dashboard/onboarding'
  | '/dashboard/account-settings'
  | '/dashboard/wallets-list'
  | '/dashboard/billing/account'
  | '/dashboard/invoices'
  | '/platform/billing'
  | '/dashboard/team-members'
  | '/dashboard/audit'
  | '/dashboard/policy-engine'
  | '/dashboard/gas-sponsorship'
  | '/dashboard/overview'
  | '/dashboard/observability'
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
    hint: 'Across tracked wallet accounts',
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
  '/dashboard/api-keys': [
    {
      title: 'Credential modes',
      items: [
        'Create server-side `secret_key` credentials with scoped relay permissions.',
        'Create browser-safe `publishable_key` credentials with allowed-origin and managed-broker policy fields.',
        'Credential values are visible once at creation or rotation and never retrievable later.',
      ],
    },
    {
      title: 'Usage and anomaly monitoring',
      items: [
        'Last-used timestamp and endpoint distribution for `secret_key` traffic.',
        'Allowed-origin, quota-bucket, and rate-bucket visibility for `publishable_key` records.',
        'Audit logging for create/revoke/rotate actions across both credential kinds.',
      ],
    },
  ],
  '/dashboard/webhooks': [
    {
      title: 'Endpoint and signing setup',
      items: [
        'Register endpoints with event categories.',
        'Signed payloads with rotating secrets.',
        'Event categories: wallet, policy, auth, tx lifecycle, session.',
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
} as const satisfies Record<CardDashboardRoute, readonly DashboardChecklistCard[]>;

export function getDashboardChecklistCards(
  route: CardDashboardRoute,
): readonly DashboardChecklistCard[] {
  return DASHBOARD_CARD_PAGE_CONTENT[route];
}
