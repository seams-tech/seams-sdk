import React from 'react';
import {
  createDashboardPlatformBillingManualAdminDebit,
  createDashboardPlatformBillingManualSupportCredit,
  formatUsdMinor,
  getDashboardPlatformBillingAccount,
  searchDashboardPlatformBillingOrganizations,
  type DashboardBillingAccountActivityEventType,
  type DashboardBillingManualAdjustmentKind,
  type DashboardPlatformBillingOrganization,
  type DashboardPlatformBillingLookupRequest,
  type DashboardPlatformBillingLookupResult,
} from './consoleBillingApi';
import type { BillingMetric } from './billingShared';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import { BillingAccountActivitySection, BillingContextSummarySection } from './billingSections';

const PLATFORM_BILLING_ACTIVITY_LIMIT = 50;
const PLATFORM_BILLING_SEARCH_LIMIT = 10;
const PLATFORM_BILLING_RECENT_ORGANIZATION_LIMIT = 5;
const PLATFORM_BILLING_ROUTE_ORG_ID_QUERY_KEY = 'billingOrgId';
const PLATFORM_BILLING_ROUTE_ORG_NAME_QUERY_KEY = 'billingOrgName';
const PLATFORM_BILLING_EVENT_TYPE_OPTIONS: Array<{
  value: 'all' | DashboardBillingAccountActivityEventType;
  label: string;
}> = [
  { value: 'all', label: 'All events' },
  { value: 'CREDIT_PURCHASE', label: 'Credit purchases' },
  { value: 'USAGE_DEBIT', label: 'Usage debits' },
  { value: 'SPONSORED_EXECUTION_DEBIT', label: 'Sponsored execution debits' },
  { value: 'MANUAL_ADJUSTMENT', label: 'Manual adjustments' },
  { value: 'REFUND', label: 'Refunds' },
  { value: 'REVERSAL', label: 'Reversals' },
];

function parseUsdAmountInputToMinor(input: string): number | null {
  const normalized = String(input || '').trim();
  if (!normalized) return null;
  if (!/^\d+(?:\.\d{0,2})?$/.test(normalized)) return null;
  const [whole, fraction = ''] = normalized.split('.');
  return Number.parseInt(whole, 10) * 100 + Number.parseInt(fraction.padEnd(2, '0'), 10);
}

function describeManualAdjustmentKind(input: DashboardBillingManualAdjustmentKind): string {
  return input === 'support_credit' ? 'Manual support credit' : 'Manual admin debit';
}

function describePlatformAdjustmentAction(input: DashboardBillingManualAdjustmentKind): string {
  return input === 'support_credit' ? 'support credit' : 'admin debit';
}

function normalizePlatformBillingSearchValue(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function scorePlatformBillingSearchCandidate(query: string, value: string, offset: number): number {
  const normalized = normalizePlatformBillingSearchValue(value);
  if (!normalized) return Number.POSITIVE_INFINITY;
  if (normalized === query) return offset;
  if (normalized.startsWith(query)) {
    return offset + 10 + Math.max(0, normalized.length - query.length);
  }
  const tokens = normalized.split(/[\s_-]+/).filter(Boolean);
  const tokenIndex = tokens.findIndex((token) => token.startsWith(query));
  if (tokenIndex >= 0) return offset + 30 + tokenIndex;
  const containsIndex = normalized.indexOf(query);
  if (containsIndex >= 0) return offset + 60 + containsIndex;
  return Number.POSITIVE_INFINITY;
}

function scorePlatformBillingOrganization(
  query: string,
  organization: DashboardPlatformBillingOrganization,
): number {
  return Math.min(
    scorePlatformBillingSearchCandidate(query, organization.name, 0),
    scorePlatformBillingSearchCandidate(query, organization.id, 20),
  );
}

function sortPlatformBillingOrganizations(
  organizations: DashboardPlatformBillingOrganization[],
  query: string,
): DashboardPlatformBillingOrganization[] {
  const normalizedQuery = normalizePlatformBillingSearchValue(query);
  if (!normalizedQuery) return [...organizations];
  return [...organizations].sort((left, right) => {
    const scoreDiff =
      scorePlatformBillingOrganization(normalizedQuery, left) -
      scorePlatformBillingOrganization(normalizedQuery, right);
    if (scoreDiff !== 0) return scoreDiff;
    const primaryDiff = left.name.localeCompare(right.name);
    if (primaryDiff !== 0) return primaryDiff;
    return left.id.localeCompare(right.id);
  });
}

function buildLookupRequest(input: {
  orgId?: string;
  projectId?: string;
  periodMonthUtc: string;
  eventType: 'all' | DashboardBillingAccountActivityEventType;
}): DashboardPlatformBillingLookupRequest {
  const orgId = String(input.orgId || '').trim();
  const projectId = String(input.projectId || '').trim();
  const periodMonthUtc = String(input.periodMonthUtc || '').trim();
  return {
    ...(orgId ? { orgId } : {}),
    ...(projectId ? { projectId } : {}),
    ...(periodMonthUtc ? { periodMonthUtc } : {}),
    ...(input.eventType !== 'all' ? { eventType: input.eventType } : {}),
    limit: PLATFORM_BILLING_ACTIVITY_LIMIT,
  };
}

function buildLookupRequestFromOrganization(input: {
  organization: DashboardPlatformBillingOrganization;
  periodMonthUtc: string;
  eventType: 'all' | DashboardBillingAccountActivityEventType;
}): DashboardPlatformBillingLookupRequest {
  return buildLookupRequest({
    orgId: input.organization.id,
    periodMonthUtc: input.periodMonthUtc,
    eventType: input.eventType,
  });
}

function buildOrganizationKey(organization: DashboardPlatformBillingOrganization): string {
  return `organization:${organization.id}`;
}

function describeOrganizationTitle(organization: DashboardPlatformBillingOrganization): string {
  return organization.name || organization.id;
}

function describeOrganizationMeta(organization: DashboardPlatformBillingOrganization): string {
  return [organization.id, organization.status || 'ACTIVE'].filter(Boolean).join(' • ');
}

function readPlatformBillingRouteSelection(): { orgId: string; orgName: string } {
  if (typeof window === 'undefined') {
    return {
      orgId: '',
      orgName: '',
    };
  }
  const searchParams = new URLSearchParams(window.location.search);
  return {
    orgId: String(searchParams.get(PLATFORM_BILLING_ROUTE_ORG_ID_QUERY_KEY) || '').trim(),
    orgName: String(searchParams.get(PLATFORM_BILLING_ROUTE_ORG_NAME_QUERY_KEY) || '').trim(),
  };
}

function writePlatformBillingRouteSelection(input: {
  orgId: string;
  orgName?: string;
  historyMode?: 'push' | 'replace';
}): void {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.search);
  const normalizedOrgId = String(input.orgId || '').trim();
  const normalizedOrgName = String(input.orgName || '').trim();
  if (normalizedOrgId) {
    params.set(PLATFORM_BILLING_ROUTE_ORG_ID_QUERY_KEY, normalizedOrgId);
    if (normalizedOrgName) {
      params.set(PLATFORM_BILLING_ROUTE_ORG_NAME_QUERY_KEY, normalizedOrgName);
    } else {
      params.delete(PLATFORM_BILLING_ROUTE_ORG_NAME_QUERY_KEY);
    }
  } else {
    params.delete(PLATFORM_BILLING_ROUTE_ORG_ID_QUERY_KEY);
    params.delete(PLATFORM_BILLING_ROUTE_ORG_NAME_QUERY_KEY);
  }
  const nextSearch = params.toString();
  const nextUrl = `${window.location.pathname}${nextSearch ? `?${nextSearch}` : ''}${window.location.hash}`;
  const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (nextUrl !== currentUrl) {
    const historyMethod = input.historyMode === 'push' ? 'pushState' : 'replaceState';
    window.history[historyMethod]({}, '', nextUrl);
  }
}

export function PlatformBillingView(): React.JSX.Element {
  const initialRouteSelection = readPlatformBillingRouteSelection();
  const [searchInput, setSearchInput] = React.useState<string>(
    () => initialRouteSelection.orgName || initialRouteSelection.orgId,
  );
  const [isSearchDropdownOpen, setIsSearchDropdownOpen] = React.useState<boolean>(false);
  const [activeSearchIndex, setActiveSearchIndex] = React.useState<number>(-1);
  const [searchResultsMode, setSearchResultsMode] = React.useState<'recent' | 'search'>('search');
  const [periodMonthUtcFilter, setPeriodMonthUtcFilter] = React.useState<string>('');
  const [eventTypeFilter, setEventTypeFilter] = React.useState<
    'all' | DashboardBillingAccountActivityEventType
  >('all');
  const [loading, setLoading] = React.useState<boolean>(false);
  const [searchLoading, setSearchLoading] = React.useState<boolean>(false);
  const [searchError, setSearchError] = React.useState<string>('');
  const [searchResults, setSearchResults] = React.useState<DashboardPlatformBillingOrganization[]>(
    [],
  );
  const [searchPerformed, setSearchPerformed] = React.useState<boolean>(false);
  const [lookupError, setLookupError] = React.useState<string>('');
  const [lookupResult, setLookupResult] =
    React.useState<DashboardPlatformBillingLookupResult | null>(null);
  const [activeLookupRequest, setActiveLookupRequest] =
    React.useState<DashboardPlatformBillingLookupRequest | null>(null);
  const [requestedRouteSelection, setRequestedRouteSelection] = React.useState<{
    orgId: string;
    orgName: string;
  }>(() => initialRouteSelection);
  const requestedSearchValue = React.useMemo(
    () => requestedRouteSelection.orgName || requestedRouteSelection.orgId,
    [requestedRouteSelection.orgId, requestedRouteSelection.orgName],
  );
  const [isAdjustmentModalOpen, setIsAdjustmentModalOpen] = React.useState<boolean>(false);
  const [startingAdjustmentKind, setStartingAdjustmentKind] = React.useState<
    DashboardBillingManualAdjustmentKind | ''
  >('');
  const [adjustmentActionError, setAdjustmentActionError] = React.useState<string>('');
  const [adjustmentActionMessage, setAdjustmentActionMessage] = React.useState<string>('');
  const [adjustmentKind, setAdjustmentKind] =
    React.useState<DashboardBillingManualAdjustmentKind>('support_credit');
  const [adjustmentAmountInput, setAdjustmentAmountInput] = React.useState<string>('');
  const [adjustmentReasonCode, setAdjustmentReasonCode] = React.useState<string>('');
  const [adjustmentRelatedInvoiceId, setAdjustmentRelatedInvoiceId] = React.useState<string>('');
  const [adjustmentNote, setAdjustmentNote] = React.useState<string>('');
  const searchRequestIdRef = React.useRef<number>(0);
  const skipRequestedRouteSelectionEffectRef = React.useRef<boolean>(false);
  const suppressSearchValueRef = React.useRef<string>(
    initialRouteSelection.orgName || initialRouteSelection.orgId,
  );
  const searchListboxId = React.useId();
  const createAdjustmentButtonRef = React.useRef<HTMLButtonElement | null>(null);
  const wasAdjustmentModalOpenRef = React.useRef<boolean>(false);

  const resetAdjustmentDraft = React.useCallback(() => {
    setAdjustmentKind('support_credit');
    setAdjustmentAmountInput('');
    setAdjustmentReasonCode('');
    setAdjustmentRelatedInvoiceId('');
    setAdjustmentNote('');
  }, []);

  const loadLookup = React.useCallback(async (request: DashboardPlatformBillingLookupRequest) => {
    setLoading(true);
    setLookupError('');
    try {
      const result = await getDashboardPlatformBillingAccount(request);
      setLookupResult(result);
      setActiveLookupRequest(request);
      return result;
    } catch (error: unknown) {
      setLookupResult(null);
      setActiveLookupRequest(null);
      setLookupError(error instanceof Error ? error.message : String(error));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchSearchResults = React.useCallback(
    async (query: string, limit: number): Promise<DashboardPlatformBillingOrganization[]> => {
      const results = await searchDashboardPlatformBillingOrganizations({
        query,
        limit,
      });
      return query ? sortPlatformBillingOrganizations(results, query) : results;
    },
    [],
  );

  const runSearchRequest = React.useCallback(
    async (query: string, mode: 'recent' | 'search', limit: number): Promise<void> => {
      const requestId = searchRequestIdRef.current + 1;
      searchRequestIdRef.current = requestId;
      setSearchLoading(true);
      setSearchError('');
      setSearchPerformed(false);
      setSearchResultsMode(mode);
      setIsSearchDropdownOpen(true);
      try {
        const results = await fetchSearchResults(query, limit);
        if (searchRequestIdRef.current !== requestId) return;
        React.startTransition(() => {
          setSearchResults(results);
          setSearchPerformed(true);
        });
      } catch (error: unknown) {
        if (searchRequestIdRef.current !== requestId) return;
        setSearchResults([]);
        setSearchPerformed(true);
        setSearchError(error instanceof Error ? error.message : String(error));
      } finally {
        if (searchRequestIdRef.current !== requestId) return;
        setSearchLoading(false);
      }
    },
    [fetchSearchResults],
  );

  const normalizedSearchInput = React.useMemo(
    () => String(searchInput || '').trim(),
    [searchInput],
  );

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const syncRequestedRouteSelection = () => {
      setRequestedRouteSelection(readPlatformBillingRouteSelection());
    };
    window.addEventListener('popstate', syncRequestedRouteSelection);
    window.addEventListener('site:navigate', syncRequestedRouteSelection as EventListener);
    return () => {
      window.removeEventListener('popstate', syncRequestedRouteSelection);
      window.removeEventListener('site:navigate', syncRequestedRouteSelection as EventListener);
    };
  }, []);

  React.useEffect(() => {
    if (skipRequestedRouteSelectionEffectRef.current) {
      skipRequestedRouteSelectionEffectRef.current = false;
      return;
    }
    searchRequestIdRef.current += 1;
    suppressSearchValueRef.current = requestedSearchValue;
    setSearchInput(requestedSearchValue);
    setSearchLoading(false);
    setSearchError('');
    setSearchResults([]);
    setSearchPerformed(false);
    setSearchResultsMode('search');
    setLookupError('');
    setAdjustmentActionError('');
    setAdjustmentActionMessage('');
    setPeriodMonthUtcFilter('');
    setEventTypeFilter('all');
    setIsAdjustmentModalOpen(false);
    setIsSearchDropdownOpen(false);
    setActiveSearchIndex(-1);
    resetAdjustmentDraft();

    if (!requestedRouteSelection.orgId) {
      setLookupResult(null);
      setActiveLookupRequest(null);
      return;
    }

    void loadLookup(
      buildLookupRequest({
        orgId: requestedRouteSelection.orgId,
        periodMonthUtc: '',
        eventType: 'all',
      }),
    );
  }, [
    loadLookup,
    requestedRouteSelection.orgId,
    requestedSearchValue,
    resetAdjustmentDraft,
  ]);

  React.useEffect(() => {
    if (!normalizedSearchInput) {
      searchRequestIdRef.current += 1;
      writePlatformBillingRouteSelection({ orgId: '' });
      setSearchLoading(false);
      setSearchError('');
      setSearchResults([]);
      setSearchPerformed(false);
      setSearchResultsMode('search');
      setLookupResult(null);
      setActiveLookupRequest(null);
      setLookupError('');
      setAdjustmentActionError('');
      setAdjustmentActionMessage('');
      setPeriodMonthUtcFilter('');
      setEventTypeFilter('all');
      setIsAdjustmentModalOpen(false);
      setIsSearchDropdownOpen(false);
      setActiveSearchIndex(-1);
      suppressSearchValueRef.current = '';
      resetAdjustmentDraft();
      return;
    }

    if (suppressSearchValueRef.current === normalizedSearchInput) {
      suppressSearchValueRef.current = '';
      setSearchLoading(false);
      setSearchError('');
      setSearchResults([]);
      setSearchPerformed(false);
      setSearchResultsMode('search');
      setIsSearchDropdownOpen(false);
      setActiveSearchIndex(-1);
      return;
    }

    void runSearchRequest(normalizedSearchInput, 'search', PLATFORM_BILLING_SEARCH_LIMIT);
  }, [normalizedSearchInput, resetAdjustmentDraft, runSearchRequest]);

  React.useEffect(() => {
    if (!searchResults.length) {
      setActiveSearchIndex(-1);
      return;
    }
    setActiveSearchIndex((current) => {
      if (current < 0) return 0;
      return Math.min(current, searchResults.length - 1);
    });
  }, [searchResults]);

  const onLoadSearchOrganization = React.useCallback(
    async (organization: DashboardPlatformBillingOrganization) => {
      const request = buildLookupRequestFromOrganization({
        organization,
        periodMonthUtc: periodMonthUtcFilter,
        eventType: eventTypeFilter,
      });
      searchRequestIdRef.current += 1;
      suppressSearchValueRef.current = describeOrganizationTitle(organization);
      setSearchInput(describeOrganizationTitle(organization));
      setIsSearchDropdownOpen(false);
      setActiveSearchIndex(-1);
      setSearchLoading(false);
      setSearchError('');
      setSearchResults([]);
      setSearchPerformed(false);
      setLookupError('');
      setAdjustmentActionError('');
      setAdjustmentActionMessage('');
      setIsAdjustmentModalOpen(false);
      resetAdjustmentDraft();
      const result = await loadLookup(request);
      if (result) {
        skipRequestedRouteSelectionEffectRef.current = true;
        setRequestedRouteSelection({
          orgId: organization.id,
          orgName: describeOrganizationTitle(organization),
        });
        writePlatformBillingRouteSelection({
          orgId: organization.id,
          orgName: describeOrganizationTitle(organization),
          historyMode: 'push',
        });
      }
    },
    [eventTypeFilter, loadLookup, periodMonthUtcFilter, resetAdjustmentDraft],
  );

  const onSearchInputChange = React.useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const nextValue = event.target.value;
    setSearchInput(nextValue);
    setSearchError('');
    setLookupError('');
    setIsSearchDropdownOpen(Boolean(String(nextValue || '').trim()));
    setActiveSearchIndex(0);
  }, []);

  const onSearchFieldFocus = React.useCallback(() => {
    if (normalizedSearchInput) {
      setIsSearchDropdownOpen(true);
      return;
    }
    void runSearchRequest('', 'recent', PLATFORM_BILLING_RECENT_ORGANIZATION_LIMIT);
  }, [normalizedSearchInput, runSearchRequest]);

  const onSearchFieldBlur = React.useCallback((event: React.FocusEvent<HTMLDivElement>) => {
    const nextTarget = event.relatedTarget;
    if (nextTarget instanceof Node && event.currentTarget.contains(nextTarget)) {
      return;
    }
    setIsSearchDropdownOpen(false);
  }, []);

  const onSearchInputKeyDown = React.useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === 'Escape') {
        setIsSearchDropdownOpen(false);
        setActiveSearchIndex(-1);
        return;
      }
      if (event.key === 'ArrowDown') {
        if (searchResults.length === 0) return;
        event.preventDefault();
        setIsSearchDropdownOpen(true);
        setActiveSearchIndex((current) => {
          if (searchResults.length === 0) return -1;
          if (current < 0) return 0;
          return Math.min(current + 1, searchResults.length - 1);
        });
        return;
      }
      if (event.key === 'ArrowUp') {
        if (searchResults.length === 0) return;
        event.preventDefault();
        setIsSearchDropdownOpen(true);
        setActiveSearchIndex((current) => {
          if (searchResults.length === 0) return -1;
          if (current < 0) return searchResults.length - 1;
          return Math.max(current - 1, 0);
        });
        return;
      }
      if (event.key === 'Enter') {
        const selectedMatch =
          searchResults[
            activeSearchIndex >= 0 ? Math.min(activeSearchIndex, searchResults.length - 1) : 0
          ];
        if (!selectedMatch) return;
        event.preventDefault();
        void onLoadSearchOrganization(selectedMatch);
      }
    },
    [activeSearchIndex, onLoadSearchOrganization, searchResults],
  );

  const onApplyActivityFilters = React.useCallback(async () => {
    if (!activeLookupRequest) {
      setLookupError('Load a billing account before applying activity filters.');
      return;
    }
    await loadLookup(
      buildLookupRequest({
        orgId: activeLookupRequest.orgId,
        projectId: activeLookupRequest.projectId,
        periodMonthUtc: periodMonthUtcFilter,
        eventType: eventTypeFilter,
      }),
    );
  }, [activeLookupRequest, eventTypeFilter, loadLookup, periodMonthUtcFilter]);

  const onResetActivityFilters = React.useCallback(() => {
    if (!activeLookupRequest) return;
    setPeriodMonthUtcFilter('');
    setEventTypeFilter('all');
    void loadLookup(
      buildLookupRequest({
        orgId: activeLookupRequest.orgId,
        projectId: activeLookupRequest.projectId,
        periodMonthUtc: '',
        eventType: 'all',
      }),
    );
  }, [activeLookupRequest, loadLookup]);

  const onOpenAdjustmentModal = React.useCallback(() => {
    if (!lookupResult?.organization.id) return;
    setAdjustmentActionError('');
    resetAdjustmentDraft();
    setIsAdjustmentModalOpen(true);
  }, [lookupResult?.organization.id, resetAdjustmentDraft]);

  const onCloseAdjustmentModal = React.useCallback(() => {
    if (startingAdjustmentKind) return;
    setIsAdjustmentModalOpen(false);
    setAdjustmentActionError('');
    resetAdjustmentDraft();
  }, [resetAdjustmentDraft, startingAdjustmentKind]);

  const adjustmentAmountMinor = React.useMemo(
    () => parseUsdAmountInputToMinor(adjustmentAmountInput),
    [adjustmentAmountInput],
  );
  const isAdjustmentAmountValid = adjustmentAmountMinor != null && adjustmentAmountMinor > 0;
  const normalizedAdjustmentReasonCode = String(adjustmentReasonCode || '').trim();
  const normalizedAdjustmentRelatedInvoiceId = String(adjustmentRelatedInvoiceId || '').trim();
  const normalizedAdjustmentNote = String(adjustmentNote || '').trim();
  const currentCreditBalanceMinor = lookupResult?.overview.creditBalanceMinor || 0;
  const adjustmentDeltaMinor = isAdjustmentAmountValid
    ? adjustmentKind === 'support_credit'
      ? adjustmentAmountMinor
      : -adjustmentAmountMinor
    : 0;
  const projectedBalanceMinor = currentCreditBalanceMinor + adjustmentDeltaMinor;
  const adjustmentDeltaLabel =
    adjustmentDeltaMinor >= 0
      ? `+${formatUsdMinor(Math.abs(adjustmentDeltaMinor))}`
      : `-${formatUsdMinor(Math.abs(adjustmentDeltaMinor))}`;
  const adjustmentPreviewLabel = isAdjustmentAmountValid
    ? `Impact preview: ${formatUsdMinor(currentCreditBalanceMinor)} -> ${formatUsdMinor(projectedBalanceMinor)} (${adjustmentDeltaLabel}).`
    : 'Enter a positive amount to preview projected balance impact.';
  const adjustmentPreviewClassName = `dashboard-form-hint dashboard-billing-adjustment-preview${projectedBalanceMinor < 0 ? ' dashboard-billing-adjustment-preview--warning' : ''}`;
  const canSubmitManualAdjustment =
    Boolean(lookupResult?.organization.id) &&
    isAdjustmentAmountValid &&
    Boolean(normalizedAdjustmentReasonCode) &&
    Boolean(normalizedAdjustmentNote) &&
    !startingAdjustmentKind;
  const adjustmentButtonLabel =
    startingAdjustmentKind === adjustmentKind
      ? 'Applying adjustment...'
      : adjustmentKind === 'support_credit'
        ? 'Apply support credit'
        : 'Apply admin debit';

  const onAdjustmentSubmit = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (
        !lookupResult?.organization.id ||
        !canSubmitManualAdjustment ||
        adjustmentAmountMinor == null
      ) {
        return;
      }
      setStartingAdjustmentKind(adjustmentKind);
      setAdjustmentActionError('');
      setAdjustmentActionMessage('');
      const organizationLabel = lookupResult.organization.name || lookupResult.organization.id;
      const idempotencyKey = [
        'platform_billing_adjustment',
        lookupResult.organization.id,
        adjustmentKind,
        String(Date.now()),
        Math.random().toString(16).slice(2, 10),
      ].join(':');
      try {
        const result =
          adjustmentKind === 'support_credit'
            ? await createDashboardPlatformBillingManualSupportCredit({
                orgId: lookupResult.organization.id,
                amountMinor: adjustmentAmountMinor,
                reasonCode: normalizedAdjustmentReasonCode,
                note: normalizedAdjustmentNote,
                idempotencyKey,
                ...(normalizedAdjustmentRelatedInvoiceId
                  ? { relatedInvoiceId: normalizedAdjustmentRelatedInvoiceId }
                  : {}),
              })
            : await createDashboardPlatformBillingManualAdminDebit({
                orgId: lookupResult.organization.id,
                amountMinor: adjustmentAmountMinor,
                reasonCode: normalizedAdjustmentReasonCode,
                note: normalizedAdjustmentNote,
                idempotencyKey,
                ...(normalizedAdjustmentRelatedInvoiceId
                  ? { relatedInvoiceId: normalizedAdjustmentRelatedInvoiceId }
                  : {}),
              });
        const resultingBalanceLabel = formatUsdMinor(result.creditBalanceMinor);
        const amountLabel = formatUsdMinor(adjustmentAmountMinor);
        setAdjustmentActionMessage(
          result.created
            ? adjustmentKind === 'support_credit'
              ? `Granted ${amountLabel} customer ${describePlatformAdjustmentAction(adjustmentKind)} to ${organizationLabel}. Balance is now ${resultingBalanceLabel}.`
              : `Applied ${amountLabel} customer ${describePlatformAdjustmentAction(adjustmentKind)} to ${organizationLabel}. Balance is now ${resultingBalanceLabel}.`
            : `Existing customer ${describePlatformAdjustmentAction(adjustmentKind)} kept for ${organizationLabel}. Balance remains ${resultingBalanceLabel}.`,
        );
        resetAdjustmentDraft();
        setIsAdjustmentModalOpen(false);
        if (activeLookupRequest) {
          await loadLookup(activeLookupRequest);
        }
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        setAdjustmentActionError(`Failed to apply bill adjustment: ${message}`);
      } finally {
        setStartingAdjustmentKind('');
      }
    },
    [
      activeLookupRequest,
      adjustmentAmountMinor,
      adjustmentKind,
      canSubmitManualAdjustment,
      loadLookup,
      lookupResult?.organization.id,
      normalizedAdjustmentNote,
      normalizedAdjustmentReasonCode,
      normalizedAdjustmentRelatedInvoiceId,
      resetAdjustmentDraft,
    ],
  );

  const summaryMetrics = React.useMemo<BillingMetric[]>(() => {
    const overview = lookupResult?.overview;
    if (!overview) return [];
    return [
      {
        label: 'Balance',
        value: formatUsdMinor(overview.creditBalanceMinor),
        hint:
          overview.liveEnvironmentState === 'BLOCKED'
            ? 'Live environments are blocked until balance is positive'
            : overview.liveEnvironmentState === 'LOW_BALANCE'
              ? `Warning at ${formatUsdMinor(overview.lowBalanceThresholdMinor)}`
              : 'Live environments enabled',
      },
      {
        label: 'Current MAW',
        value: String(overview.monthlyActiveWallets || 0),
        hint: `${overview.currentMonthUtc} (${overview.usageMetricVersion})`,
      },
      {
        label: 'Recent usage',
        value: formatUsdMinor(overview.recentUsageDebitMinor || 0),
        hint: 'Current month debit total',
      },
      {
        label: 'Recent top-ups',
        value: formatUsdMinor(overview.recentCreditPurchasedMinor || 0),
        hint: `${overview.documentCount || 0} billing document${overview.documentCount === 1 ? '' : 's'}`,
      },
    ];
  }, [lookupResult?.overview]);

  React.useEffect(() => {
    const wasOpen = wasAdjustmentModalOpenRef.current;
    wasAdjustmentModalOpenRef.current = isAdjustmentModalOpen;
    if (!wasOpen || isAdjustmentModalOpen) return;
    const frameId = window.requestAnimationFrame(() => {
      createAdjustmentButtonRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frameId);
  }, [isAdjustmentModalOpen]);

  const accountActivityControls = (
    <div className="dashboard-billing-filters" role="group" aria-label="Platform billing filters">
      <label className="dashboard-form-field">
        <span>Period</span>
        <input
          className="dashboard-input"
          type="month"
          value={periodMonthUtcFilter}
          onChange={(event) => setPeriodMonthUtcFilter(event.target.value)}
        />
      </label>
      <label className="dashboard-form-field">
        <span>Event type</span>
        <select
          className="dashboard-input"
          value={eventTypeFilter}
          onChange={(event) =>
            setEventTypeFilter(
              String(event.target.value || '')
                .trim()
                .toUpperCase() === 'ALL'
                ? 'all'
                : (String(event.target.value || '')
                    .trim()
                    .toUpperCase() as DashboardBillingAccountActivityEventType),
            )
          }
        >
          {PLATFORM_BILLING_EVENT_TYPE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <div className="dashboard-form-actions">
        <button
          type="button"
          className="dashboard-pagination-button"
          onClick={() => {
            void onApplyActivityFilters();
          }}
          disabled={loading || !activeLookupRequest}
        >
          {loading ? 'Applying...' : 'Apply filters'}
        </button>
        <button
          type="button"
          className="dashboard-pagination-button dashboard-pagination-button--secondary"
          onClick={onResetActivityFilters}
          disabled={loading || !activeLookupRequest}
        >
          Reset filters
        </button>
      </div>
    </div>
  );

  const showSearchResults =
    isSearchDropdownOpen &&
    (searchLoading || searchPerformed || searchResults.length > 0 || Boolean(searchError));

  return (
    <>
      <section className="dashboard-view__section dashboard-billing-filters-panel dashboard-platform-billing-search-card">
        <div className="dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">
            Find Customer Organisation Billing Account
          </h3>
          <div className="dashboard-billing-filters dashboard-platform-billing-search-form">
            <div
              className="dashboard-platform-billing-search-combobox"
              onFocus={onSearchFieldFocus}
              onBlur={onSearchFieldBlur}
            >
              <label className="dashboard-form-field dashboard-platform-billing-search-form__name">
                <span>Search</span>
                <input
                  className="dashboard-input"
                  type="text"
                  role="combobox"
                  aria-autocomplete="list"
                  aria-expanded={showSearchResults}
                  aria-controls={showSearchResults ? searchListboxId : undefined}
                  aria-activedescendant={
                    showSearchResults && activeSearchIndex >= 0 && searchResults[activeSearchIndex]
                      ? `${searchListboxId}-${buildOrganizationKey(searchResults[activeSearchIndex]!)}`
                      : undefined
                  }
                  value={searchInput}
                  onChange={onSearchInputChange}
                  onKeyDown={onSearchInputKeyDown}
                  placeholder="Watchbook or org_123"
                  autoComplete="off"
                />
              </label>
              {showSearchResults ? (
                <div
                  className="dashboard-platform-billing-search-dropdown"
                  id={searchListboxId}
                  role="listbox"
                  aria-label="Platform billing search suggestions"
                >
                  {searchLoading ? (
                    <p className="dashboard-platform-billing-search-dropdown__state">
                      Searching...
                    </p>
                  ) : searchError ? (
                    <p className="dashboard-platform-billing-search-dropdown__state">
                      Search failed. Refine the customer lookup and try again.
                    </p>
                  ) : searchResults.length === 0 ? (
                    <p className="dashboard-platform-billing-search-dropdown__state">
                      {searchResultsMode === 'recent' ? (
                        'No organisations have been created yet.'
                      ) : (
                        <>
                          No customer accounts matched <code>{normalizedSearchInput || '-'}</code>.
                        </>
                      )}
                    </p>
                  ) : (
                    searchResults.map((organization, index) => {
                      const organizationKey = buildOrganizationKey(organization);
                      const isActive = index === activeSearchIndex;
                      return (
                        <button
                          key={organizationKey}
                          id={`${searchListboxId}-${organizationKey}`}
                          type="button"
                          className={`dashboard-platform-billing-search-option${isActive ? ' is-active' : ''}`}
                          role="option"
                          aria-selected={isActive}
                          onMouseDown={(event) => event.preventDefault()}
                          onMouseEnter={() => setActiveSearchIndex(index)}
                          onClick={() => {
                            void onLoadSearchOrganization(organization);
                          }}
                          disabled={loading}
                        >
                          <span className="dashboard-platform-billing-search-option__kind">
                            {searchResultsMode === 'recent' ? 'Recent' : 'Organization'}
                          </span>
                          <span className="dashboard-platform-billing-search-option__copy">
                            <strong>{describeOrganizationTitle(organization)}</strong>
                            <span>{describeOrganizationMeta(organization)}</span>
                          </span>
                        </button>
                      );
                    })
                  )}
                </div>
              ) : null}
            </div>
          </div>
          {searchError ? <p className="dashboard-form-alert">{searchError}</p> : null}
          {lookupError ? <p className="dashboard-form-alert">{lookupError}</p> : null}
        </div>
      </section>

      {lookupResult ? (
        <>
          <BillingContextSummarySection
            context={{
              organization: `${lookupResult.organization.name} (${lookupResult.organization.id})`,
              project: lookupResult.project
                ? `${lookupResult.project.name} (${lookupResult.project.id})`
                : '-',
              thirdLabel: 'Resolved by',
              thirdValue:
                lookupResult.resolvedBy === 'project_id' ? 'Project ID' : 'Organization ID',
            }}
            title="Customer Organisation Account"
            description="Reviewing customer organisation's billing account as a platform admin"
            ariaLabel="Customer organisation account summary"
            members={lookupResult.teamMembers}
            metrics={summaryMetrics}
          />

          <BillingAccountActivitySection
            accountActivity={lookupResult.activity}
            accountActivityError=""
            controls={accountActivityControls}
            emptyStateText="No ledger events match the current filters."
          />

          <section
            className="dashboard-table-wrapper dashboard-platform-billing-adjustment-shell"
            aria-label="Customer billing adjustments"
          >
            <div className="dashboard-table-limit dashboard-billing-table__intro dashboard-platform-billing-adjustment-shell__intro">
              <div className="dashboard-platform-billing-adjustment-shell__copy">
                <h3 className="dashboard-billing-table__title">Customer billing adjustments</h3>
                <p className="dashboard-billing-table__description">
                  Apply manual support credits or admin debits to{' '}
                  <code>{lookupResult.organization.id}</code>.
                </p>
              </div>
              <div className="dashboard-form-actions">
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  ref={createAdjustmentButtonRef}
                  onClick={onOpenAdjustmentModal}
                >
                  Create Bill Adjustment
                </button>
              </div>
              {adjustmentActionMessage ? (
                <p className="dashboard-info-banner">{adjustmentActionMessage}</p>
              ) : null}
            </div>
          </section>

          <DashboardInlineModal
            isOpen={isAdjustmentModalOpen}
            ariaLabel="Create Bill Adjustment modal"
            ariaLabelledBy="platform-billing-adjustment-dialog-title"
            ariaDescribedBy="platform-billing-adjustment-dialog-description"
            onRequestClose={onCloseAdjustmentModal}
            className="dashboard-billing-adjustment-card dashboard-billing-meta-card"
          >
              <h2 id="platform-billing-adjustment-dialog-title">Create Bill Adjustment</h2>
              <p
                className="dashboard-pagination-note"
                id="platform-billing-adjustment-dialog-description"
              >
                Apply manual support credits or admin debits to{' '}
                <code>{lookupResult.organization.id}</code>.
              </p>
              <form className="dashboard-billing-adjustment-form" onSubmit={onAdjustmentSubmit}>
                <div className="dashboard-billing-adjustment-grid">
                  <label className="dashboard-form-field">
                    <span>Adjustment type</span>
                    <select
                      className="dashboard-input"
                      autoFocus
                      value={adjustmentKind}
                      onChange={(event) =>
                        setAdjustmentKind(
                          String(event.target.value) === 'admin_debit'
                            ? 'admin_debit'
                            : 'support_credit',
                        )
                      }
                    >
                      <option value="support_credit">Manual support credit</option>
                      <option value="admin_debit">Manual admin debit</option>
                    </select>
                  </label>
                  <label className="dashboard-form-field">
                    <span>Amount (USD)</span>
                    <input
                      className="dashboard-input"
                      type="number"
                      min="0.01"
                      step="0.01"
                      inputMode="decimal"
                      value={adjustmentAmountInput}
                      onChange={(event) => setAdjustmentAmountInput(event.target.value)}
                      placeholder="25.00"
                    />
                  </label>
                </div>
                <label className="dashboard-form-field">
                  <span>Reason code</span>
                  <input
                    className="dashboard-input"
                    type="text"
                    value={adjustmentReasonCode}
                    onChange={(event) => setAdjustmentReasonCode(event.target.value)}
                    placeholder="incident_credit"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Related document ID (optional)</span>
                  <input
                    className="dashboard-input"
                    type="text"
                    value={adjustmentRelatedInvoiceId}
                    onChange={(event) => setAdjustmentRelatedInvoiceId(event.target.value)}
                    placeholder="receipt_bcp_xxx or inv_202603_001"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Operator note</span>
                  <textarea
                    className="dashboard-input dashboard-textarea"
                    value={adjustmentNote}
                    onChange={(event) => setAdjustmentNote(event.target.value)}
                    placeholder="Describe why this adjustment is required."
                  />
                </label>
                <p className={adjustmentPreviewClassName}>{adjustmentPreviewLabel}</p>
                <p className="dashboard-form-hint">
                  Selected action: {describeManualAdjustmentKind(adjustmentKind)}.
                </p>
                <p className="dashboard-form-hint">
                  Link a document ID to surface this adjustment on that document timeline.
                </p>
                {adjustmentActionError ? (
                  <p className="dashboard-form-alert" role="alert">
                    {adjustmentActionError}
                  </p>
                ) : null}
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button dashboard-pagination-button--secondary"
                    onClick={onCloseAdjustmentModal}
                    disabled={Boolean(startingAdjustmentKind)}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canSubmitManualAdjustment}
                  >
                    {adjustmentButtonLabel}
                  </button>
                </div>
              </form>
          </DashboardInlineModal>
        </>
      ) : (
        <section className="dashboard-view__section">
          <p>
            Search for a customer organisation name or organisation ID to review account activity
            and apply bill adjustments.
          </p>
        </section>
      )}
    </>
  );
}

export default PlatformBillingView;
