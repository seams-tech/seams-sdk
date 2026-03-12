import React from 'react';
import {
  CONSOLE_WEBHOOK_EVENT_CATEGORIES,
  type ConsoleWebhookEventCategory,
} from '../../../../../../../shared/src/console/webhookEventCategories';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import { ScopePicker, type DashboardScopeOption } from '../../components/ScopePicker';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  createDashboardWebhookEndpoint,
  deleteDashboardWebhookEndpoint,
  listDashboardWebhookDeliveries,
  listDashboardWebhookEndpoints,
  replayDashboardWebhookDelivery,
  updateDashboardWebhookEndpoint,
  type DashboardConsoleWebhookDelivery,
  type DashboardConsoleWebhookEndpoint,
} from './consoleWebhooksApi';

const DEFAULT_WEBHOOK_EVENT_CATEGORIES: ConsoleWebhookEventCategory[] = ['billing'];
const WEBHOOK_EVENT_CATEGORY_OPTIONS: readonly DashboardScopeOption[] =
  CONSOLE_WEBHOOK_EVENT_CATEGORIES.map((value) => ({
    value,
    label:
      value === 'tx'
        ? 'Transaction lifecycle'
        : value === 'auth'
          ? 'Authentication'
          : value === 'policy'
            ? 'Policy changes'
            : value === 'wallet'
              ? 'Wallet activity'
              : value === 'billing'
                ? 'Billing'
                : 'Session lifecycle',
    description:
      value === 'tx'
        ? 'Transaction creation, signing, submission, and status transitions.'
        : value === 'auth'
          ? 'Authentication and identity lifecycle events.'
          : value === 'policy'
            ? 'Policy publish, assignment, and approval events.'
            : value === 'wallet'
              ? 'Wallet provisioning, configuration, and state changes.'
              : value === 'billing'
                ? 'Invoices, usage, and payment lifecycle events.'
                : 'Session creation, refresh, and teardown events.',
  }));
const WEBHOOK_ENDPOINTS_TABLE_COLUMNS = dashboardTableColumns(
  1,
  1.45,
  1.05,
  0.7,
  0.85,
  0.85,
  0.85,
  0.95,
);
const WEBHOOK_DELIVERIES_TABLE_COLUMNS = dashboardTableColumns(
  1,
  0.95,
  0.9,
  0.65,
  0.8,
  0.75,
  0.9,
  0.8,
);

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function WebhooksPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const [endpoints, setEndpoints] = React.useState<DashboardConsoleWebhookEndpoint[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [isCreateModalOpen, setIsCreateModalOpen] = React.useState<boolean>(false);
  const [urlInput, setUrlInput] = React.useState<string>('');
  const [eventCategories, setEventCategories] = React.useState<ConsoleWebhookEventCategory[]>(
    DEFAULT_WEBHOOK_EVENT_CATEGORIES,
  );
  const [creating, setCreating] = React.useState<boolean>(false);
  const [busyEndpointId, setBusyEndpointId] = React.useState<string>('');
  const [selectedEndpointId, setSelectedEndpointId] = React.useState<string>('');

  const [deliveries, setDeliveries] = React.useState<DashboardConsoleWebhookDelivery[]>([]);
  const [deliveriesLoading, setDeliveriesLoading] = React.useState<boolean>(false);
  const [deliveriesError, setDeliveriesError] = React.useState<string>('');
  const [replayingDeliveryId, setReplayingDeliveryId] = React.useState<string>('');
  const endpointsPagination = useDashboardTablePagination(endpoints, {
    disabled: session.loading || loading,
    itemLabel: 'endpoint',
    itemLabelPlural: 'endpoints',
  });
  const deliveriesPagination = useDashboardTablePagination(deliveries, {
    disabled: deliveriesLoading,
    itemLabel: 'delivery',
    itemLabelPlural: 'deliveries',
  });

  const loadEndpoints = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setEndpoints([]);
      setSelectedEndpointId('');
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardWebhookEndpoints()
      .then((rows) => {
        if (cancelled) return;
        const next = [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        setEndpoints(next);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setEndpoints([]);
        setSelectedEndpointId('');
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
    const cleanup = loadEndpoints();
    return cleanup;
  }, [loadEndpoints, session.loading]);

  React.useEffect(() => {
    if (endpoints.length === 0) {
      setSelectedEndpointId('');
      return;
    }
    if (selectedEndpointId && endpoints.some((entry) => entry.id === selectedEndpointId)) return;
    setSelectedEndpointId(endpoints[0]?.id || '');
  }, [endpoints, selectedEndpointId]);

  const loadDeliveries = React.useCallback(
    (input: { endpointId: string }) => {
      const endpointId = String(input.endpointId || '').trim();
      if (!endpointId || !session.claims) {
        setDeliveries([]);
        setDeliveriesLoading(false);
        setDeliveriesError('');
        return;
      }
      setDeliveriesLoading(true);
      setDeliveriesError('');
      void (async () => {
        try {
          let cursor = '';
          const allDeliveries: DashboardConsoleWebhookDelivery[] = [];
          for (;;) {
            const page = await listDashboardWebhookDeliveries({
              endpointId,
              limit: 100,
              ...(cursor ? { cursor } : {}),
            });
            allDeliveries.push(...page.deliveries);
            cursor = String(page.nextCursor || '').trim();
            if (!cursor) break;
          }
          setDeliveries(allDeliveries);
        } catch (error: unknown) {
          setDeliveries([]);
          setDeliveriesError(error instanceof Error ? error.message : String(error));
        } finally {
          setDeliveriesLoading(false);
        }
      })();
    },
    [session.claims],
  );

  React.useEffect(() => {
    loadDeliveries({ endpointId: selectedEndpointId });
  }, [loadDeliveries, selectedEndpointId]);

  const onOpenCreateModal = React.useCallback(() => {
    setIsCreateModalOpen(true);
    setMutationError('');
  }, []);

  const onCloseCreateModal = React.useCallback(() => {
    if (creating) return;
    setIsCreateModalOpen(false);
    setMutationError('');
  }, [creating]);

  const onCreateEndpoint = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const url = String(urlInput || '').trim();
      if (!url) {
        setMutationError('URL is required.');
        return;
      }
      if (eventCategories.length === 0) {
        setMutationError('At least one event category is required.');
        return;
      }
      setCreating(true);
      setMutationError('');
      try {
        const endpoint = await createDashboardWebhookEndpoint({
          url,
          eventCategories,
          status: 'ACTIVE',
        });
        setUrlInput('');
        setEventCategories([...DEFAULT_WEBHOOK_EVENT_CATEGORIES]);
        setIsCreateModalOpen(false);
        loadEndpoints();
        setSelectedEndpointId(endpoint.id);
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreating(false);
      }
    },
    [eventCategories, loadEndpoints, session.claims, session.errorMessage, urlInput],
  );

  const onToggleEndpointStatus = React.useCallback(
    async (endpoint: DashboardConsoleWebhookEndpoint) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setBusyEndpointId(endpoint.id);
      setMutationError('');
      try {
        await updateDashboardWebhookEndpoint({
          endpointId: endpoint.id,
          status: endpoint.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE',
        });
        loadEndpoints();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyEndpointId('');
      }
    },
    [loadEndpoints, session.claims, session.errorMessage],
  );

  const onDeleteEndpoint = React.useCallback(
    async (endpointId: string) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!window.confirm(`Delete webhook endpoint ${endpointId}?`)) return;
      setBusyEndpointId(endpointId);
      setMutationError('');
      try {
        await deleteDashboardWebhookEndpoint({ endpointId });
        if (selectedEndpointId === endpointId) {
          setSelectedEndpointId('');
        }
        loadEndpoints();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyEndpointId('');
      }
    },
    [loadEndpoints, selectedEndpointId, session.claims, session.errorMessage],
  );

  const onReplayDelivery = React.useCallback(
    async (endpointId: string, deliveryId: string) => {
      if (!session.claims) {
        setDeliveriesError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setReplayingDeliveryId(deliveryId);
      setDeliveriesError('');
      try {
        await replayDashboardWebhookDelivery({ endpointId, deliveryId });
        loadDeliveries({ endpointId });
      } catch (error: unknown) {
        setDeliveriesError(error instanceof Error ? error.message : String(error));
      } finally {
        setReplayingDeliveryId('');
      }
    },
    [loadDeliveries, session.claims, session.errorMessage],
  );

  return (
    <div className="dashboard-view" aria-label="Webhooks page">
      <section
        className="dashboard-view__section dashboard-view__section--toolbar"
        aria-label="Webhook endpoint controls"
      >
        <div className="dashboard-section-toolbar dashboard-section-toolbar--stacked-start">
          <div className="dashboard-section-toolbar__copy">
            <h2>Webhook endpoints</h2>
            <p className="dashboard-form-hint">
              Register delivery URLs and subscribe them to the event categories your integration
              needs.
            </p>
          </div>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={onOpenCreateModal}
            disabled={creating || session.loading || !session.claims}
          >
            Create Webhook
          </button>
        </div>
      </section>

      {mutationError && !isCreateModalOpen ? (
        <p className="dashboard-form-alert" role="alert">
          {mutationError}
        </p>
      ) : null}

      <DashboardTable
        ariaLabel="Webhook endpoints table"
        columns={WEBHOOK_ENDPOINTS_TABLE_COLUMNS}
        pagination={endpointsPagination.pagination}
      >
        <DashboardTableHeader>
          <DashboardTableHeaderCell>Endpoint ID</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>URL</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Event categories</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Secret</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Updated</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Created</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {session.loading || loading ? (
          <DashboardTableState>Loading webhook endpoints...</DashboardTableState>
        ) : !session.claims ? (
          <DashboardTableState>
            Webhooks unavailable: {session.errorMessage || 'unauthorized'}.
          </DashboardTableState>
        ) : errorMessage ? (
          <DashboardTableState>Webhook endpoints unavailable: {errorMessage}</DashboardTableState>
        ) : endpoints.length === 0 ? (
          <DashboardTableState>No webhook endpoints configured yet.</DashboardTableState>
        ) : (
          <>
            {endpointsPagination.rows.map((endpoint) => (
              <DashboardTableRow key={endpoint.id}>
                <DashboardTableCell title={endpoint.id}>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setSelectedEndpointId(endpoint.id)}
                  >
                    {endpoint.id}
                  </button>
                </DashboardTableCell>
                <DashboardTableCell title={endpoint.url}>{endpoint.url}</DashboardTableCell>
                <DashboardTableCell title={endpoint.eventCategories.join(', ')}>
                  {endpoint.eventCategories.join(', ') || '-'}
                </DashboardTableCell>
                <DashboardTableCell>{endpoint.status}</DashboardTableCell>
                <DashboardTableCell title={endpoint.secretPreview}>
                  v{endpoint.secretVersion} {endpoint.secretPreview || ''}
                </DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(endpoint.updatedAt)}
                </DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(endpoint.createdAt)}
                </DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableActionGroup>
                    <DashboardTableActionButton
                      onClick={() => onToggleEndpointStatus(endpoint)}
                      disabled={busyEndpointId === endpoint.id}
                    >
                      {endpoint.status === 'ACTIVE' ? 'Disable' : 'Enable'}
                    </DashboardTableActionButton>
                    <DashboardTableActionButton
                      tone="danger"
                      onClick={() => onDeleteEndpoint(endpoint.id)}
                      disabled={busyEndpointId === endpoint.id}
                    >
                      Delete
                    </DashboardTableActionButton>
                  </DashboardTableActionGroup>
                </DashboardTableCell>
              </DashboardTableRow>
            ))}
          </>
        )}
      </DashboardTable>

      <DashboardInlineModal
        isOpen={isCreateModalOpen}
        ariaLabel="Create webhook modal"
        onRequestClose={onCloseCreateModal}
      >
        <h2>Create Webhook</h2>
        <form className="dashboard-view-grid dashboard-webhook-form" onSubmit={onCreateEndpoint}>
          <label className="dashboard-form-field dashboard-webhook-form__field">
            <span>Endpoint URL</span>
            <input
              className="dashboard-input"
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
              placeholder="https://example.com/webhooks/tatchi"
              disabled={creating}
            />
          </label>
          <ScopePicker
            label="Event categories"
            options={WEBHOOK_EVENT_CATEGORY_OPTIONS}
            values={eventCategories}
            onChange={(next) => setEventCategories(next as ConsoleWebhookEventCategory[])}
            disabled={creating}
            addLabel=""
            emptyLabel="No event categories selected."
            placeholderLabel="Select an event category"
          />
          {mutationError ? (
            <p className="dashboard-form-alert" role="alert">
              {mutationError}
            </p>
          ) : null}
          <div className="dashboard-form-actions dashboard-webhook-form__actions">
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={onCloseCreateModal}
              disabled={creating}
            >
              Cancel
            </button>
            <button type="submit" className="dashboard-pagination-button" disabled={creating}>
              {creating ? 'Creating...' : 'Create endpoint'}
            </button>
          </div>
        </form>
      </DashboardInlineModal>

      <DashboardTable
        ariaLabel="Webhook deliveries table"
        columns={WEBHOOK_DELIVERIES_TABLE_COLUMNS}
        pagination={selectedEndpointId ? deliveriesPagination.pagination : undefined}
      >
        <DashboardTableHeader>
          <DashboardTableHeaderCell>Delivery ID</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Event ID</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Event type</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Attempts</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Response</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Last attempt</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Action</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {!selectedEndpointId ? (
          <DashboardTableState>Select an endpoint to view deliveries.</DashboardTableState>
        ) : deliveriesLoading ? (
          <DashboardTableState>Loading deliveries for {selectedEndpointId}...</DashboardTableState>
        ) : deliveriesError ? (
          <DashboardTableState>Deliveries unavailable: {deliveriesError}</DashboardTableState>
        ) : deliveries.length === 0 ? (
          <DashboardTableState>No deliveries recorded for this endpoint yet.</DashboardTableState>
        ) : (
          <>
            {deliveriesPagination.rows.map((delivery) => (
              <DashboardTableRow key={delivery.id}>
                <DashboardTableCell title={delivery.id}>{delivery.id}</DashboardTableCell>
                <DashboardTableCell title={delivery.eventId}>
                  {delivery.eventId || '-'}
                </DashboardTableCell>
                <DashboardTableCell title={delivery.eventType}>
                  {delivery.eventType || '-'}
                </DashboardTableCell>
                <DashboardTableCell>{delivery.status}</DashboardTableCell>
                <DashboardTableCell>
                  {delivery.attemptCount} (replays: {delivery.replayCount})
                </DashboardTableCell>
                <DashboardTableCell title={delivery.errorMessage || ''}>
                  {delivery.responseStatus != null ? String(delivery.responseStatus) : '-'}
                </DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(delivery.lastAttemptAt || delivery.deliveredAt)}
                </DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableActionButton
                    onClick={() => onReplayDelivery(delivery.endpointId, delivery.id)}
                    disabled={replayingDeliveryId === delivery.id}
                  >
                    {replayingDeliveryId === delivery.id ? 'Replaying...' : 'Replay'}
                  </DashboardTableActionButton>
                </DashboardTableCell>
              </DashboardTableRow>
            ))}
          </>
        )}
      </DashboardTable>
    </div>
  );
}

export default WebhooksPage;
