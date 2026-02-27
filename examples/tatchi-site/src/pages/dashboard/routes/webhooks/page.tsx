import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
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

const WEBHOOK_SUBSCRIPTIONS = ['wallet', 'policy', 'auth', 'tx', 'billing'] as const;
const WEBHOOK_SUBSCRIPTION_SET = new Set<string>(WEBHOOK_SUBSCRIPTIONS);

function parseSubscriptions(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of String(raw || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)) {
    if (!WEBHOOK_SUBSCRIPTION_SET.has(entry)) continue;
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
  }
  return out;
}

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function WebhooksPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const [endpoints, setEndpoints] = React.useState<DashboardConsoleWebhookEndpoint[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [urlInput, setUrlInput] = React.useState<string>('');
  const [subscriptionsInput, setSubscriptionsInput] = React.useState<string>('billing');
  const [creating, setCreating] = React.useState<boolean>(false);
  const [busyEndpointId, setBusyEndpointId] = React.useState<string>('');
  const [selectedEndpointId, setSelectedEndpointId] = React.useState<string>('');

  const [deliveries, setDeliveries] = React.useState<DashboardConsoleWebhookDelivery[]>([]);
  const [deliveriesNextCursor, setDeliveriesNextCursor] = React.useState<string>('');
  const [deliveriesLoading, setDeliveriesLoading] = React.useState<boolean>(false);
  const [deliveriesError, setDeliveriesError] = React.useState<string>('');
  const [loadingMoreDeliveries, setLoadingMoreDeliveries] = React.useState<boolean>(false);
  const [replayingDeliveryId, setReplayingDeliveryId] = React.useState<string>('');

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
    (input: { endpointId: string; cursor?: string; append?: boolean }) => {
      const endpointId = String(input.endpointId || '').trim();
      if (!endpointId || !session.claims) {
        setDeliveries([]);
        setDeliveriesNextCursor('');
        setDeliveriesLoading(false);
        setLoadingMoreDeliveries(false);
        setDeliveriesError('');
        return;
      }
      const appending = input.append === true;
      if (appending) {
        setLoadingMoreDeliveries(true);
      } else {
        setDeliveriesLoading(true);
        setDeliveriesError('');
      }
      listDashboardWebhookDeliveries({
        endpointId,
        limit: 20,
        ...(input.cursor ? { cursor: input.cursor } : {}),
      })
        .then((page) => {
          setDeliveries((current) => (appending ? [...current, ...page.deliveries] : page.deliveries));
          setDeliveriesNextCursor(page.nextCursor || '');
        })
        .catch((error: unknown) => {
          if (!appending) setDeliveries([]);
          setDeliveriesNextCursor('');
          setDeliveriesError(error instanceof Error ? error.message : String(error));
        })
        .finally(() => {
          if (appending) {
            setLoadingMoreDeliveries(false);
          } else {
            setDeliveriesLoading(false);
          }
        });
    },
    [session.claims],
  );

  React.useEffect(() => {
    loadDeliveries({ endpointId: selectedEndpointId });
  }, [loadDeliveries, selectedEndpointId]);

  const onCreateEndpoint = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const url = String(urlInput || '').trim();
      const subscriptions = parseSubscriptions(subscriptionsInput);
      if (!url) {
        setMutationError('URL is required.');
        return;
      }
      if (subscriptions.length === 0) {
        setMutationError('At least one subscription is required.');
        return;
      }
      setCreating(true);
      setMutationError('');
      try {
        const endpoint = await createDashboardWebhookEndpoint({
          url,
          subscriptions,
          status: 'ACTIVE',
        });
        setUrlInput('');
        setSubscriptionsInput('billing');
        loadEndpoints();
        setSelectedEndpointId(endpoint.id);
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreating(false);
      }
    },
    [loadEndpoints, session.claims, session.errorMessage, subscriptionsInput, urlInput],
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
      <section className="dashboard-view__section" aria-label="Webhook endpoint controls">
        <h2>Create webhook endpoint</h2>
        <p>
          Webhooks are org-scoped. Current topbar context: org {selectedContext.organization || '-'},
          project {selectedContext.project || '-'}, environment {selectedContext.environment || '-'}.
        </p>
        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateEndpoint}>
          <label className="dashboard-form-field">
            <span>Endpoint URL</span>
            <input
              className="dashboard-input"
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
              placeholder="https://example.com/webhooks/tatchi"
            />
          </label>
          <label className="dashboard-form-field">
            <span>Subscriptions (comma separated)</span>
            <input
              className="dashboard-input"
              value={subscriptionsInput}
              onChange={(event) => setSubscriptionsInput(event.target.value)}
              placeholder="billing,tx"
            />
          </label>
          <div className="dashboard-form-actions">
            <button type="submit" className="dashboard-pagination-button" disabled={creating}>
              {creating ? 'Creating...' : 'Create endpoint'}
            </button>
          </div>
        </form>
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      <section className="dashboard-table-wrapper" aria-label="Webhook endpoints table">
        <div className="dashboard-table-header" role="row">
          <span>Endpoint ID</span>
          <span>URL</span>
          <span>Subscriptions</span>
          <span>Status</span>
          <span>Secret</span>
          <span>Updated</span>
          <span>Created</span>
          <span>Actions</span>
        </div>
        {session.loading || loading ? (
          <p className="dashboard-table-limit">Loading webhook endpoints...</p>
        ) : !session.claims ? (
          <p className="dashboard-table-limit">
            Webhooks unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">Webhook endpoints unavailable: {errorMessage}</p>
        ) : endpoints.length === 0 ? (
          <p className="dashboard-table-limit">No webhook endpoints configured yet.</p>
        ) : (
          <>
            {endpoints.map((endpoint) => (
              <div className="dashboard-table-row" key={endpoint.id} role="row">
                <span title={endpoint.id}>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setSelectedEndpointId(endpoint.id)}
                  >
                    {endpoint.id}
                  </button>
                </span>
                <span title={endpoint.url}>{endpoint.url}</span>
                <span title={endpoint.subscriptions.join(', ')}>
                  {endpoint.subscriptions.join(', ') || '-'}
                </span>
                <span>{endpoint.status}</span>
                <span title={endpoint.secretPreview}>
                  v{endpoint.secretVersion} {endpoint.secretPreview || ''}
                </span>
                <span>{formatTimestamp(endpoint.updatedAt)}</span>
                <span>{formatTimestamp(endpoint.createdAt)}</span>
                <span>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onToggleEndpointStatus(endpoint)}
                    disabled={busyEndpointId === endpoint.id}
                  >
                    {endpoint.status === 'ACTIVE' ? 'Disable' : 'Enable'}
                  </button>{' '}
                  <button
                    type="button"
                    className="dashboard-inline-link dashboard-inline-link--danger"
                    onClick={() => onDeleteEndpoint(endpoint.id)}
                    disabled={busyEndpointId === endpoint.id}
                  >
                    Delete
                  </button>
                </span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              Showing {endpoints.length} endpoint{endpoints.length === 1 ? '' : 's'}.
            </p>
          </>
        )}
      </section>

      <section className="dashboard-table-wrapper" aria-label="Webhook deliveries table">
        <div className="dashboard-table-header" role="row">
          <span>Delivery ID</span>
          <span>Event ID</span>
          <span>Event type</span>
          <span>Status</span>
          <span>Attempts</span>
          <span>Response</span>
          <span>Last attempt</span>
          <span>Action</span>
        </div>
        {!selectedEndpointId ? (
          <p className="dashboard-table-limit">Select an endpoint to view deliveries.</p>
        ) : deliveriesLoading ? (
          <p className="dashboard-table-limit">Loading deliveries for {selectedEndpointId}...</p>
        ) : deliveriesError ? (
          <p className="dashboard-table-limit">Deliveries unavailable: {deliveriesError}</p>
        ) : deliveries.length === 0 ? (
          <p className="dashboard-table-limit">No deliveries recorded for this endpoint yet.</p>
        ) : (
          <>
            {deliveries.map((delivery) => (
              <div className="dashboard-table-row" key={delivery.id} role="row">
                <span title={delivery.id}>{delivery.id}</span>
                <span title={delivery.eventId}>{delivery.eventId || '-'}</span>
                <span title={delivery.eventType}>{delivery.eventType || '-'}</span>
                <span>{delivery.status}</span>
                <span>
                  {delivery.attemptCount} (replays: {delivery.replayCount})
                </span>
                <span title={delivery.errorMessage || ''}>
                  {delivery.responseStatus != null ? String(delivery.responseStatus) : '-'}
                </span>
                <span>{formatTimestamp(delivery.lastAttemptAt || delivery.deliveredAt)}</span>
                <span>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onReplayDelivery(delivery.endpointId, delivery.id)}
                    disabled={replayingDeliveryId === delivery.id}
                  >
                    {replayingDeliveryId === delivery.id ? 'Replaying...' : 'Replay'}
                  </button>
                </span>
              </div>
            ))}
            <div className="dashboard-pagination-controls">
              {deliveriesNextCursor ? (
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={() =>
                    loadDeliveries({
                      endpointId: selectedEndpointId,
                      cursor: deliveriesNextCursor,
                      append: true,
                    })
                  }
                  disabled={loadingMoreDeliveries}
                >
                  {loadingMoreDeliveries ? 'Loading more...' : 'Load more deliveries'}
                </button>
              ) : (
                <span className="dashboard-pagination-note">End of delivery history.</span>
              )}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

export default WebhooksPage;
