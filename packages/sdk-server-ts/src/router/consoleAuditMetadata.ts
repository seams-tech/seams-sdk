import type {
  BillingCreditPurchase,
  BillingInvoice,
  GenerateMonthlyInvoiceResult,
} from '../console/billing';
import type {
  ConsolePolicy,
  ConsolePolicyAssignment,
  CreateConsolePolicyAssignmentInput,
} from '../console/policies';
import type { ConsoleWebhookDelivery, ConsoleWebhookEndpoint } from '../console/webhooks';

type PolicyAssignmentScopeInput = Pick<CreateConsolePolicyAssignmentInput, 'scopeType' | 'scopeId'>;

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function readPolicyScopeFromRules(
  policy: ConsolePolicy,
): {
  projectId?: string;
  environmentId?: string;
  metadata: Record<string, unknown>;
} {
  if (policy.kind !== 'GAS_SPONSORSHIP') {
    return { metadata: {} };
  }

  const rules =
    policy.rules && typeof policy.rules === 'object' && !Array.isArray(policy.rules)
      ? (policy.rules as unknown as Record<string, unknown>)
      : {};
  const scopeType = normalizeString(rules.scopeType);
  const projectId = normalizeString(rules.projectId);
  const environmentId = normalizeString(rules.environmentId);
  const scopePolicyId = normalizeString(rules.scopePolicyId);
  const walletSegmentId = normalizeString(rules.walletSegmentId);

  return {
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    metadata: {
      ...(scopeType ? { scopeType } : {}),
      ...(projectId ? { projectId } : {}),
      ...(environmentId ? { environmentId } : {}),
      ...(scopePolicyId ? { scopePolicyId } : {}),
      ...(walletSegmentId ? { walletSegmentId } : {}),
    },
  };
}

function readAssignmentScope(
  assignment: PolicyAssignmentScopeInput | undefined,
): {
  projectId?: string;
  environmentId?: string;
  metadata: Record<string, unknown>;
} {
  const scopeType = normalizeString(assignment?.scopeType).toUpperCase();
  const scopeId = normalizeString(assignment?.scopeId);
  return {
    ...(scopeType === 'PROJECT' && scopeId ? { projectId: scopeId } : {}),
    ...(scopeType === 'ENVIRONMENT' && scopeId ? { environmentId: scopeId } : {}),
    metadata: {
      ...(scopeType ? { assignmentScopeType: scopeType } : {}),
      ...(scopeId ? { assignmentScopeId: scopeId } : {}),
    },
  };
}

function summarizePolicyAction(action: string, policyId: string): string {
  if (action === 'policy.create') return `Created policy ${policyId}`;
  if (action === 'policy.update') return `Updated policy ${policyId}`;
  if (action === 'policy.delete') return `Deleted policy ${policyId}`;
  if (action === 'policy.publish') return `Published policy ${policyId}`;
  return `Updated policy ${policyId}`;
}

function summarizePolicyAssignmentAction(input: {
  action: 'policy.assignment.upsert' | 'policy.assignment.delete';
  assignment: ConsolePolicyAssignment;
}): string {
  const scopeType = normalizeString(input.assignment.scopeType).toUpperCase() || 'SCOPE';
  if (input.action === 'policy.assignment.delete') {
    return `Removed policy assignment ${input.assignment.id} from ${scopeType} ${input.assignment.scopeId}`;
  }
  return `Assigned policy ${input.assignment.policyId} to ${scopeType} ${input.assignment.scopeId}`;
}

export function buildConsolePolicyAuditEvent(input: {
  action: 'policy.create' | 'policy.update' | 'policy.delete' | 'policy.publish';
  policy: ConsolePolicy;
  assignment?: CreateConsolePolicyAssignmentInput;
  extraMetadata?: Record<string, unknown>;
}): {
  summary: string;
  metadata: Record<string, unknown>;
  projectId?: string;
  environmentId?: string;
} {
  const policyScope = readPolicyScopeFromRules(input.policy);
  const assignmentScope = readAssignmentScope(input.assignment);
  return {
    summary: summarizePolicyAction(input.action, input.policy.id),
    metadata: {
      policyId: input.policy.id,
      policyName: input.policy.name,
      policyKind: input.policy.kind,
      status: input.policy.status,
      version: input.policy.version,
      isSystemDefault: input.policy.isSystemDefault,
      ...(input.policy.description ? { description: input.policy.description } : {}),
      ...policyScope.metadata,
      ...assignmentScope.metadata,
      ...(input.extraMetadata ? input.extraMetadata : {}),
    },
    ...(policyScope.projectId
      ? { projectId: policyScope.projectId }
      : assignmentScope.projectId
        ? { projectId: assignmentScope.projectId }
        : {}),
    ...(policyScope.environmentId
      ? { environmentId: policyScope.environmentId }
      : assignmentScope.environmentId
        ? { environmentId: assignmentScope.environmentId }
        : {}),
  };
}

export function buildConsolePolicyAssignmentAuditEvent(input: {
  action: 'policy.assignment.upsert' | 'policy.assignment.delete';
  assignment: ConsolePolicyAssignment;
  policy?: ConsolePolicy | null;
}): {
  summary: string;
  metadata: Record<string, unknown>;
  projectId?: string;
  environmentId?: string;
} {
  const assignmentScope = readAssignmentScope(input.assignment);
  return {
    summary: summarizePolicyAssignmentAction(input),
    metadata: {
      assignmentId: input.assignment.id,
      policyId: input.assignment.policyId,
      assignmentScopeType: input.assignment.scopeType,
      assignmentScopeId: input.assignment.scopeId,
      assignmentCreatedAt: input.assignment.createdAt,
      assignmentUpdatedAt: input.assignment.updatedAt,
      ...(input.policy
        ? {
            policyName: input.policy.name,
            policyKind: input.policy.kind,
            status: input.policy.status,
            version: input.policy.version,
            isSystemDefault: input.policy.isSystemDefault,
          }
        : {}),
    },
    ...(assignmentScope.projectId ? { projectId: assignmentScope.projectId } : {}),
    ...(assignmentScope.environmentId ? { environmentId: assignmentScope.environmentId } : {}),
  };
}

export function buildConsoleBillingCreditPurchaseSettledAuditEvent(input: {
  purchase: BillingCreditPurchase;
  invoice: BillingInvoice | null;
  source: 'stripe_webhook' | 'stripe_checkout_reconcile';
  settlementEventId?: string;
}): {
  summary: string;
  metadata: Record<string, unknown>;
} {
  return {
    summary: `Settled Stripe credit purchase ${input.purchase.id}`,
    metadata: {
      purchaseId: input.purchase.id,
      creditPackId: input.purchase.creditPackId,
      amountMinor: input.purchase.amountMinor,
      currency: input.purchase.currency,
      purchaseStatus: input.purchase.status,
      provider: input.purchase.provider,
      providerCheckoutSessionRef: input.purchase.providerCheckoutSessionRef,
      ...(input.purchase.providerCustomerRef
        ? { providerCustomerRef: input.purchase.providerCustomerRef }
        : {}),
      ...(input.purchase.relatedInvoiceId ? { relatedInvoiceId: input.purchase.relatedInvoiceId } : {}),
      ...(input.purchase.settledAt ? { settledAt: input.purchase.settledAt } : {}),
      settlementSource: input.source,
      ...(input.settlementEventId ? { settlementEventId: input.settlementEventId } : {}),
      ...(input.invoice
        ? {
            receiptId: input.invoice.id,
            receiptStatus: input.invoice.status,
            receiptDocumentType: input.invoice.documentType,
          }
        : {}),
    },
  };
}

export function buildConsoleBillingInvoiceGeneratedAuditEvent(input: {
  generation: GenerateMonthlyInvoiceResult;
}): {
  summary: string;
  metadata: Record<string, unknown>;
} {
  return {
    summary: input.generation.generated
      ? `Generated monthly invoice ${input.generation.invoice.id}`
      : `Refreshed monthly invoice ${input.generation.invoice.id}`,
    metadata: {
      invoiceId: input.generation.invoice.id,
      invoiceStatus: input.generation.invoice.status,
      invoiceDocumentType: input.generation.invoice.documentType,
      periodMonthUtc: input.generation.invoice.periodMonthUtc,
      currency: input.generation.invoice.currency,
      amountDueMinor: input.generation.invoice.amountDueMinor,
      amountPaidMinor: input.generation.invoice.amountPaidMinor,
      ...(input.generation.invoice.dueAt ? { dueAt: input.generation.invoice.dueAt } : {}),
      generated: input.generation.generated,
      monthlyActiveWallets: input.generation.monthlyActiveWallets,
      lineItemCount: input.generation.lineItems.length,
      mawUnitPriceMinor: input.generation.pricing.mawUnitPriceMinor,
    },
  };
}

function summarizeWebhookEndpointAction(action: string, endpointId: string): string {
  if (action === 'webhook.endpoint.create') return `Created webhook endpoint ${endpointId}`;
  if (action === 'webhook.endpoint.update') return `Updated webhook endpoint ${endpointId}`;
  if (action === 'webhook.endpoint.delete') return `Deleted webhook endpoint ${endpointId}`;
  return `Updated webhook endpoint ${endpointId}`;
}

export function buildConsoleWebhookEndpointAuditEvent(input: {
  action: 'webhook.endpoint.create' | 'webhook.endpoint.update' | 'webhook.endpoint.delete';
  endpoint: ConsoleWebhookEndpoint;
}): {
  summary: string;
  metadata: Record<string, unknown>;
} {
  return {
    summary: summarizeWebhookEndpointAction(input.action, input.endpoint.id),
    metadata: {
      endpointId: input.endpoint.id,
      endpointUrl: input.endpoint.url,
      endpointStatus: input.endpoint.status,
      eventCategories: [...input.endpoint.eventCategories],
      secretVersion: input.endpoint.secretVersion,
      secretPreview: input.endpoint.secretPreview,
      endpointCreatedAt: input.endpoint.createdAt,
      endpointUpdatedAt: input.endpoint.updatedAt,
    },
  };
}

export function buildConsoleWebhookReplayAuditEvent(input: {
  endpointId: string;
  delivery: ConsoleWebhookDelivery;
  requestedDeliveryId?: string;
}): {
  summary: string;
  metadata: Record<string, unknown>;
} {
  const selectionMode = normalizeString(input.requestedDeliveryId)
    ? 'explicit_delivery'
    : 'latest_replayable_delivery';
  return {
    summary: `Requested replay for webhook delivery ${input.delivery.id}`,
    metadata: {
      endpointId: input.endpointId,
      deliveryId: input.delivery.id,
      deliveryEventId: input.delivery.eventId,
      deliveryEventType: input.delivery.eventType,
      deliveryStatus: input.delivery.status,
      attemptCount: input.delivery.attemptCount,
      replayCount: input.delivery.replayCount,
      ...(input.delivery.responseStatus !== null
        ? { responseStatus: input.delivery.responseStatus }
        : {}),
      ...(input.delivery.errorMessage ? { errorMessage: input.delivery.errorMessage } : {}),
      ...(input.delivery.lastAttemptAt ? { lastAttemptAt: input.delivery.lastAttemptAt } : {}),
      ...(input.delivery.deliveredAt ? { deliveredAt: input.delivery.deliveredAt } : {}),
      selectionMode,
      ...(input.requestedDeliveryId ? { requestedDeliveryId: input.requestedDeliveryId } : {}),
    },
  };
}
