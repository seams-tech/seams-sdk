import { buildLinkedDeviceProvisioningCommandV1 } from '@shared/device-linking/parsers';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionTransportRequestV1,
} from '@shared/device-linking/contracts';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionServiceResultV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  DeviceLinkingRouteMutationResultV1,
  DeviceLinkingOwnerSourceHandoffProviderV1,
} from '../../../../router/transport/fetch/routes/deviceLinking';

/** Direct D1 acknowledgement path owned by the linked-device session service. */
export class D1LinkedDeviceAggregateReceiptAcknowledgementV1 {
  constructor(private readonly sessionService: LinkedDeviceSessionServiceV1) {}

  async acknowledgeReceiptV1(input: {
    readonly acknowledgement: LinkedDeviceReceiptAcknowledgementV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingRouteMutationResultV1> {
    const result = await this.sessionService.recordAggregateActivationV1({
      linkSessionId: input.session.linkSessionId,
      expectedRevision: input.session.revision,
      receipt: input.acknowledgement.receipt,
      nowMs: input.requestedAtMs,
    });
    return mapCompletionMutationResultV1(result);
  }
}

function mapCompletionMutationResultV1(
  result: LinkedDeviceSessionServiceResultV1,
): DeviceLinkingRouteMutationResultV1 {
  switch (result.outcome) {
    case 'applied':
    case 'replayed':
      return { outcome: result.outcome, record: result.record };
    case 'conflict':
      return {
        outcome: 'conflict',
        expectedRevision: result.expectedRevision,
        actualRevision: result.actualRevision,
        record: result.record,
      };
    case 'expired':
      return { outcome: 'expired', record: result.record };
    case 'invalid_state':
      return { outcome: 'invalid_state', state: result.state, record: result.record };
    case 'invalid_input':
      return { outcome: 'invalid_input', message: result.message };
    case 'unauthorized':
      throw new Error(
        `aggregate activation reached an unauthorized service result: ${result.message}`,
      );
  }
}

/**
 * Replays the exact committed source handoff after a transport/process loss.
 * The retry endpoint is a read fence: it never creates a second protocol
 * effect or advances the linked-device session by itself.
 */
export class D1LinkedDeviceCommittedDeliveryRetryV1 {
  constructor(
    private readonly sourceHandoff: Pick<
      DeviceLinkingOwnerSourceHandoffProviderV1,
      'getTargetReadyV1' | 'submitPreparedProvisioningDeliveriesV1'
    > & {
      prepareProvisioningDeliveriesV1(input: {
        readonly command: import('@shared/device-linking/contracts').LinkedDeviceProvisioningCommandV1;
        readonly session: LinkedDeviceSessionRecordV1;
        readonly approval: LinkedDeviceApprovalV1;
        readonly requestedAtMs: number;
      }): Promise<import('@shared/device-linking/contracts').LinkedDeviceProvisioningDeliveriesV1>;
    },
  ) {}

  async retryCommittedDeliveryV1(input: {
    readonly request: Extract<
      LinkedDeviceSessionTransportRequestV1,
      { readonly kind: 'linked_device_session_retry_committed_delivery_request_v1' }
    >;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingRouteMutationResultV1> {
    if (input.session.state.state !== 'committed_completion_required') {
      return {
        outcome: 'invalid_state',
        state: input.session.state.state,
        record: input.session,
      };
    }
    const approval = input.session.approvalTranscript?.value;
    const recovery = input.session.recovery;
    if (!approval || !recovery) {
      return { outcome: 'invalid_input', message: 'committed delivery recovery is missing' };
    }
    if (
      input.request.linkSessionId !== input.session.linkSessionId ||
      input.request.enrollmentId !== approval.enrollmentId ||
      input.request.deviceId !== approval.deviceId
    ) {
      return { outcome: 'invalid_input', message: 'committed delivery retry identity differs' };
    }
    if (recovery.kind === 'bound') {
      if (
        recovery.continuation.linkSessionId !== input.session.linkSessionId ||
        recovery.continuation.enrollmentId !== approval.enrollmentId ||
        recovery.continuation.deviceId !== approval.deviceId
      ) {
        return { outcome: 'invalid_input', message: 'committed delivery recovery binding differs' };
      }
    }
    const deliveries = await this.sourceHandoff.prepareProvisioningDeliveriesV1({
      command: buildLinkedDeviceProvisioningCommandV1({
        linkSessionId: input.session.linkSessionId,
        enrollmentId: approval.enrollmentId,
        deviceId: approval.deviceId,
      }),
      session: input.session,
      approval,
      requestedAtMs: input.requestedAtMs,
    });
    if (
      deliveries.linkSessionId !== input.session.linkSessionId ||
      deliveries.enrollmentId !== approval.enrollmentId ||
      deliveries.deviceId !== approval.deviceId ||
      deliveries.orderedChildren.length !== approval.orderedKeyBindings.length
    ) {
      throw new Error('committed delivery replay changed its durable identity');
    }
    return { outcome: 'replayed', record: input.session };
  }
}

export type D1LinkedDeviceCompletionAdaptersV1 = {
  readonly acknowledgement: D1LinkedDeviceAggregateReceiptAcknowledgementV1;
  readonly retry: D1LinkedDeviceCommittedDeliveryRetryV1;
};

export function createD1LinkedDeviceCompletionAdaptersV1(input: {
  readonly sessionService: LinkedDeviceSessionServiceV1;
  readonly sourceHandoff: ConstructorParameters<typeof D1LinkedDeviceCommittedDeliveryRetryV1>[0];
}): D1LinkedDeviceCompletionAdaptersV1 {
  return {
    acknowledgement: new D1LinkedDeviceAggregateReceiptAcknowledgementV1(input.sessionService),
    retry: new D1LinkedDeviceCommittedDeliveryRetryV1(input.sourceHandoff),
  };
}
