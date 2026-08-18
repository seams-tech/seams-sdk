/**
 * Refactor 103 Phase 8 — the port the custody-transfer routes depend on.
 *
 * Lives in core rather than beside the D1 adapter so the transport layer
 * depends on the contract and not on a storage implementation, matching
 * `LinkedDeviceManagementProjectionPortV1`.
 */
import type {
  LinkedDeviceCustodyTransferPackageV1,
  LinkedDeviceCustodyTransferRecipientV1,
} from '@shared/device-linking/custodyTransfer';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';

/**
 * Why a write could not apply. Each names the exact identity that disagreed,
 * so Device 1 and Device 2 can tell "you are too early" from "someone else
 * already sealed this" without inspecting storage.
 */
export type LinkedDeviceCustodyTransferConflictV1 =
  | 'recipient_already_registered_with_another_key'
  | 'recipient_not_registered'
  | 'package_addressed_to_another_recipient'
  | 'package_already_sealed_differently';

/**
 * A replay is normal — both devices retry over an unreliable relay — so it is
 * a distinct success rather than a conflict.
 */
export type LinkedDeviceCustodyTransferWriteResultV1 =
  | { readonly outcome: 'applied' }
  | { readonly outcome: 'replayed' }
  | { readonly outcome: 'conflict'; readonly reason: LinkedDeviceCustodyTransferConflictV1 };

export type LinkedDeviceCustodyTransferRecordV1 =
  | {
      readonly state: 'recipient_registered';
      readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
      readonly package?: never;
    }
  | {
      readonly state: 'sealed';
      readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
      readonly package: LinkedDeviceCustodyTransferPackageV1;
    };

export type LinkedDeviceCustodyTransferPortV1 = {
  readonly registerRecipientV1: (input: {
    readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
  }) => Promise<LinkedDeviceCustodyTransferWriteResultV1>;
  readonly submitPackageV1: (input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly package: LinkedDeviceCustodyTransferPackageV1;
  }) => Promise<LinkedDeviceCustodyTransferWriteResultV1>;
  readonly readTransferV1: (
    linkSessionId: LinkDeviceSessionId,
  ) => Promise<LinkedDeviceCustodyTransferRecordV1 | null>;
};
