/**
 * Port for the authenticated linked-device Ed25519 export-root relay.
 * Storage carries only the recipient registration and encrypted root package;
 * wallet custody seed material is never a port value.
 */
import type {
  LinkedDeviceEd25519ExportRootPackageV1,
  LinkedDeviceEd25519ExportRootRecipientV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type { LinkDeviceSessionId } from '@shared/signing-lanes/ids';

export type LinkedDeviceEd25519ExportRootConflictV1 =
  | 'recipient_already_registered_with_another_key'
  | 'recipient_not_registered'
  | 'package_addressed_to_another_recipient'
  | 'package_already_sealed_differently';

export type LinkedDeviceEd25519ExportRootWriteResultV1 =
  | { readonly outcome: 'applied' }
  | { readonly outcome: 'replayed' }
  | {
      readonly outcome: 'conflict';
      readonly reason: LinkedDeviceEd25519ExportRootConflictV1;
    };

export type LinkedDeviceEd25519ExportRootRecordV1 =
  | {
      readonly state: 'recipient_registered';
      readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
      readonly package?: never;
    }
  | {
      readonly state: 'sealed';
      readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
      readonly package: LinkedDeviceEd25519ExportRootPackageV1;
    };

export type LinkedDeviceEd25519ExportRootPortV1 = {
  readonly registerRecipientV1: (input: {
    readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
  }) => Promise<LinkedDeviceEd25519ExportRootWriteResultV1>;
  readonly submitPackageV1: (input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly package: LinkedDeviceEd25519ExportRootPackageV1;
  }) => Promise<LinkedDeviceEd25519ExportRootWriteResultV1>;
  readonly readTransferV1: (
    linkSessionId: LinkDeviceSessionId,
  ) => Promise<LinkedDeviceEd25519ExportRootRecordV1 | null>;
};
