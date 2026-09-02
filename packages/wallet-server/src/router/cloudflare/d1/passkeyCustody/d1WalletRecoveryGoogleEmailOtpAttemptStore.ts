import type { VersionedJsonObject, VersionedJsonRecordReadResult } from '../../../framework/versionedJsonRecordStore';
import {
  createCloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordScopeV1,
} from '../versionedJson/d1VersionedJsonRecordStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  parseWalletRecoveryGoogleEmailOtpAttemptRecord,
  walletRecoveryGoogleEmailOtpAttemptKey,
  type WalletRecoveryGoogleEmailOtpAttemptRecord,
} from './d1WalletRecoveryGoogleEmailOtpRecords';
import type { WalletRecoveryOperationId } from '@shared/utils/domainIds';

function encodeAttempt(record: WalletRecoveryGoogleEmailOtpAttemptRecord): VersionedJsonObject {
  return record as unknown as VersionedJsonObject;
}

/**
 * D1 persistence for the recovery-scoped Google/Email state machine. The
 * recovery code, Google credential, OTP, and factor secret never belong in
 * this record; only the server-issued operation identities and verified
 * challenge binding do.
 */
export class CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore {
  private readonly records: CloudflareD1VersionedJsonRecordStore<WalletRecoveryGoogleEmailOtpAttemptRecord>;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: CloudflareD1VersionedJsonRecordScopeV1;
  }) {
    this.records = createCloudflareD1VersionedJsonRecordStore({
      database: input.database,
      scope: input.scope,
      keyPrefix: 'wallet-recovery-google-email-otp:',
      encode: encodeAttempt,
      parse: parseWalletRecoveryGoogleEmailOtpAttemptRecord,
    });
  }

  async read(
    recoveryOperationId: WalletRecoveryOperationId,
  ): Promise<VersionedJsonRecordReadResult<WalletRecoveryGoogleEmailOtpAttemptRecord>> {
    return await this.records.read(walletRecoveryGoogleEmailOtpAttemptKey(recoveryOperationId));
  }

  async create(
    attempt: WalletRecoveryGoogleEmailOtpAttemptRecord,
  ): Promise<{ readonly kind: 'stored'; readonly version: string } | { readonly kind: 'conflict' }> {
    const result = await this.records.put(
      walletRecoveryGoogleEmailOtpAttemptKey(attempt.recoveryOperationId),
      attempt,
      null,
    );
    return result.kind === 'stored' ? result : { kind: 'conflict' };
  }

  async update(
    attempt: WalletRecoveryGoogleEmailOtpAttemptRecord,
    expectedVersion: string,
  ): Promise<{ readonly kind: 'stored'; readonly version: string } | { readonly kind: 'conflict' }> {
    const result = await this.records.put(
      walletRecoveryGoogleEmailOtpAttemptKey(attempt.recoveryOperationId),
      attempt,
      expectedVersion,
    );
    return result.kind === 'stored' ? result : { kind: 'conflict' };
  }
}
