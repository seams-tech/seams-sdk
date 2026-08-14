import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';

export type WalletCustodyAdminOperation =
  | 'credentials_list'
  | 'credential_label'
  | 'recovery_acknowledge'
  | 'recovery_rotate'
  | 'recovery_read';

/** Public challenge digest for a single wallet-administration factor proof. */
export async function computeWalletCustodyAdminChallengeDigest(input: {
  readonly walletId: string;
  readonly operation: WalletCustodyAdminOperation;
  readonly payload: Record<string, unknown>;
  readonly requestOrigin: string;
}): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `seams:wallet-custody:challenge:v1|${alphabetizeStringify({
          walletId: input.walletId,
          operation: input.operation,
          payload: input.payload,
          requestOrigin: input.requestOrigin,
        })}`,
      ),
    ),
  );
}
