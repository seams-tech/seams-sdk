import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import { toAccountId } from '../../types/accountIds';
import {
  buildNearProfileId,
  parseNearAccountProjectionProfileId,
  type NearAccountProjectionProfileId,
  type NearProfileId,
} from './profileId';

const walletId: WalletId = walletIdFromString('wallet-profile-typecheck');
const nearProfileId: NearProfileId = buildNearProfileId(toAccountId('profile-typecheck.testnet'));
const parsedProjectionProfileId = parseNearAccountProjectionProfileId(nearProfileId);
if (!parsedProjectionProfileId.ok) throw new Error(parsedProjectionProfileId.message);
const projectionProfileId: NearAccountProjectionProfileId = parsedProjectionProfileId.value;

void projectionProfileId;

// @ts-expect-error Wallet identity cannot be used as a NEAR projection profile key.
const invalidProjectionProfileId: NearAccountProjectionProfileId = walletId;

// @ts-expect-error NEAR projection profile keys cannot be used as wallet identity.
const invalidWalletId: WalletId = nearProfileId;

void invalidProjectionProfileId;
void invalidWalletId;
