import type {
  HostedPasskeyRegistrationPrepared,
  HostedPasskeyRegistrationPreparationInput,
} from './operations/registration/registration';
import type {
  WalletIframeAuthMenuSessionId,
  WalletIframeRequestId,
} from '@/core/types/walletIframeIdentity';
import type { RegistrationWebContext } from './signingSurface/types';
import type { RegistrationSignerSetSelection } from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

declare const context: RegistrationWebContext;
declare const requestId: WalletIframeRequestId;
declare const authMenuSessionId: WalletIframeAuthMenuSessionId;
declare const cancellationSignal: AbortSignal;
declare const signerSelection: RegistrationSignerSetSelection;

const rpIdResult = parseWebAuthnRpId('wallet.example.test');
if (!rpIdResult.ok) throw new Error('type fixture rp id is invalid');

const validPreparationInput: HostedPasskeyRegistrationPreparationInput = {
  context,
  wallet: { kind: 'server_allocated' },
  signerSelection,
  authMethod: {
    kind: 'passkey',
    rpId: rpIdResult.value,
  },
  authMenuSessionId,
  requestId,
  cancellation: { kind: 'abort_signal', signal: cancellationSignal },
};
void validPreparationInput;

// @ts-expect-error Host request identities must remain branded at this boundary.
const rawRequestId: HostedPasskeyRegistrationPreparationInput['requestId'] = 'raw-request-id';
void rawRequestId;

declare const prepared: HostedPasskeyRegistrationPrepared;
void prepared;

// @ts-expect-error Internal binding identities are not exposed on prepared values.
const exposedBinding = prepared.binding;
void exposedBinding;

// @ts-expect-error Internal cancellation identities are not exposed on prepared values.
const exposedCancellationIdentity = prepared.cancellationIdentity;
void exposedCancellationIdentity;

// @ts-expect-error Prepared continuations have one exact lifecycle kind.
const forgedPrepared: HostedPasskeyRegistrationPrepared = { kind: 'forged' };
void forgedPrepared;

export {};
