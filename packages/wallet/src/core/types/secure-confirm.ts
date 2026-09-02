/**
 * UserConfirm UI context
 *
 * This is display-only metadata shown in the wallet-origin confirmer UI.
 * It should not contain secrets (PRF outputs, keys, etc).
 */
export type PasskeyRegistrationConfirmDisplay = {
  kind: 'passkey_registration_confirm_display_v1';
  intendedUserName: string;
  accountId: string;
  rpId: string;
  signerSlot: number;
};

export interface UserConfirmSecurityContext {
  rpId?: string;
  passkeyRegistration?: PasskeyRegistrationConfirmDisplay;
  blockHeight?: string;
  blockHash?: string;
}
