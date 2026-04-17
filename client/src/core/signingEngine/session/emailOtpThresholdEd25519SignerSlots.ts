import type { AccountSignerRecord } from '../../indexedDB/passkeyClientDB.types';

export type EmailOtpThresholdEd25519SignerSlotPlan = {
  signerSlot: number;
  staleSignerIds: string[];
};

export function planEmailOtpThresholdEd25519SignerSlot(args: {
  activeSigners: readonly Pick<
    AccountSignerRecord,
    'signerId' | 'signerSlot' | 'signerType'
  >[];
  signerId: string;
}): EmailOtpThresholdEd25519SignerSlotPlan {
  const signerId = String(args.signerId || '').trim();
  if (!signerId) {
    throw new Error('Email OTP threshold-ed25519 signer slot planning requires signerId');
  }

  const activeSigners = Array.isArray(args.activeSigners) ? args.activeSigners : [];
  const existingSigner = activeSigners.find((signer) => signer.signerId === signerId);
  const staleSignerIds = activeSigners
    .filter(
      (signer) =>
        signer.signerId !== signerId &&
        signer.signerType === 'threshold' &&
        signer.signerId.startsWith('threshold-ed25519:'),
    )
    .map((signer) => signer.signerId);
  if (existingSigner) {
    return {
      signerSlot: existingSigner.signerSlot,
      staleSignerIds,
    };
  }

  const staleSignerIdSet = new Set(staleSignerIds);
  const reservedSlots = new Set(
    activeSigners
      .filter((signer) => !staleSignerIdSet.has(signer.signerId))
      .map((signer) => signer.signerSlot),
  );
  for (let slot = 1; slot < 1000; slot += 1) {
    if (!reservedSlots.has(slot)) {
      return {
        signerSlot: slot,
        staleSignerIds,
      };
    }
  }
  throw new Error('No available Email OTP threshold-ed25519 signer slot');
}
