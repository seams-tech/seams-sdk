import type { BillingCreditPack, BillingCreditPackId } from './types';

export const BILLING_CREDIT_PACK_IDS = ['usd_10', 'usd_25', 'usd_50'] as const;
export const BILLING_CREDIT_PACK_ID_SQL = BILLING_CREDIT_PACK_IDS.map((id) => `'${id}'`).join(', ');

export const BILLING_PRESET_CREDIT_PACKS: BillingCreditPack[] = [
  {
    id: 'usd_10',
    label: '$10 credit pack',
    description: 'Prepaid credits for initial testing and smaller top-ups.',
    amountMinor: 1000,
  },
  {
    id: 'usd_25',
    label: '$25 credit pack',
    description: 'Prepaid credits for a light production balance top-up.',
    amountMinor: 2500,
  },
  {
    id: 'usd_50',
    label: '$50 credit pack',
    description: 'Prepaid credits for a larger one-time balance top-up.',
    amountMinor: 5000,
  },
] as const;

const BILLING_PRESET_CREDIT_PACKS_BY_ID = new Map<BillingCreditPackId, BillingCreditPack>(
  BILLING_PRESET_CREDIT_PACKS.map((pack) => [pack.id, pack] as const),
);

export function isBillingCreditPackId(value: string): value is BillingCreditPackId {
  return BILLING_CREDIT_PACK_IDS.some((packId) => packId === value);
}

export function resolveCreditPackAmountMinorOrThrow(creditPackId: BillingCreditPackId): number {
  const preset = BILLING_PRESET_CREDIT_PACKS_BY_ID.get(creditPackId);
  if (!preset) throw new Error(`Unknown configured billing credit pack: ${creditPackId}`);
  return preset.amountMinor;
}
