export type EmailOtpRegistrationNearProvisioning =
  | { readonly status: 'near_pending' }
  | { readonly status: 'near_provisioning' }
  | { readonly status: 'near_ready' }
  | { readonly status: 'near_failed_retryable' };

type WalletSessionReader<Session> = {
  getWalletSession(walletId: string): Promise<Session>;
};

/**
 * Deferred NEAR publication can finish after registration returned its session
 * snapshot. Read the exact current session once readiness is already durable.
 */
export async function resolveEmailOtpRegistrationSession<Session>(args: {
  readonly walletId: string;
  readonly completedSession: Session;
  readonly nearProvisioning: EmailOtpRegistrationNearProvisioning | null;
  readonly auth: WalletSessionReader<Session>;
}): Promise<Session> {
  if (args.nearProvisioning?.status !== 'near_ready') return args.completedSession;
  return await args.auth.getWalletSession(args.walletId);
}
