import {
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '@/pages/dashboard/consoleHttp';

export interface CreateStripeCheckoutSessionInput {
  successUrl: string;
  cancelUrl: string;
  planId?: string;
}

export interface StripeCheckoutSessionResponse {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

function readCheckoutSession(body: any): StripeCheckoutSessionResponse {
  const id = String(body?.checkoutSession?.id || '').trim();
  const url = String(body?.checkoutSession?.url || '').trim();
  const customerRef = String(body?.checkoutSession?.customerRef || '').trim();
  const expiresAt = String(body?.checkoutSession?.expiresAt || '').trim();
  if (!id || !url || !customerRef || !expiresAt) {
    throw new Error('Checkout session response is missing required fields');
  }
  return {
    id,
    url,
    customerRef,
    expiresAt,
  };
}

export async function createStripeCheckoutSession(
  input: CreateStripeCheckoutSessionInput,
): Promise<StripeCheckoutSessionResponse> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/checkout-session`, {
    method: 'POST',
    credentials: 'include',
    headers: buildConsoleJsonHeaders(),
    body: JSON.stringify({
      successUrl: input.successUrl,
      cancelUrl: input.cancelUrl,
      ...(input.planId ? { planId: input.planId } : {}),
    }),
  });
  const body = await parseConsoleJson(response);
  if (!response.ok || body?.ok === false) {
    throw new Error(consoleErrorMessage(response, body, 'Failed to create Stripe checkout session'));
  }
  return readCheckoutSession(body);
}
