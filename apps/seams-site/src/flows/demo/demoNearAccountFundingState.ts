export type DemoNearAccountFundingStatus =
  | {
      kind: 'signed_out';
    }
  | {
      kind: 'identity_unavailable';
      missing: 'near_account_id';
      nearAccountId?: never;
    }
  | {
      kind: 'identity_unavailable';
      missing: 'near_public_key';
      nearAccountId: string;
    }
  | {
      kind: 'checking';
      nearAccountId: string;
    }
  | {
      kind: 'ready';
      nearAccountId: string;
    }
  | {
      kind: 'needs_funding';
      nearAccountId: string;
    }
  | {
      kind: 'unknown';
      nearAccountId: string;
      message: string;
    };

export type DemoNearFundingCheckResolution =
  | {
      kind: 'skip';
      status: Extract<
        DemoNearAccountFundingStatus,
        { kind: 'signed_out' | 'identity_unavailable' }
      >;
    }
  | {
      kind: 'check';
      nearAccountId: string;
      nearPublicKey: string;
    };

export type DemoNearFundingIdentity = {
  isLoggedIn: boolean;
  nearAccountId: string | null;
  nearPublicKey: string | null;
};

function normalizeDemoNearIdentityValue(value: string | null): string {
  return String(value ?? '').trim();
}

export function resolveDemoNearFundingCheck(
  identity: DemoNearFundingIdentity,
): DemoNearFundingCheckResolution {
  if (!identity.isLoggedIn) {
    return { kind: 'skip', status: { kind: 'signed_out' } };
  }
  const nearAccountId = normalizeDemoNearIdentityValue(identity.nearAccountId);
  if (!nearAccountId) {
    return {
      kind: 'skip',
      status: { kind: 'identity_unavailable', missing: 'near_account_id' },
    };
  }
  const nearPublicKey = normalizeDemoNearIdentityValue(identity.nearPublicKey);
  if (!nearPublicKey) {
    return {
      kind: 'skip',
      status: {
        kind: 'identity_unavailable',
        missing: 'near_public_key',
        nearAccountId,
      },
    };
  }
  return { kind: 'check', nearAccountId, nearPublicKey };
}

export function initialDemoNearFundingStatus(
  identity: DemoNearFundingIdentity,
): DemoNearAccountFundingStatus {
  const resolution = resolveDemoNearFundingCheck(identity);
  switch (resolution.kind) {
    case 'skip':
      return resolution.status;
    case 'check':
      return { kind: 'checking', nearAccountId: resolution.nearAccountId };
    default: {
      const exhaustive: never = resolution;
      return exhaustive;
    }
  }
}

export function demoNearFundingStatusText(status: DemoNearAccountFundingStatus): string | null {
  switch (status.kind) {
    case 'needs_funding':
      return 'NEAR account needs funding before signing.';
    case 'unknown':
      return `NEAR funding status unavailable: ${status.message}`;
    case 'identity_unavailable':
      return status.missing === 'near_account_id'
        ? 'NEAR account identity is unavailable. Refresh the wallet session.'
        : 'NEAR public key is unavailable. Refresh the wallet session.';
    /* 'checking' deliberately renders nothing: a transient "checking" line
       mounts the status slot and then unmounts it a beat later, jolting the
       buttons below it on every load (and on each needs_funding re-poll). */
    case 'checking':
    case 'signed_out':
    case 'ready':
      return null;
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

export function canStartDemoNearTransaction(status: DemoNearAccountFundingStatus): boolean {
  switch (status.kind) {
    case 'ready':
    case 'needs_funding':
      return true;
    case 'signed_out':
    case 'identity_unavailable':
    case 'checking':
    case 'unknown':
      return false;
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

export function canSignDemoNearDelegate(status: DemoNearAccountFundingStatus): boolean {
  return status.kind === 'ready';
}
