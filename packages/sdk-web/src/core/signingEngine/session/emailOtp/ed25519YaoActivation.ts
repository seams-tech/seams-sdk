import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  registerProductEd25519YaoV1,
  type ProductEd25519YaoPendingRegistrationPortV1,
} from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoRecoveryResultV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  EmailOtpEd25519YaoRootVault,
  type EmailOtpEd25519YaoOwnedFactorSecret,
  type EmailOtpEd25519YaoRootBinding,
  type EmailOtpEd25519YaoRootConsumeResult,
  type EmailOtpEd25519YaoRootConsumer,
  type EmailOtpEd25519YaoRootConsumerResult,
  type EmailOtpEd25519YaoRootHandle,
  type EmailOtpEd25519YaoRootScope,
} from './ed25519YaoRootVault';
import { zeroizeBytes } from './zeroize';

export type VerifiedEmailOtpEd25519YaoAuthorityV1 = {
  kind: 'verified_email_otp_ed25519_yao_authority_v1';
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  bearerToken: string;
};

export type EmailOtpEd25519YaoActivationTransportV1 = {
  kind: 'email_otp_ed25519_yao_http_transport_v1';
  routerOrigin: string;
  fetch: typeof fetch;
};

export type EmailOtpEd25519YaoRegistrationInputV1 = {
  kind: 'email_otp_ed25519_yao_registration_input_v1';
  authority: VerifiedEmailOtpEd25519YaoAuthorityV1;
  rootHandle: EmailOtpEd25519YaoRootHandle;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  transport: EmailOtpEd25519YaoActivationTransportV1;
  nowMs: number;
};

export type EmailOtpEd25519YaoRecoveryInputV1 = {
  kind: 'email_otp_ed25519_yao_recovery_input_v1';
  authority: VerifiedEmailOtpEd25519YaoAuthorityV1;
  rootHandle: EmailOtpEd25519YaoRootHandle;
  admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  transport: EmailOtpEd25519YaoActivationTransportV1;
  nowMs: number;
};

function requireNonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireMatching(left: string | number, right: string | number, label: string): void {
  if (left !== right) throw new Error(`${label} does not match the verified Email OTP authority`);
}

function requireMatchingParticipantIds(
  left: readonly [number, number],
  right: readonly [number, number],
): void {
  if (left[0] !== right[0] || left[1] !== right[1]) {
    throw new Error('Yao participant IDs do not match the verified Email OTP root');
  }
}

function rootScopeFromAdmission(args: {
  purpose: EmailOtpEd25519YaoRootScope['purpose'];
  providerSubject: string;
  admission:
    | RouterAbEd25519YaoRegistrationAdmissionRequestV1
    | RouterAbEd25519YaoRecoveryAdmissionRequestV1;
}): EmailOtpEd25519YaoRootScope {
  return {
    kind: 'email_otp_ed25519_yao_root_scope_v1',
    purpose: args.purpose,
    walletId: args.admission.application_binding.wallet_id,
    providerSubject: requireNonEmpty(args.providerSubject, 'providerSubject'),
    nearEd25519SigningKeyId: args.admission.application_binding.near_ed25519_signing_key_id,
    signingRootId: args.admission.application_binding.signing_root_id,
    signerSlot: args.admission.application_binding.key_creation_signer_slot,
    participantIds: args.admission.participant_ids,
  };
}

function validateAuthority(
  authority: VerifiedEmailOtpEd25519YaoAuthorityV1,
  scope: EmailOtpEd25519YaoRootScope,
): void {
  requireMatching(
    scope.walletId,
    requireNonEmpty(authority.walletId, 'authority.walletId'),
    'wallet',
  );
  requireMatching(
    scope.providerSubject,
    requireNonEmpty(authority.providerSubject, 'authority.providerSubject'),
    'provider subject',
  );
  requireNonEmpty(authority.registrationAuthorityId, 'authority.registrationAuthorityId');
  requireNonEmpty(authority.bearerToken, 'authority.bearerToken');
}

function validateOwnedFactorBinding(args: {
  owned: EmailOtpEd25519YaoOwnedFactorSecret;
  expected: EmailOtpEd25519YaoRootBinding;
}): void {
  requireMatching(args.owned.binding.lifecycleId, args.expected.lifecycleId, 'Yao lifecycle');
  const left = args.owned.binding.scope;
  const right = args.expected.scope;
  requireMatching(left.purpose, right.purpose, 'Yao purpose');
  requireMatching(left.walletId, right.walletId, 'wallet');
  requireMatching(left.providerSubject, right.providerSubject, 'provider subject');
  requireMatching(
    left.nearEd25519SigningKeyId,
    right.nearEd25519SigningKeyId,
    'Ed25519 signing key',
  );
  requireMatching(left.signingRootId, right.signingRootId, 'signing root');
  requireMatching(left.signerSlot, right.signerSlot, 'signer slot');
  requireMatchingParticipantIds(left.participantIds, right.participantIds);
}

function transportConfig(args: {
  authority: VerifiedEmailOtpEd25519YaoAuthorityV1;
  transport: EmailOtpEd25519YaoActivationTransportV1;
}) {
  return {
    routerOrigin: requireNonEmpty(args.transport.routerOrigin, 'Yao Router origin'),
    authorization: `Bearer ${requireNonEmpty(args.authority.bearerToken, 'authority.bearerToken')}`,
    fetch: args.transport.fetch,
  };
}

class EmailOtpRegistrationRootConsumer implements EmailOtpEd25519YaoRootConsumer<RetainedEmailOtpEd25519YaoRegistrationV1> {
  constructor(
    private readonly binding: EmailOtpEd25519YaoRootBinding,
    private readonly admission: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    private readonly transport: RouterAbEd25519YaoHttpActivationTransportV1,
  ) {}

  async consumeOwnedFactorSecret(
    owned: EmailOtpEd25519YaoOwnedFactorSecret,
  ): Promise<EmailOtpEd25519YaoRootConsumerResult<RetainedEmailOtpEd25519YaoRegistrationV1>> {
    validateOwnedFactorBinding({ owned, expected: this.binding });
    const retainedFactorSecret32 = owned.factorSecret32.slice();
    try {
      const result = await registerProductEd25519YaoV1({
        request: this.admission,
        factor: { kind: 'email_otp_factor', ownedSecret32: owned.factorSecret32 },
        transport: this.transport,
      });
      if (!result.ok) {
        zeroizeBytes(retainedFactorSecret32);
        return { ok: false, code: result.code, message: result.message };
      }
      return {
        ok: true,
        value: {
          registration: result.registration,
          retainedFactorSecret32,
        },
      };
    } catch (error) {
      zeroizeBytes(retainedFactorSecret32);
      throw error;
    }
  }
}

class EmailOtpRecoveryRootConsumer implements EmailOtpEd25519YaoRootConsumer<RetainedEmailOtpEd25519YaoRecoveryV1> {
  constructor(
    private readonly binding: EmailOtpEd25519YaoRootBinding,
    private readonly admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
    private readonly transport: RouterAbEd25519YaoHttpActivationTransportV1,
  ) {}

  async consumeOwnedFactorSecret(
    owned: EmailOtpEd25519YaoOwnedFactorSecret,
  ): Promise<EmailOtpEd25519YaoRootConsumerResult<RetainedEmailOtpEd25519YaoRecoveryV1>> {
    validateOwnedFactorBinding({ owned, expected: this.binding });
    const retainedFactorSecret32 = owned.factorSecret32.slice();
    try {
      const client = await RouterAbEd25519YaoClientV1.initializeBundled();
      const result = await client.recover({
        request: this.admission,
        factor: { kind: 'email_otp_factor', ownedSecret32: owned.factorSecret32 },
        transport: this.transport,
      });
      if (!result.ok) {
        zeroizeBytes(retainedFactorSecret32);
        return { ok: false, code: result.code, message: result.message };
      }
      return {
        ok: true,
        value: {
          recovery: result,
          retainedFactorSecret32,
        },
      };
    } catch (error) {
      zeroizeBytes(retainedFactorSecret32);
      throw error;
    }
  }
}

export type RetainedEmailOtpEd25519YaoRegistrationV1 = {
  registration: ProductEd25519YaoPendingRegistrationPortV1;
  retainedFactorSecret32: Uint8Array;
};

export type RetainedEmailOtpEd25519YaoRecoveryV1 = {
  recovery: RouterAbEd25519YaoRecoveryResultV1;
  retainedFactorSecret32: Uint8Array;
};

export function emailOtpEd25519YaoRegistrationRootScopeV1(args: {
  providerSubject: string;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): EmailOtpEd25519YaoRootScope {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(args.admissionRequest);
  if (!parsed.ok) throw new Error(parsed.message);
  return rootScopeFromAdmission({
    purpose: 'registration',
    providerSubject: args.providerSubject,
    admission: parsed.value,
  });
}

export function emailOtpEd25519YaoRecoveryRootScopeV1(args: {
  providerSubject: string;
  admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
}): EmailOtpEd25519YaoRootScope {
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(args.admissionRequest);
  if (!parsed.ok) throw new Error(parsed.message);
  return rootScopeFromAdmission({
    purpose: 'recovery',
    providerSubject: args.providerSubject,
    admission: parsed.value,
  });
}

export async function registerEmailOtpEd25519YaoV1(args: {
  vault: EmailOtpEd25519YaoRootVault;
  input: EmailOtpEd25519YaoRegistrationInputV1;
}): Promise<EmailOtpEd25519YaoRootConsumeResult<RetainedEmailOtpEd25519YaoRegistrationV1>> {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(args.input.admissionRequest);
  if (!parsed.ok) throw new Error(parsed.message);
  const scope = rootScopeFromAdmission({
    purpose: 'registration',
    providerSubject: args.input.authority.providerSubject,
    admission: parsed.value,
  });
  validateAuthority(args.input.authority, scope);
  const binding: EmailOtpEd25519YaoRootBinding = {
    kind: 'email_otp_ed25519_yao_root_binding_v1',
    lifecycleId: parsed.value.scope.lifecycle_id,
    scope,
  };
  return await args.vault.consume({
    handle: args.input.rootHandle,
    binding,
    consumer: new EmailOtpRegistrationRootConsumer(
      binding,
      parsed.value,
      new RouterAbEd25519YaoHttpActivationTransportV1(
        transportConfig({ authority: args.input.authority, transport: args.input.transport }),
      ),
    ),
    nowMs: args.input.nowMs,
  });
}

export async function recoverEmailOtpEd25519YaoV1(args: {
  vault: EmailOtpEd25519YaoRootVault;
  input: EmailOtpEd25519YaoRecoveryInputV1;
}): Promise<EmailOtpEd25519YaoRootConsumeResult<RetainedEmailOtpEd25519YaoRecoveryV1>> {
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(args.input.admissionRequest);
  if (!parsed.ok) throw new Error(parsed.message);
  const scope = rootScopeFromAdmission({
    purpose: 'recovery',
    providerSubject: args.input.authority.providerSubject,
    admission: parsed.value,
  });
  validateAuthority(args.input.authority, scope);
  const binding: EmailOtpEd25519YaoRootBinding = {
    kind: 'email_otp_ed25519_yao_root_binding_v1',
    lifecycleId: parsed.value.scope.lifecycle_id,
    scope,
  };
  return await args.vault.consume({
    handle: args.input.rootHandle,
    binding,
    consumer: new EmailOtpRecoveryRootConsumer(
      binding,
      parsed.value,
      new RouterAbEd25519YaoHttpActivationTransportV1(
        transportConfig({ authority: args.input.authority, transport: args.input.transport }),
      ),
    ),
    nowMs: args.input.nowMs,
  });
}
