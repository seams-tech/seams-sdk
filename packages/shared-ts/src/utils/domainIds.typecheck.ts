import type {
  ChallengeSubjectId,
  AgentPrincipalId,
  CapabilityInstanceRef,
  DelegatedIdempotencyKey,
  DelegatedIntentDigest,
  DomainIdParseResult,
  EcdsaActiveStateId,
  EmailOtpChallengeId,
  EmailOtpRegistrationAttemptId,
  GoogleProviderSubject,
  LaneShareEpoch,
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LinkDeviceSessionId,
  MandatePolicyId,
  MpcCapabilityRuntimeRef,
  MpcKeyBindingRef,
  MpcLifecycleBindingRef,
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  MpcMaterialOwnerRef,
  MpcReauthorizationPolicyRef,
  MpcRegisteredPublicKeyBindingRef,
  MpcSigningWorkerRef,
  OrgId,
  ProviderSubject,
  RootShareEpoch,
  SigningLaneId,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  VerifiedGoogleEmail,
  WalletAuthorityId,
  WalletAuthMethodId,
  WalletId,
  WalletKeyId,
} from './domainIds';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcCapabilityRuntimeRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialActivationRef,
  parseMpcMaterialOwnerRef,
  parseMpcReauthorizationPolicyRef,
  parseMpcRegisteredPublicKeyBindingRef,
  parseMpcSigningWorkerRef,
  parseWalletAuthorityId,
  parseWalletAuthMethodId,
} from './domainIds';
import type {
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';

declare const walletId: WalletId;
declare const walletAuthorityId: WalletAuthorityId;
declare const walletAuthMethodId: WalletAuthMethodId;
declare const walletSessionAuthorizationId: WalletSessionAuthorizationId;
declare const providerSubject: ProviderSubject;
declare const googleProviderSubject: GoogleProviderSubject;
declare const verifiedGoogleEmail: VerifiedGoogleEmail;
declare const challengeSubjectId: ChallengeSubjectId;
declare const orgId: OrgId;
declare const emailOtpChallengeId: EmailOtpChallengeId;
declare const registrationAttemptId: EmailOtpRegistrationAttemptId;
declare const walletSessionId: WalletSessionId;
declare const thresholdEd25519SessionId: ThresholdEd25519SessionId;
declare const thresholdEcdsaSessionId: ThresholdEcdsaSessionId;
declare const ecdsaActiveStateId: EcdsaActiveStateId;
declare const rootShareEpoch: RootShareEpoch;
declare const walletKeyId: WalletKeyId;
declare const signingLaneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
declare const agentPrincipalId: AgentPrincipalId;
declare const linkedDeviceId: LinkedDeviceId;
declare const linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
declare const mandatePolicyId: MandatePolicyId;
declare const delegatedIntentDigest: DelegatedIntentDigest;
declare const delegatedIdempotencyKey: DelegatedIdempotencyKey;
declare const linkDeviceSessionId: LinkDeviceSessionId;
declare const capabilityInstanceRef: CapabilityInstanceRef;
declare const mpcMaterialOwnerRef: MpcMaterialOwnerRef;
declare const otherMpcMaterialOwnerRef: MpcMaterialOwnerRef;
declare const mpcCapabilityRuntimeRef: MpcCapabilityRuntimeRef;
declare const mpcMaterialActivationId: MpcMaterialActivationId;
declare const mpcSigningWorkerRef: MpcSigningWorkerRef;
declare const mpcKeyBindingRef: MpcKeyBindingRef;
declare const mpcLifecycleBindingRef: MpcLifecycleBindingRef;
declare const mpcReauthorizationPolicyRef: MpcReauthorizationPolicyRef;
declare const mpcRegisteredPublicKeyBindingRef: MpcRegisteredPublicKeyBindingRef;

const mpcMaterialActivationRef = buildMpcMaterialActivationRef({
  activationId: mpcMaterialActivationId,
  capability: capabilityInstanceRef,
  materialOwner: mpcMaterialOwnerRef,
  keyBinding: mpcKeyBindingRef,
  lifecycleBinding: mpcLifecycleBindingRef,
  signingWorker: mpcSigningWorkerRef,
});

function acceptsWalletId(value: WalletId): void {
  void value;
}

function acceptsWalletAuthorityId(value: WalletAuthorityId): void {
  void value;
}

function acceptsProviderSubject(value: ProviderSubject): void {
  void value;
}

function acceptsGoogleProviderSubject(value: GoogleProviderSubject): void {
  void value;
}

function acceptsVerifiedGoogleEmail(value: VerifiedGoogleEmail): void {
  void value;
}

function acceptsChallengeSubjectId(value: ChallengeSubjectId): void {
  void value;
}

function acceptsEmailOtpChallengeId(value: EmailOtpChallengeId): void {
  void value;
}

function acceptsEmailOtpRegistrationAttemptId(value: EmailOtpRegistrationAttemptId): void {
  void value;
}

function acceptsOrgId(value: OrgId): void {
  void value;
}

function acceptsWalletSessionId(value: WalletSessionId): void {
  void value;
}

function acceptsThresholdEd25519SessionId(value: ThresholdEd25519SessionId): void {
  void value;
}

function acceptsThresholdEcdsaSessionId(value: ThresholdEcdsaSessionId): void {
  void value;
}

function acceptsEcdsaActiveStateId(value: EcdsaActiveStateId): void {
  void value;
}

function acceptsRootShareEpoch(value: RootShareEpoch): void {
  void value;
}

function acceptsWalletKeyId(value: WalletKeyId): void {
  void value;
}

function acceptsSigningLaneId(value: SigningLaneId): void {
  void value;
}

function acceptsLaneShareEpoch(value: LaneShareEpoch): void {
  void value;
}

function acceptsAgentPrincipalId(value: AgentPrincipalId): void {
  void value;
}

function acceptsLinkedDeviceId(value: LinkedDeviceId): void {
  void value;
}

function acceptsMandatePolicyId(value: MandatePolicyId): void {
  void value;
}

function acceptsDelegatedIntentDigest(value: DelegatedIntentDigest): void {
  void value;
}

function acceptsDelegatedIdempotencyKey(value: DelegatedIdempotencyKey): void {
  void value;
}

function acceptsLinkDeviceSessionId(value: LinkDeviceSessionId): void {
  void value;
}

function acceptsCapabilityInstanceRef(value: CapabilityInstanceRef): void {
  void value;
}

function acceptsMpcMaterialOwnerRef(value: MpcMaterialOwnerRef): void {
  void value;
}

function acceptsMpcCapabilityRuntimeRef(value: MpcCapabilityRuntimeRef): void {
  void value;
}

function acceptsMpcMaterialActivationId(value: MpcMaterialActivationId): void {
  void value;
}

function acceptsMpcSigningWorkerRef(value: MpcSigningWorkerRef): void {
  void value;
}

function acceptsMpcKeyBindingRef(value: MpcKeyBindingRef): void {
  void value;
}

function acceptsMpcLifecycleBindingRef(value: MpcLifecycleBindingRef): void {
  void value;
}

function acceptsMpcReauthorizationPolicyRef(value: MpcReauthorizationPolicyRef): void {
  void value;
}

function acceptsMpcRegisteredPublicKeyBindingRef(value: MpcRegisteredPublicKeyBindingRef): void {
  void value;
}

function acceptsMpcMaterialActivationRef(value: MpcMaterialActivationRef): void {
  void value;
}

acceptsWalletId(walletId);
acceptsWalletAuthorityId(walletAuthorityId);
acceptsProviderSubject(providerSubject);
acceptsProviderSubject(googleProviderSubject);
acceptsGoogleProviderSubject(googleProviderSubject);
acceptsVerifiedGoogleEmail(verifiedGoogleEmail);
acceptsChallengeSubjectId(challengeSubjectId);
acceptsOrgId(orgId);
acceptsEmailOtpChallengeId(emailOtpChallengeId);
acceptsEmailOtpRegistrationAttemptId(registrationAttemptId);
acceptsWalletSessionId(walletSessionId);
acceptsThresholdEd25519SessionId(thresholdEd25519SessionId);
acceptsThresholdEcdsaSessionId(thresholdEcdsaSessionId);
acceptsEcdsaActiveStateId(ecdsaActiveStateId);
acceptsRootShareEpoch(rootShareEpoch);
acceptsWalletKeyId(walletKeyId);
acceptsSigningLaneId(signingLaneId);
acceptsLaneShareEpoch(laneShareEpoch);
acceptsAgentPrincipalId(agentPrincipalId);
acceptsLinkedDeviceId(linkedDeviceId);
acceptsMandatePolicyId(mandatePolicyId);
acceptsDelegatedIntentDigest(delegatedIntentDigest);
acceptsDelegatedIdempotencyKey(delegatedIdempotencyKey);
acceptsLinkDeviceSessionId(linkDeviceSessionId);
acceptsCapabilityInstanceRef(capabilityInstanceRef);
acceptsMpcMaterialOwnerRef(mpcMaterialOwnerRef);
acceptsMpcCapabilityRuntimeRef(mpcCapabilityRuntimeRef);
acceptsMpcMaterialActivationId(mpcMaterialActivationId);
acceptsMpcSigningWorkerRef(mpcSigningWorkerRef);
acceptsMpcKeyBindingRef(mpcKeyBindingRef);
acceptsMpcLifecycleBindingRef(mpcLifecycleBindingRef);
acceptsMpcReauthorizationPolicyRef(mpcReauthorizationPolicyRef);
acceptsMpcRegisteredPublicKeyBindingRef(mpcRegisteredPublicKeyBindingRef);
acceptsMpcMaterialActivationRef(mpcMaterialActivationRef);

parseCapabilityInstanceRef('capability') satisfies DomainIdParseResult<CapabilityInstanceRef>;
parseMpcMaterialOwnerRef('material-owner') satisfies DomainIdParseResult<MpcMaterialOwnerRef>;
parseMpcCapabilityRuntimeRef('runtime') satisfies DomainIdParseResult<MpcCapabilityRuntimeRef>;
parseMpcMaterialActivationId('activation') satisfies DomainIdParseResult<MpcMaterialActivationId>;
parseMpcSigningWorkerRef('worker') satisfies DomainIdParseResult<MpcSigningWorkerRef>;
parseMpcKeyBindingRef('key-binding') satisfies DomainIdParseResult<MpcKeyBindingRef>;
parseMpcLifecycleBindingRef('lifecycle') satisfies DomainIdParseResult<MpcLifecycleBindingRef>;
parseMpcReauthorizationPolicyRef(
  'policy',
) satisfies DomainIdParseResult<MpcReauthorizationPolicyRef>;
parseMpcRegisteredPublicKeyBindingRef(
  'public-key',
) satisfies DomainIdParseResult<MpcRegisteredPublicKeyBindingRef>;
parseMpcMaterialActivationRef({
  kind: 'mpc_material_activation_ref',
  activationId: 'activation',
  capability: 'capability',
  materialOwner: 'material-owner',
  keyBinding: 'key-binding',
  lifecycleBinding: 'lifecycle',
  signingWorker: 'worker',
}) satisfies DomainIdParseResult<MpcMaterialActivationRef>;
parseWalletAuthorityId('wallet-authority') satisfies DomainIdParseResult<WalletAuthorityId>;
parseWalletAuthMethodId('wallet-auth-method') satisfies DomainIdParseResult<WalletAuthMethodId>;

// @ts-expect-error Provider subjects are not wallet ids.
acceptsWalletId(providerSubject);

// @ts-expect-error Wallet ids are not wallet authority ids.
acceptsWalletAuthorityId(walletId);

// @ts-expect-error Auth-method ids are not wallet authority ids.
acceptsWalletAuthorityId(walletAuthMethodId);

// @ts-expect-error Material activation ids are not wallet authority ids.
acceptsWalletAuthorityId(mpcMaterialActivationId);

// @ts-expect-error Link enrollment ids are not wallet authority ids.
acceptsWalletAuthorityId(linkedDeviceEnrollmentId);

// @ts-expect-error Wallet Session authorization ids are not wallet authority ids.
acceptsWalletAuthorityId(walletSessionAuthorizationId);

// @ts-expect-error Wallet ids are not provider subjects.
acceptsProviderSubject(walletId);

// @ts-expect-error Generic provider subjects are not Google-specific provider subjects.
acceptsGoogleProviderSubject(providerSubject);

// @ts-expect-error Verified Google emails are not provider subjects.
acceptsProviderSubject(verifiedGoogleEmail);

// @ts-expect-error Challenge subjects are not wallet ids.
acceptsWalletId(challengeSubjectId);

// @ts-expect-error Provider subjects are not challenge subject ids.
acceptsChallengeSubjectId(providerSubject);

// @ts-expect-error OTP challenge ids are not challenge-owner subjects.
acceptsChallengeSubjectId(emailOtpChallengeId);

// @ts-expect-error Organization ids are not wallet ids.
acceptsWalletId(orgId);

// @ts-expect-error Registration attempt ids are not OTP challenge ids.
acceptsEmailOtpChallengeId(registrationAttemptId);

// @ts-expect-error OTP challenge ids are not registration attempt ids.
acceptsEmailOtpRegistrationAttemptId(emailOtpChallengeId);

// @ts-expect-error Wallet Session ids are not threshold Ed25519 session ids.
acceptsThresholdEd25519SessionId(walletSessionId);

// @ts-expect-error Threshold Ed25519 session ids are not Wallet Session ids.
acceptsWalletSessionId(thresholdEd25519SessionId);

// @ts-expect-error Material activation ids are not threshold Ed25519 session ids.
acceptsThresholdEd25519SessionId(mpcMaterialActivationId);

// @ts-expect-error Threshold Ed25519 session ids are not material activation ids.
acceptsMpcMaterialActivationId(thresholdEd25519SessionId);

// @ts-expect-error Threshold Ed25519 and ECDSA session ids are curve-specific.
acceptsThresholdEcdsaSessionId(thresholdEd25519SessionId);

// @ts-expect-error Threshold ECDSA session ids are not root-share epochs.
acceptsRootShareEpoch(thresholdEcdsaSessionId);

// @ts-expect-error Root-share epochs are not threshold ECDSA session ids.
acceptsThresholdEcdsaSessionId(rootShareEpoch);

// @ts-expect-error ECDSA active-state ids are not authorization-session ids.
acceptsThresholdEcdsaSessionId(ecdsaActiveStateId);

// @ts-expect-error ECDSA authorization-session ids are not active-state ids.
acceptsEcdsaActiveStateId(thresholdEcdsaSessionId);

// @ts-expect-error Wallet keys are not wallet ids.
acceptsWalletId(walletKeyId);

// @ts-expect-error Wallet ids are not wallet keys.
acceptsWalletKeyId(walletId);

// @ts-expect-error Lane share epochs are not signing lanes.
acceptsSigningLaneId(laneShareEpoch);

// @ts-expect-error Agent principals are not linked devices.
acceptsLinkedDeviceId(agentPrincipalId);

// @ts-expect-error Linked devices are not agent principals.
acceptsAgentPrincipalId(linkedDeviceId);

// @ts-expect-error Delegated intent digests are not idempotency keys.
acceptsDelegatedIdempotencyKey(delegatedIntentDigest);

// @ts-expect-error Link-device sessions are not signing lanes.
acceptsSigningLaneId(linkDeviceSessionId);

// @ts-expect-error Capability instances are not material owners.
acceptsMpcMaterialOwnerRef(capabilityInstanceRef);

// @ts-expect-error Material owners are not capability instances.
acceptsCapabilityInstanceRef(mpcMaterialOwnerRef);

// @ts-expect-error Signing-worker references are not runtime references.
acceptsMpcCapabilityRuntimeRef(mpcSigningWorkerRef);

// @ts-expect-error Key bindings are not lifecycle bindings.
acceptsMpcLifecycleBindingRef(mpcKeyBindingRef);

// @ts-expect-error Reauthorization policies are not registered-key bindings.
acceptsMpcRegisteredPublicKeyBindingRef(mpcReauthorizationPolicyRef);

// @ts-expect-error Exact activation references can only come from the canonical builder or parser.
acceptsMpcMaterialActivationRef({
  kind: 'mpc_material_activation_ref',
  activationId: mpcMaterialActivationId,
  capability: capabilityInstanceRef,
  materialOwner: mpcMaterialOwnerRef,
  keyBinding: mpcKeyBindingRef,
  lifecycleBinding: mpcLifecycleBindingRef,
  signingWorker: mpcSigningWorkerRef,
});

buildMpcMaterialActivationRef({
  // @ts-expect-error Raw strings cannot construct material activation identity.
  activationId: 'activation',
  capability: capabilityInstanceRef,
  materialOwner: mpcMaterialOwnerRef,
  keyBinding: mpcKeyBindingRef,
  lifecycleBinding: mpcLifecycleBindingRef,
  signingWorker: mpcSigningWorkerRef,
});

// @ts-expect-error Exact activation references require a signing-worker binding.
buildMpcMaterialActivationRef({
  activationId: mpcMaterialActivationId,
  capability: capabilityInstanceRef,
  materialOwner: mpcMaterialOwnerRef,
  keyBinding: mpcKeyBindingRef,
  lifecycleBinding: mpcLifecycleBindingRef,
});

const activationWithRawOwner = {
  ...mpcMaterialActivationRef,
  materialOwner: otherMpcMaterialOwnerRef,
};

// @ts-expect-error Broad spreads lose the activation proof even when replacement fields are branded.
acceptsMpcMaterialActivationRef(activationWithRawOwner);
