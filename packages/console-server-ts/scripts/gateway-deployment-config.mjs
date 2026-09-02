const RESOURCE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const D1_DATABASE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TENANT_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/;
const X25519_PUBLIC_KEY_PATTERN = /^x25519:[0-9a-f]{64}$/;
const ED25519_PUBLIC_KEY_PATTERN = /^ed25519:[1-9A-HJ-NP-Za-km-z]+$/;
const ED25519_VERIFYING_KEY_PATTERN = /^[0-9a-f]{64}$/;
const UNSIGNED_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;

export const GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION = 4;
export const DEFAULT_NEAR_INITIAL_BALANCE_YOCTO = '30000000000000000000000';
export const DEFAULT_RELAY_SESSION_AUDIENCE = 'seams-wallet-session';
export const DEFAULT_SESSION_COOKIE_NAME = 'seams-jwt';
export const DEFAULT_CONSOLE_SESSION_AUDIENCE = 'seams-console-session';
export const DEFAULT_CONSOLE_SESSION_COOKIE_NAME = 'seams-console-jwt';
export const DEFAULT_EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX = '30';
export const DEFAULT_EMAIL_OTP_VERIFY_RATE_LIMIT_MAX = '30';
export const DEFAULT_EMAIL_OTP_GRANT_RATE_LIMIT_MAX = '30';
export const DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS = '60000';
export const DEFAULT_EMAIL_OTP_MAX_ATTEMPTS = '5';
export const DEFAULT_EMAIL_OTP_LOCKOUT_TTL_MS = '300000';
export const DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX = '5';
export const GATEWAY_WORKER_COMPATIBILITY_DATE = '2026-07-18';
export const GATEWAY_WORKER_COMPATIBILITY_FLAGS = Object.freeze(['nodejs_compat']);

export function consoleOriginFor(gatewayOrigin) {
  const url = new URL(gatewayOrigin);
  if (!url.hostname.split('.').includes('api')) {
    throw new Error(`cannot derive console origin from ${gatewayOrigin}`);
  }
  const hostname = url.hostname
    .split('.')
    .map((label) => (label === 'api' ? 'console' : label))
    .join('.');
  return `${url.protocol}//${hostname}`;
}
export const GATEWAY_RUNTIME_PROFILE_KINDS = {
  testnetLiveDemo: 'testnet_live_demo',
  testnetService: 'testnet_service',
  mainnetService: 'mainnet_service',
};
const BACKEND_LANE_DEFINITIONS = Object.freeze({
  'staging-testnet': Object.freeze({
    runtimeProfileKind: 'testnet_live_demo',
    serviceNames: Object.freeze({
      deriverA: 'router-ab-deriver-a-staging',
      deriverB: 'router-ab-deriver-b-staging',
      signingWorker: 'router-ab-signing-worker-staging',
      mpcRouter: 'router-ab-mpc-router-staging',
    }),
  }),
  'production-testnet': Object.freeze({
    runtimeProfileKind: 'testnet_live_demo',
    serviceNames: Object.freeze({
      deriverA: 'router-ab-deriver-a-testnet',
      deriverB: 'router-ab-deriver-b-testnet',
      signingWorker: 'router-ab-signing-worker-testnet',
      mpcRouter: 'router-ab-mpc-router-testnet',
    }),
  }),
  'production-mainnet': Object.freeze({
    runtimeProfileKind: 'mainnet_service',
    serviceNames: Object.freeze({
      deriverA: 'router-ab-deriver-a',
      deriverB: 'router-ab-deriver-b',
      signingWorker: 'router-ab-signing-worker',
      mpcRouter: 'router-ab-mpc-router',
    }),
  }),
});
export const GATEWAY_EMAIL_OTP_DELIVERY_KINDS = {
  emailProvider: 'email_provider',
  demoCodeResponse: 'demo_code_response',
  providerAndDemoCode: 'provider_and_demo_code',
};
export function buildGatewayRuntimeProfile(kind, emailOtpDeliveryKind) {
  switch (kind) {
    case GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo: {
      const deliveryKind =
        emailOtpDeliveryKind || GATEWAY_EMAIL_OTP_DELIVERY_KINDS.demoCodeResponse;
      if (
        deliveryKind !== GATEWAY_EMAIL_OTP_DELIVERY_KINDS.demoCodeResponse &&
        deliveryKind !== GATEWAY_EMAIL_OTP_DELIVERY_KINDS.providerAndDemoCode
      ) {
        throw new Error(
          'testnet_live_demo requires demo_code_response or provider_and_demo_code Email OTP delivery',
        );
      }
      return {
        kind,
        nearFunding: {
          kind: 'implicit_account_relayer',
          network: 'near_testnet',
        },
        emailOtpDelivery: {
          kind: deliveryKind,
        },
      };
    }
    case GATEWAY_RUNTIME_PROFILE_KINDS.testnetService:
      if (
        emailOtpDeliveryKind &&
        emailOtpDeliveryKind !== GATEWAY_EMAIL_OTP_DELIVERY_KINDS.emailProvider
      ) {
        throw new Error(`${kind} requires email_provider Email OTP delivery`);
      }
      return {
        kind,
        nearFunding: {
          kind: 'implicit_account_relayer',
          network: 'near_testnet',
        },
        emailOtpDelivery: { kind: 'email_provider' },
      };
    case GATEWAY_RUNTIME_PROFILE_KINDS.mainnetService:
      if (
        emailOtpDeliveryKind &&
        emailOtpDeliveryKind !== GATEWAY_EMAIL_OTP_DELIVERY_KINDS.emailProvider
      ) {
        throw new Error(`${kind} requires email_provider Email OTP delivery`);
      }
      return {
        kind,
        nearFunding: { kind: 'disabled' },
        emailOtpDelivery: { kind: 'email_provider' },
      };
    default:
      throw new Error(
        `runtime profile must be ${Object.values(GATEWAY_RUNTIME_PROFILE_KINDS).join(', ')}`,
      );
  }
}

export function gatewayRuntimeProfileNearNetwork(runtimeProfile) {
  switch (runtimeProfile.kind) {
    case GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo:
    case GATEWAY_RUNTIME_PROFILE_KINDS.testnetService:
      return 'testnet';
    case GATEWAY_RUNTIME_PROFILE_KINDS.mainnetService:
      return 'mainnet';
    default:
      throw new Error(`Unsupported Gateway runtime profile: ${String(runtimeProfile.kind)}`);
  }
}

export function parseGatewayDeploymentConfig(source, expectedLaneId) {
  const root = parseJsonObject(source, 'Gateway deployment config');
  requireExactInteger(
    root.schemaVersion,
    GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
    'schemaVersion',
  );
  requireExactKeys(root, gatewayDeploymentConfigKeys(), 'Gateway deployment config');
  const expectedLane = requireBackendLaneId(expectedLaneId, 'expected lane');
  const lane = requireBackendLaneId(root.lane, 'lane');
  if (lane !== expectedLane) {
    throw new Error(`lane must match --lane ${expectedLane}`);
  }

  const laneDefinition = BACKEND_LANE_DEFINITIONS[lane];
  const serviceNames = laneDefinition.serviceNames;
  const runtimeProfile = parseRuntimeProfile(root.runtimeProfile);
  requireExactString(
    runtimeProfile.kind,
    laneDefinition.runtimeProfileKind,
    `runtimeProfile.kind for ${lane}`,
  );
  const resources = parseResources(root.resources);
  const tenant = parseTenant(root.tenant);
  const origins = parseOrigins(root.origins);
  const session = parseSession(root.session);
  const signingSessionSeal = parseSigningSessionSeal(root.signingSessionSeal);
  const routerAb = parseRouterAb(root.routerAb, serviceNames);
  const optional = parseOptionalConfig(root.optional);

  if (lane === 'production-mainnet' && optional.nearRelayer) {
    throw new Error('production-mainnet must not configure optional.nearRelayer');
  }
  requireNearFundingConfiguration(runtimeProfile, optional.nearRelayer);
  return {
    schemaVersion: GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
    lane,
    runtimeProfile,
    resources,
    tenant,
    origins,
    session,
    signingSessionSeal,
    routerAb,
    optional,
    serviceNames,
  };
}

function gatewayDeploymentConfigKeys() {
  return [
    'schemaVersion',
    'lane',
    'runtimeProfile',
    'resources',
    'tenant',
    'origins',
    'session',
    'signingSessionSeal',
    'routerAb',
    'optional',
  ];
}

function parseRuntimeProfile(value) {
  const runtimeProfile = requireObject(value, 'runtimeProfile');
  requireExactKeys(runtimeProfile, ['kind', 'nearFunding', 'emailOtpDelivery'], 'runtimeProfile');
  const kind = requireString(runtimeProfile.kind, 'runtimeProfile.kind');
  const emailOtpDelivery = requireObject(
    runtimeProfile.emailOtpDelivery,
    'runtimeProfile.emailOtpDelivery',
  );
  requireExactKeys(emailOtpDelivery, ['kind'], 'runtimeProfile.emailOtpDelivery');
  const canonical = buildGatewayRuntimeProfile(
    kind,
    requireString(emailOtpDelivery.kind, 'runtimeProfile.emailOtpDelivery.kind'),
  );
  const nearFunding = requireObject(runtimeProfile.nearFunding, 'runtimeProfile.nearFunding');
  if (canonical.nearFunding.kind === 'implicit_account_relayer') {
    requireExactKeys(nearFunding, ['kind', 'network'], 'runtimeProfile.nearFunding');
    requireExactString(
      nearFunding.kind,
      canonical.nearFunding.kind,
      'runtimeProfile.nearFunding.kind',
    );
    requireExactString(
      nearFunding.network,
      canonical.nearFunding.network,
      'runtimeProfile.nearFunding.network',
    );
    return canonical;
  }
  requireExactKeys(nearFunding, ['kind'], 'runtimeProfile.nearFunding');
  requireExactString(
    nearFunding.kind,
    canonical.nearFunding.kind,
    'runtimeProfile.nearFunding.kind',
  );
  return canonical;
}

function requireNearFundingConfiguration(runtimeProfile, nearRelayer) {
  if (runtimeProfile.nearFunding.kind === 'implicit_account_relayer' && !nearRelayer) {
    throw new Error('testnet_live_demo requires optional.nearRelayer');
  }
  if (!nearRelayer) return;

  const expectedNetwork = gatewayRuntimeProfileNearNetwork(runtimeProfile);
  const configuredNetwork = knownNearNetworkForRpcUrl(nearRelayer.rpcUrl);
  if (configuredNetwork && configuredNetwork !== expectedNetwork) {
    throw new Error(
      `optional.nearRelayer.rpcUrl targets NEAR ${configuredNetwork}, ` +
        `but runtimeProfile targets NEAR ${expectedNetwork}`,
    );
  }
  if (
    runtimeProfile.nearFunding.kind === 'implicit_account_relayer' &&
    nearRelayer.initialBalanceYocto === '0'
  ) {
    throw new Error(
      'testnet_live_demo requires a positive optional.nearRelayer.initialBalanceYocto',
    );
  }
}

function knownNearNetworkForRpcUrl(rpcUrl) {
  const hostname = new URL(rpcUrl).hostname.toLowerCase();
  if (hostname === 'rpc.testnet.near.org') return 'testnet';
  if (hostname === 'rpc.mainnet.near.org') return 'mainnet';
  return null;
}

function parseResources(value) {
  const resources = requireObject(value, 'resources');
  requireExactKeys(resources, ['workerName', 'consoleD1', 'signerD1'], 'resources');
  return {
    workerName: requirePattern(resources.workerName, RESOURCE_NAME_PATTERN, 'resources.workerName'),
    consoleD1: parseD1Resource(resources.consoleD1, 'resources.consoleD1'),
    signerD1: parseD1Resource(resources.signerD1, 'resources.signerD1'),
  };
}

function parseD1Resource(value, path) {
  const resource = requireObject(value, path);
  requireExactKeys(resource, ['name', 'id'], path);
  return {
    name: requirePattern(resource.name, RESOURCE_NAME_PATTERN, `${path}.name`),
    id: requireNonZeroHexPattern(resource.id, D1_DATABASE_ID_PATTERN, `${path}.id`),
  };
}

function parseTenant(value) {
  const tenant = requireObject(value, 'tenant');
  requireExactKeys(tenant, ['namespace', 'orgId', 'projectId', 'environmentId'], 'tenant');
  return {
    namespace: requireTenantId(tenant.namespace, 'tenant.namespace'),
    orgId: requireTenantId(tenant.orgId, 'tenant.orgId'),
    projectId: requireTenantId(tenant.projectId, 'tenant.projectId'),
    environmentId: requireTenantId(tenant.environmentId, 'tenant.environmentId'),
  };
}

function parseOrigins(value) {
  const origins = requireObject(value, 'origins');
  requireExactKeys(origins, ['gateway', 'allowedCors'], 'origins');
  return {
    gateway: requireHttpsUrl(origins.gateway, 'origins.gateway'),
    allowedCors: parseOriginArray(origins.allowedCors, 'origins.allowedCors'),
  };
}

function parseSession(value) {
  const session = requireObject(value, 'session');
  requireExactKeys(session, ['issuer'], 'session');
  return {
    issuer: requireString(session.issuer, 'session.issuer'),
  };
}

function parseSigningSessionSeal(value) {
  const seal = requireObject(value, 'signingSessionSeal');
  requireExactKeys(
    seal,
    ['algorithm', 'groupId', 'currentKeyVersion', 'acceptedWarmKeyVersions'],
    'signingSessionSeal',
  );
  requireExactString(seal.algorithm, 'shamir3pass-v2', 'signingSessionSeal.algorithm');
  requireExactString(seal.groupId, 'rfc2409-group2', 'signingSessionSeal.groupId');
  const currentKeyVersion = requireString(
    seal.currentKeyVersion,
    'signingSessionSeal.currentKeyVersion',
  );
  const acceptedWarmKeyVersions = parseStringArray(
    seal.acceptedWarmKeyVersions,
    'signingSessionSeal.acceptedWarmKeyVersions',
  );
  if (!acceptedWarmKeyVersions.includes(currentKeyVersion)) {
    throw new Error('signingSessionSeal.acceptedWarmKeyVersions must include currentKeyVersion');
  }
  return {
    algorithm: 'shamir3pass-v2',
    groupId: 'rfc2409-group2',
    currentKeyVersion,
    acceptedWarmKeyVersions,
  };
}

function parseRouterAb(value, serviceNames) {
  const routerAb = requireObject(value, 'routerAb');
  requireExactKeys(
    routerAb,
    [
      'ceremonyJwtAudience',
      'ceremonyJwtKeyId',
      'publicKeyset',
      'registrationTopology',
      'deriverAYaoInputPublicKey',
      'deriverBYaoInputPublicKey',
      'signingWorkerOutputPublicKey',
    ],
    'routerAb',
  );
  const publicKeyset = parsePublicKeyset(routerAb.publicKeyset);
  const registrationTopology = parseRegistrationTopology(
    routerAb.registrationTopology,
    serviceNames,
  );
  requireRegistrationKeysMatch(publicKeyset, registrationTopology);
  const deriverAInputPublicKey = publicKeyset.signer_envelope_hpke.current.deriver_a.public_key;
  const deriverBInputPublicKey = publicKeyset.signer_envelope_hpke.current.deriver_b.public_key;
  const signingWorkerOutputPublicKey = publicKeyset.signing_worker_server_output_hpke.public_key;
  requireEqual(
    requireNonZeroHexPattern(
      routerAb.deriverAYaoInputPublicKey,
      X25519_PUBLIC_KEY_PATTERN,
      'routerAb.deriverAYaoInputPublicKey',
    ),
    deriverAInputPublicKey,
    'routerAb.deriverAYaoInputPublicKey and publicKeyset',
  );
  requireEqual(
    requireNonZeroHexPattern(
      routerAb.deriverBYaoInputPublicKey,
      X25519_PUBLIC_KEY_PATTERN,
      'routerAb.deriverBYaoInputPublicKey',
    ),
    deriverBInputPublicKey,
    'routerAb.deriverBYaoInputPublicKey and publicKeyset',
  );
  requireEqual(
    requireNonZeroHexPattern(
      routerAb.signingWorkerOutputPublicKey,
      X25519_PUBLIC_KEY_PATTERN,
      'routerAb.signingWorkerOutputPublicKey',
    ),
    signingWorkerOutputPublicKey,
    'routerAb.signingWorkerOutputPublicKey and publicKeyset',
  );
  return {
    ceremonyJwtAudience: requireString(
      routerAb.ceremonyJwtAudience,
      'routerAb.ceremonyJwtAudience',
    ),
    ceremonyJwtKeyId: requireString(routerAb.ceremonyJwtKeyId, 'routerAb.ceremonyJwtKeyId'),
    publicKeyset,
    registrationTopology,
    deriverAInputPublicKey,
    deriverBInputPublicKey,
    signingWorkerOutputPublicKey,
  };
}

function parsePublicKeyset(value) {
  const keyset = requireObject(value, 'routerAb.publicKeyset');
  requireExactKeys(
    keyset,
    [
      'keyset_version',
      'signer_envelope_hpke',
      'signer_peer_verifying_keys',
      'signing_worker_server_output_hpke',
    ],
    'routerAb.publicKeyset',
  );
  if (keyset.keyset_version !== 'router_ab_keyset_v2') {
    throw new Error('routerAb.publicKeyset.keyset_version must be router_ab_keyset_v2');
  }
  const signerEnvelope = requireObject(
    keyset.signer_envelope_hpke,
    'routerAb.publicKeyset.signer_envelope_hpke',
  );
  requireExactKeys(signerEnvelope, ['current'], 'routerAb.publicKeyset.signer_envelope_hpke');
  const current = requireObject(
    signerEnvelope.current,
    'routerAb.publicKeyset.signer_envelope_hpke.current',
  );
  requireExactKeys(
    current,
    ['deriver_a', 'deriver_b'],
    'routerAb.publicKeyset.signer_envelope_hpke.current',
  );
  const peerKeys = requireObject(
    keyset.signer_peer_verifying_keys,
    'routerAb.publicKeyset.signer_peer_verifying_keys',
  );
  requireExactKeys(
    peerKeys,
    ['deriver_a', 'deriver_b'],
    'routerAb.publicKeyset.signer_peer_verifying_keys',
  );
  const workerOutput = requireObject(
    keyset.signing_worker_server_output_hpke,
    'routerAb.publicKeyset.signing_worker_server_output_hpke',
  );
  requireExactKeys(
    workerOutput,
    ['key_epoch', 'public_key'],
    'routerAb.publicKeyset.signing_worker_server_output_hpke',
  );
  return {
    keyset_version: 'router_ab_keyset_v2',
    signer_envelope_hpke: {
      current: {
        deriver_a: parseEnvelopeKey(
          current.deriver_a,
          'signer_a',
          'routerAb.publicKeyset.signer_envelope_hpke.current.deriver_a',
        ),
        deriver_b: parseEnvelopeKey(
          current.deriver_b,
          'signer_b',
          'routerAb.publicKeyset.signer_envelope_hpke.current.deriver_b',
        ),
      },
    },
    signer_peer_verifying_keys: {
      deriver_a: parsePeerVerifyingKey(
        peerKeys.deriver_a,
        'signer_a',
        'routerAb.publicKeyset.signer_peer_verifying_keys.deriver_a',
      ),
      deriver_b: parsePeerVerifyingKey(
        peerKeys.deriver_b,
        'signer_b',
        'routerAb.publicKeyset.signer_peer_verifying_keys.deriver_b',
      ),
    },
    signing_worker_server_output_hpke: {
      key_epoch: requireEpoch(
        workerOutput.key_epoch,
        'routerAb.publicKeyset.signing_worker_server_output_hpke.key_epoch',
      ),
      public_key: requireNonZeroHexPattern(
        workerOutput.public_key,
        X25519_PUBLIC_KEY_PATTERN,
        'routerAb.publicKeyset.signing_worker_server_output_hpke.public_key',
      ),
    },
  };
}

function parseEnvelopeKey(value, expectedRole, path) {
  const key = requireObject(value, path);
  requireExactKeys(key, ['role', 'key_epoch', 'public_key'], path);
  requireExactString(key.role, expectedRole, `${path}.role`);
  return {
    role: expectedRole,
    key_epoch: requireEpoch(key.key_epoch, `${path}.key_epoch`),
    public_key: requireNonZeroHexPattern(
      key.public_key,
      X25519_PUBLIC_KEY_PATTERN,
      `${path}.public_key`,
    ),
  };
}

function parsePeerVerifyingKey(value, expectedRole, path) {
  const key = requireObject(value, path);
  requireExactKeys(key, ['role', 'verifying_key_hex'], path);
  requireExactString(key.role, expectedRole, `${path}.role`);
  return {
    role: expectedRole,
    verifying_key_hex: requireNonZeroHexPattern(
      key.verifying_key_hex,
      ED25519_VERIFYING_KEY_PATTERN,
      `${path}.verifying_key_hex`,
    ),
  };
}

function parseRegistrationTopology(value, serviceNames) {
  const topology = requireObject(value, 'routerAb.registrationTopology');
  requireExactKeys(
    topology,
    ['routerId', 'signerSet', 'deriverRecipientKeys'],
    'routerAb.registrationTopology',
  );
  requireExactString(
    topology.routerId,
    serviceNames.mpcRouter,
    'routerAb.registrationTopology.routerId',
  );
  const signerSet = requireObject(topology.signerSet, 'routerAb.registrationTopology.signerSet');
  requireExactKeys(
    signerSet,
    ['signer_set_id', 'policy', 'signer_a', 'signer_b', 'selected_server'],
    'routerAb.registrationTopology.signerSet',
  );
  requireExactString(signerSet.policy, 'all_2', 'routerAb.registrationTopology.signerSet.policy');
  const selectedServer = requireObject(
    signerSet.selected_server,
    'routerAb.registrationTopology.signerSet.selected_server',
  );
  requireExactKeys(
    selectedServer,
    ['server_id', 'key_epoch', 'recipient_encryption_key'],
    'routerAb.registrationTopology.signerSet.selected_server',
  );
  requireExactString(
    selectedServer.server_id,
    serviceNames.signingWorker,
    'routerAb.registrationTopology.signerSet.selected_server.server_id',
  );
  const recipientKeys = requireObject(
    topology.deriverRecipientKeys,
    'routerAb.registrationTopology.deriverRecipientKeys',
  );
  requireExactKeys(
    recipientKeys,
    ['deriver_a', 'deriver_b'],
    'routerAb.registrationTopology.deriverRecipientKeys',
  );
  return {
    routerId: serviceNames.mpcRouter,
    signerSet: {
      signer_set_id: requireString(
        signerSet.signer_set_id,
        'routerAb.registrationTopology.signerSet.signer_set_id',
      ),
      policy: 'all_2',
      signer_a: parseSignerIdentity(
        signerSet.signer_a,
        'signer_a',
        'signer-a',
        'routerAb.registrationTopology.signerSet.signer_a',
      ),
      signer_b: parseSignerIdentity(
        signerSet.signer_b,
        'signer_b',
        'signer-b',
        'routerAb.registrationTopology.signerSet.signer_b',
      ),
      selected_server: {
        server_id: serviceNames.signingWorker,
        key_epoch: requireEpoch(
          selectedServer.key_epoch,
          'routerAb.registrationTopology.signerSet.selected_server.key_epoch',
        ),
        recipient_encryption_key: requireNonZeroHexPattern(
          selectedServer.recipient_encryption_key,
          X25519_PUBLIC_KEY_PATTERN,
          'routerAb.registrationTopology.signerSet.selected_server.recipient_encryption_key',
        ),
      },
    },
    deriverRecipientKeys: {
      deriver_a: parseEnvelopeKey(
        recipientKeys.deriver_a,
        'signer_a',
        'routerAb.registrationTopology.deriverRecipientKeys.deriver_a',
      ),
      deriver_b: parseEnvelopeKey(
        recipientKeys.deriver_b,
        'signer_b',
        'routerAb.registrationTopology.deriverRecipientKeys.deriver_b',
      ),
    },
  };
}

function parseSignerIdentity(value, expectedRole, expectedId, path) {
  const signer = requireObject(value, path);
  requireExactKeys(signer, ['role', 'signer_id', 'key_epoch'], path);
  requireExactString(signer.role, expectedRole, `${path}.role`);
  requireExactString(signer.signer_id, expectedId, `${path}.signer_id`);
  return {
    role: expectedRole,
    signer_id: expectedId,
    key_epoch: requireEpoch(signer.key_epoch, `${path}.key_epoch`),
  };
}

function parseOptionalConfig(value) {
  const optional = requireObject(value, 'optional');
  requireExactKeys(optional, ['nearRelayer', 'googleOidcClientId'], 'optional');
  return {
    nearRelayer: parseNearRelayer(optional.nearRelayer),
    googleOidcClientId: parseNullableString(
      optional.googleOidcClientId,
      'optional.googleOidcClientId',
    ),
  };
}

function parseNearRelayer(value) {
  if (value === null) return null;
  const relayer = requireObject(value, 'optional.nearRelayer');
  requireAllowedAndRequiredKeys(
    relayer,
    ['accountId', 'publicKey', 'rpcUrl', 'initialBalanceYocto'],
    ['accountId', 'rpcUrl'],
    'optional.nearRelayer',
  );
  const initialBalance =
    relayer.initialBalanceYocto === undefined
      ? DEFAULT_NEAR_INITIAL_BALANCE_YOCTO
      : requirePattern(
          relayer.initialBalanceYocto,
          UNSIGNED_INTEGER_PATTERN,
          'optional.nearRelayer.initialBalanceYocto',
        );
  return {
    accountId: requireString(relayer.accountId, 'optional.nearRelayer.accountId'),
    publicKey: parseNullablePattern(
      relayer.publicKey,
      ED25519_PUBLIC_KEY_PATTERN,
      'optional.nearRelayer.publicKey',
    ),
    rpcUrl: requireHttpsUrl(relayer.rpcUrl, 'optional.nearRelayer.rpcUrl'),
    initialBalanceYocto: initialBalance,
  };
}

function parseNullableString(value, path) {
  if (value === null) return null;
  return requireString(value, path);
}

function parseNullablePattern(value, pattern, path) {
  if (value === null || value === undefined) return null;
  return requirePattern(value, pattern, path);
}

function requireRegistrationKeysMatch(keyset, topology) {
  requireEqual(
    keyset.signer_envelope_hpke.current.deriver_a.public_key,
    topology.deriverRecipientKeys.deriver_a.public_key,
    'Deriver A registration public key',
  );
  requireEqual(
    keyset.signer_envelope_hpke.current.deriver_b.public_key,
    topology.deriverRecipientKeys.deriver_b.public_key,
    'Deriver B registration public key',
  );
  requireEqual(
    keyset.signing_worker_server_output_hpke.public_key,
    topology.signerSet.selected_server.recipient_encryption_key,
    'SigningWorker registration public key',
  );
}

function parseOriginArray(value, path) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array`);
  }
  const origins = value.map((entry, index) => requireHttpsOrigin(entry, `${path}[${index}]`));
  return [...new Set(origins)];
}

function parseStringArray(value, path) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array`);
  }
  const entries = value.map((entry, index) => requireString(entry, `${path}[${index}]`));
  if (new Set(entries).size !== entries.length) {
    throw new Error(`${path} must not contain duplicates`);
  }
  return entries;
}

function parseJsonObject(source, path) {
  let parsed;
  try {
    parsed = JSON.parse(String(source || ''));
  } catch {
    throw new Error(`${path} must contain valid JSON`);
  }
  return requireObject(parsed, path);
}

function requireObject(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value;
}

function requireExactKeys(value, keys, path) {
  requireAllowedAndRequiredKeys(value, keys, keys, path);
}

function requireAllowedAndRequiredKeys(value, allowedKeys, requiredKeys, path) {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${path}.${key} is not supported`);
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(value, key)) throw new Error(`${path}.${key} is required`);
  }
}

function requireString(value, path) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${path} must be a non-empty string`);
  }
  return value.trim();
}

function requirePattern(value, pattern, path) {
  const normalized = requireString(value, path);
  if (!pattern.test(normalized)) throw new Error(`${path} has an invalid format`);
  return normalized;
}

function requireNonZeroHexPattern(value, pattern, path) {
  const normalized = requirePattern(value, pattern, path);
  const hex = normalized.includes(':')
    ? normalized.slice(normalized.indexOf(':') + 1)
    : normalized.replaceAll('-', '');
  if (/^0+$/.test(hex)) throw new Error(`${path} must not be all zeroes`);
  return normalized;
}

function requireTenantId(value, path) {
  return requirePattern(value, TENANT_ID_PATTERN, path);
}

function requireBackendLaneId(value, path) {
  const lane = requireString(value, path);
  if (!Object.hasOwn(BACKEND_LANE_DEFINITIONS, lane)) {
    throw new Error(`${path} must be ${Object.keys(BACKEND_LANE_DEFINITIONS).join(', ')}`);
  }
  return lane;
}

function requireExactString(value, expected, path) {
  const normalized = requireString(value, path);
  if (normalized !== expected) throw new Error(`${path} must be ${expected}`);
}

function requireExactInteger(value, expected, path) {
  if (value !== expected) throw new Error(`${path} must be ${expected}`);
}

function requireHttpsUrl(value, path) {
  const normalized = requireString(value, path);
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`${path} must be an absolute HTTPS URL`);
  }
  if (parsed.protocol !== 'https:') throw new Error(`${path} must be an absolute HTTPS URL`);
  return normalized.replace(/\/+$/, '');
}

function requireHttpsOrigin(value, path) {
  const normalized = requireHttpsUrl(value, path);
  const parsed = new URL(normalized);
  if (parsed.origin !== normalized)
    throw new Error(`${path} must be an HTTPS origin without a path`);
  return parsed.origin;
}

function requireEpoch(value, path) {
  return requireString(value, path);
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} values must match`);
}
