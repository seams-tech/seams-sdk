export type VoiceIdTemplateEncryptionAlgorithm = 'AES-GCM-256';
export type VoiceIdTemplateEncryptionConfigVersion = 'voiceid-template-encryption-config-v1';

export type VoiceIdTemplateEncryptionKeyId = string & {
  readonly __brand: 'VoiceIdTemplateEncryptionKeyId';
};

export type VoiceIdTemplateEncryptionRotationVersion = string & {
  readonly __brand: 'VoiceIdTemplateEncryptionRotationVersion';
};

export type VoiceIdTemplateEncryptionAadLabel = string & {
  readonly __brand: 'VoiceIdTemplateEncryptionAadLabel';
};

export type VoiceIdTemplateEncryptionSecretBindingName = string & {
  readonly __brand: 'VoiceIdTemplateEncryptionSecretBindingName';
};

export type VoiceIdTemplateEncryptionSecretEnvName = string & {
  readonly __brand: 'VoiceIdTemplateEncryptionSecretEnvName';
};

export type VoiceIdTemplateEncryptionKeyConfig =
  | {
      kind: 'cloudflare_workers_secret';
      configVersion: VoiceIdTemplateEncryptionConfigVersion;
      algorithm: VoiceIdTemplateEncryptionAlgorithm;
      keyId: VoiceIdTemplateEncryptionKeyId;
      secretBindingName: VoiceIdTemplateEncryptionSecretBindingName;
      rotationVersion: VoiceIdTemplateEncryptionRotationVersion;
      aadLabel: VoiceIdTemplateEncryptionAadLabel;
    }
  | {
      kind: 'robot_local_secret';
      configVersion: VoiceIdTemplateEncryptionConfigVersion;
      algorithm: VoiceIdTemplateEncryptionAlgorithm;
      keyId: VoiceIdTemplateEncryptionKeyId;
      secretEnvName: VoiceIdTemplateEncryptionSecretEnvName;
      rotationVersion: VoiceIdTemplateEncryptionRotationVersion;
      aadLabel: VoiceIdTemplateEncryptionAadLabel;
    };

export type VoiceIdTemplateEncryptionEnv = Readonly<Record<string, string | undefined>>;

const configVersion: VoiceIdTemplateEncryptionConfigVersion = 'voiceid-template-encryption-config-v1';
const algorithm: VoiceIdTemplateEncryptionAlgorithm = 'AES-GCM-256';

export function parseVoiceIdTemplateEncryptionKeyConfigFromEnv(
  env: VoiceIdTemplateEncryptionEnv,
): VoiceIdTemplateEncryptionKeyConfig {
  const mode = requireEnv(env, 'VOICEID_TEMPLATE_KEY_SOURCE');
  if (mode === 'cloudflare-workers-secret') {
    return {
      kind: 'cloudflare_workers_secret',
      configVersion,
      algorithm: parseAlgorithm(env),
      keyId: parseKeyId(requireEnv(env, 'VOICEID_TEMPLATE_KEY_ID')),
      secretBindingName: parseSecretBindingName(requireEnv(env, 'VOICEID_TEMPLATE_KEY_SECRET_BINDING')),
      rotationVersion: parseRotationVersion(requireEnv(env, 'VOICEID_TEMPLATE_KEY_ROTATION_VERSION')),
      aadLabel: parseAadLabel(requireEnv(env, 'VOICEID_TEMPLATE_KEY_AAD_LABEL')),
    };
  }
  if (mode === 'robot-local-secret') {
    return {
      kind: 'robot_local_secret',
      configVersion,
      algorithm: parseAlgorithm(env),
      keyId: parseKeyId(requireEnv(env, 'VOICEID_TEMPLATE_KEY_ID')),
      secretEnvName: parseSecretEnvName(requireEnv(env, 'VOICEID_TEMPLATE_KEY_SECRET_ENV')),
      rotationVersion: parseRotationVersion(requireEnv(env, 'VOICEID_TEMPLATE_KEY_ROTATION_VERSION')),
      aadLabel: parseAadLabel(requireEnv(env, 'VOICEID_TEMPLATE_KEY_AAD_LABEL')),
    };
  }

  throw new Error(
    "VOICEID_TEMPLATE_KEY_SOURCE must be 'cloudflare-workers-secret' or 'robot-local-secret'",
  );
}

function parseAlgorithm(env: VoiceIdTemplateEncryptionEnv): VoiceIdTemplateEncryptionAlgorithm {
  const value = requireEnv(env, 'VOICEID_TEMPLATE_KEY_ALGORITHM');
  if (value !== algorithm) {
    throw new Error(`VOICEID_TEMPLATE_KEY_ALGORITHM must be ${algorithm}`);
  }

  return value;
}

function requireEnv(env: VoiceIdTemplateEncryptionEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} must be set`);
  }

  return value.trim();
}

function parseKeyId(value: string): VoiceIdTemplateEncryptionKeyId {
  return parseNonEmpty(value, 'VOICEID_TEMPLATE_KEY_ID') as VoiceIdTemplateEncryptionKeyId;
}

function parseRotationVersion(value: string): VoiceIdTemplateEncryptionRotationVersion {
  return parseNonEmpty(value, 'VOICEID_TEMPLATE_KEY_ROTATION_VERSION') as VoiceIdTemplateEncryptionRotationVersion;
}

function parseAadLabel(value: string): VoiceIdTemplateEncryptionAadLabel {
  return parseNonEmpty(value, 'VOICEID_TEMPLATE_KEY_AAD_LABEL') as VoiceIdTemplateEncryptionAadLabel;
}

function parseSecretBindingName(value: string): VoiceIdTemplateEncryptionSecretBindingName {
  return parseNonEmpty(value, 'VOICEID_TEMPLATE_KEY_SECRET_BINDING') as VoiceIdTemplateEncryptionSecretBindingName;
}

function parseSecretEnvName(value: string): VoiceIdTemplateEncryptionSecretEnvName {
  return parseNonEmpty(value, 'VOICEID_TEMPLATE_KEY_SECRET_ENV') as VoiceIdTemplateEncryptionSecretEnvName;
}

function parseNonEmpty(value: string, name: string): string {
  if (value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }

  return value.trim();
}
