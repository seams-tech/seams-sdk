export type VoiceIdDiagnosticRetentionConfigVersion = 'voiceid-diagnostic-retention-config-v1';
export type VoiceIdDiagnosticRetentionPolicyVersion = string & {
  readonly __brand: 'VoiceIdDiagnosticRetentionPolicyVersion';
};
export type VoiceIdDiagnosticR2BucketBindingName = string & {
  readonly __brand: 'VoiceIdDiagnosticR2BucketBindingName';
};
export type VoiceIdDiagnosticLocalDirectory = string & {
  readonly __brand: 'VoiceIdDiagnosticLocalDirectory';
};

export type VoiceIdDiagnosticCapturePolicy =
  | {
      rawAudio: true;
      rawVideo: false;
    }
  | {
      rawAudio: false;
      rawVideo: true;
    }
  | {
      rawAudio: true;
      rawVideo: true;
    };

export type VoiceIdDiagnosticRetentionWindow = {
  ttlSeconds: number;
  deleteAfterSeconds: number;
};

export type VoiceIdDiagnosticRetentionConfig =
  | {
      kind: 'disabled';
      configVersion: VoiceIdDiagnosticRetentionConfigVersion;
      rawAudio: false;
      rawVideo: false;
    }
  | {
      kind: 'cloudflare_r2';
      configVersion: VoiceIdDiagnosticRetentionConfigVersion;
      policyVersion: VoiceIdDiagnosticRetentionPolicyVersion;
      bucketBindingName: VoiceIdDiagnosticR2BucketBindingName;
      retentionWindow: VoiceIdDiagnosticRetentionWindow;
      capture: VoiceIdDiagnosticCapturePolicy;
      maxArtifactBytes: number;
    }
  | {
      kind: 'robot_local_files';
      configVersion: VoiceIdDiagnosticRetentionConfigVersion;
      policyVersion: VoiceIdDiagnosticRetentionPolicyVersion;
      directory: VoiceIdDiagnosticLocalDirectory;
      retentionWindow: VoiceIdDiagnosticRetentionWindow;
      capture: VoiceIdDiagnosticCapturePolicy;
      maxArtifactBytes: number;
    };

export type VoiceIdDiagnosticRetentionEnv = Readonly<Record<string, string | undefined>>;

const configVersion: VoiceIdDiagnosticRetentionConfigVersion = 'voiceid-diagnostic-retention-config-v1';
const minimumRetentionSeconds = 60;
const maximumRetentionSeconds = 7 * 24 * 60 * 60;
const maximumArtifactBytes = 25 * 1024 * 1024;

export function parseVoiceIdDiagnosticRetentionConfigFromEnv(
  env: VoiceIdDiagnosticRetentionEnv,
): VoiceIdDiagnosticRetentionConfig {
  const mode = env.VOICEID_DIAGNOSTIC_RETENTION ?? 'disabled';
  if (mode === 'disabled') {
    return {
      kind: 'disabled',
      configVersion,
      rawAudio: false,
      rawVideo: false,
    };
  }
  if (mode === 'cloudflare-r2') {
    return {
      kind: 'cloudflare_r2',
      configVersion,
      policyVersion: parsePolicyVersion(requireEnv(env, 'VOICEID_DIAGNOSTIC_POLICY_VERSION')),
      bucketBindingName: parseR2BucketBindingName(requireEnv(env, 'VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING')),
      retentionWindow: parseRetentionWindow(env),
      capture: parseCapturePolicy(env),
      maxArtifactBytes: parseMaxArtifactBytes(env),
    };
  }
  if (mode === 'robot-local-files') {
    return {
      kind: 'robot_local_files',
      configVersion,
      policyVersion: parsePolicyVersion(requireEnv(env, 'VOICEID_DIAGNOSTIC_POLICY_VERSION')),
      directory: parseLocalDirectory(requireEnv(env, 'VOICEID_DIAGNOSTIC_LOCAL_DIRECTORY')),
      retentionWindow: parseRetentionWindow(env),
      capture: parseCapturePolicy(env),
      maxArtifactBytes: parseMaxArtifactBytes(env),
    };
  }

  throw new Error(
    "VOICEID_DIAGNOSTIC_RETENTION must be 'disabled', 'cloudflare-r2', or 'robot-local-files'",
  );
}

function parseRetentionWindow(env: VoiceIdDiagnosticRetentionEnv): VoiceIdDiagnosticRetentionWindow {
  const ttlSeconds = parseIntegerEnv(env, 'VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS');
  if (ttlSeconds < minimumRetentionSeconds || ttlSeconds > maximumRetentionSeconds) {
    throw new Error('VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS must be between 60 and 604800');
  }

  return {
    ttlSeconds,
    deleteAfterSeconds: ttlSeconds,
  };
}

function parseCapturePolicy(env: VoiceIdDiagnosticRetentionEnv): VoiceIdDiagnosticCapturePolicy {
  const rawAudio = parseBooleanEnv(env, 'VOICEID_DIAGNOSTIC_CAPTURE_AUDIO');
  const rawVideo = parseBooleanEnv(env, 'VOICEID_DIAGNOSTIC_CAPTURE_VIDEO');
  if (rawAudio === false && rawVideo === false) {
    throw new Error('diagnostic retention requires audio, video, or both capture types');
  }
  if (rawAudio === true && rawVideo === false) {
    return { rawAudio, rawVideo };
  }
  if (rawAudio === false && rawVideo === true) {
    return { rawAudio, rawVideo };
  }

  return { rawAudio: true, rawVideo: true };
}

function parseMaxArtifactBytes(env: VoiceIdDiagnosticRetentionEnv): number {
  const value = parseIntegerEnv(env, 'VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES');
  if (value <= 0 || value > maximumArtifactBytes) {
    throw new Error('VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES must be between 1 and 26214400');
  }

  return value;
}

function parseBooleanEnv(env: VoiceIdDiagnosticRetentionEnv, name: string): boolean {
  const value = requireEnv(env, name);
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }

  throw new Error(`${name} must be 'true' or 'false'`);
}

function parseIntegerEnv(env: VoiceIdDiagnosticRetentionEnv, name: string): number {
  const value = Number.parseInt(requireEnv(env, name), 10);
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${name} must be an integer`);
  }

  return value;
}

function requireEnv(env: VoiceIdDiagnosticRetentionEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} must be set`);
  }

  return value.trim();
}

function parsePolicyVersion(value: string): VoiceIdDiagnosticRetentionPolicyVersion {
  return parseNonEmpty(value, 'VOICEID_DIAGNOSTIC_POLICY_VERSION') as VoiceIdDiagnosticRetentionPolicyVersion;
}

function parseR2BucketBindingName(value: string): VoiceIdDiagnosticR2BucketBindingName {
  return parseNonEmpty(value, 'VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING') as VoiceIdDiagnosticR2BucketBindingName;
}

function parseLocalDirectory(value: string): VoiceIdDiagnosticLocalDirectory {
  return parseNonEmpty(value, 'VOICEID_DIAGNOSTIC_LOCAL_DIRECTORY') as VoiceIdDiagnosticLocalDirectory;
}

function parseNonEmpty(value: string, name: string): string {
  if (value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }

  return value.trim();
}
