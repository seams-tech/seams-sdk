import { ensureEd25519Prefix, toOptionalTrimmedString } from '@shared/utils/validation';

export type ThresholdEd25519KeygenMaterial = {
  relayerKeyId: string;
  publicKey: string;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
  keyVersion: string;
  recoveryExportCapable: true;
};

export interface ThresholdEd25519KeygenStrategy {
  keygenFromRegistrationMaterial(input: {
    keyVersion: string;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
    recoveryExportCapable: true;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  >;
}

export class ThresholdEd25519KeygenStrategyV1 implements ThresholdEd25519KeygenStrategy {
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;

  constructor(input: { clientParticipantId: number; relayerParticipantId: number }) {
    this.clientParticipantId = input.clientParticipantId;
    this.relayerParticipantId = input.relayerParticipantId;
  }

  async keygenFromRegistrationMaterial(input: {
    keyVersion: string;
    publicKey: string;
    relayerSigningShareB64u: string;
    relayerVerifyingShareB64u: string;
    recoveryExportCapable: true;
  }): Promise<
    | { ok: true; keyMaterial: ThresholdEd25519KeygenMaterial }
    | { ok: false; code: string; message: string }
  > {
    const keyVersion = toOptionalTrimmedString(input.keyVersion);
    const publicKey = ensureEd25519Prefix(toOptionalTrimmedString(input.publicKey) || '');
    const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
    const relayerVerifyingShareB64u = toOptionalTrimmedString(input.relayerVerifyingShareB64u);
    if (!keyVersion) return { ok: false, code: 'invalid_body', message: 'keyVersion is required' };
    if (!publicKey) return { ok: false, code: 'invalid_body', message: 'publicKey is required' };
    if (!relayerSigningShareB64u) {
      return { ok: false, code: 'invalid_body', message: 'relayerSigningShareB64u is required' };
    }
    if (!relayerVerifyingShareB64u) {
      return { ok: false, code: 'invalid_body', message: 'relayerVerifyingShareB64u is required' };
    }
    if (!input.recoveryExportCapable) {
      return { ok: false, code: 'invalid_body', message: 'recoveryExportCapable must be true' };
    }

    const relayerKeyId = publicKey;
    return {
      ok: true,
      keyMaterial: {
        relayerKeyId,
        publicKey,
        relayerSigningShareB64u,
        relayerVerifyingShareB64u,
        keyVersion,
        recoveryExportCapable: true,
      },
    };
  }
}
