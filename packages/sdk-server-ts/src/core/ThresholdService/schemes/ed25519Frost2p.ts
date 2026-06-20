import type {
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
} from '../../types';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from './schemeIds';
import type {
  ThresholdEd25519Frost2pSchemeModule,
  ThresholdEd25519RegistrationKeygenRequest,
  ThresholdEd25519RegistrationKeygenResult,
} from './thresholdServiceSchemes.types';

export type ThresholdEd25519Frost2pSchemeModuleDeps = {
  healthz?: () => Promise<{ ok: boolean; code?: string; message?: string }>;
  registrationKeygenFromRegistrationMaterial(
    request: ThresholdEd25519RegistrationKeygenRequest,
  ): Promise<ThresholdEd25519RegistrationKeygenResult>;
  session(request: ThresholdEd25519SessionRequest): Promise<ThresholdEd25519SessionResponse>;
  protocol: ThresholdEd25519Frost2pSchemeModule['protocol'];
};

export function createThresholdEd25519Frost2pSchemeModule(
  deps: ThresholdEd25519Frost2pSchemeModuleDeps,
): ThresholdEd25519Frost2pSchemeModule {
  return {
    schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    healthz: deps.healthz || (async () => ({ ok: true })),
    registration: {
      keygenFromRegistrationMaterial: deps.registrationKeygenFromRegistrationMaterial,
    },
    session: deps.session,
    protocol: deps.protocol,
  };
}
