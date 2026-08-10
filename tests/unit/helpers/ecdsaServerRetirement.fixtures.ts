import { parseEcdsaServerRetirementReceiptV1 } from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { computeEcdsaServerRetirementReceiptDigestV1 as computeReceiptDigest } from '../../../packages/shared-ts/src/signing-lanes/rotationDigests';
import type {
  EcdsaServerRetirementReceiptV1,
  EcdsaAdditiveLaneJobV1,
} from '../../../packages/shared-ts/src/signing-lanes';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { buildR102ServerActivationReceipt } from './r102LaneGateway.fixtures';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32));

export async function buildR102EcdsaServerRetirementReceipt(
  job: EcdsaAdditiveLaneJobV1,
  overrides: Readonly<Partial<RawEcdsaServerRetirementReceipt>> = {},
): Promise<EcdsaServerRetirementReceiptV1> {
  const activation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
  const raw: RawEcdsaServerRetirementReceipt = {
    kind: 'ecdsa_server_retirement_receipt_v1',
    manifest: {
      manifestId: job.targetCapability.manifestId,
      manifestRevision: job.targetCapability.manifestRevision,
    },
    materialActivation: activation,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    revocationEpoch: job.source.revocationEpoch,
    retirementReason: 'lane_revoked',
    retirementCorrelationId: 'correlation-r102-retirement',
    retirementRequestDigestB64u: DIGEST_B64U,
    serverGeneration: job.sourceCapability.serverGeneration,
    lifecycleId: 'lifecycle-r102-retirement',
    receiptDigestB64u: DIGEST_B64U,
    retiredAt: '2026-08-11T00:00:00.000Z',
    ...overrides,
  };
  const parsed = parseEcdsaServerRetirementReceiptV1(raw);
  const digest = await computeReceiptDigest(parsed);
  return parseEcdsaServerRetirementReceiptV1({
    ...raw,
    receiptDigestB64u: digest,
  });
}

type RawEcdsaServerRetirementReceipt = {
  readonly kind: 'ecdsa_server_retirement_receipt_v1';
  readonly manifest: {
    readonly manifestId: string;
    readonly manifestRevision: number;
  };
  readonly materialActivation: EcdsaServerRetirementReceiptV1['materialActivation'];
  readonly walletKeyId: string;
  readonly laneId: string;
  readonly laneShareEpoch: string;
  readonly revocationEpoch: number;
  readonly retirementReason: EcdsaServerRetirementReceiptV1['retirementReason'];
  readonly retirementCorrelationId: string;
  readonly retirementRequestDigestB64u: string;
  readonly serverGeneration: string;
  readonly lifecycleId: string;
  readonly receiptDigestB64u: string;
  readonly retiredAt: string;
};
