import {
  type RouterAbEd25519YaoExportSeedInputV1,
  WasmRouterAbEd25519YaoActiveClientV1,
} from './yaoClient';

// @ts-expect-error Active Client state can only be created from verified WASM completion.
const forgedActiveClient = new WasmRouterAbEd25519YaoActiveClientV1({});

void forgedActiveClient;

declare const exportRequest: RouterAbEd25519YaoExportSeedInputV1['request'];
declare const exportTransport: RouterAbEd25519YaoExportSeedInputV1['transport'];
declare const custodyEnvelope: RouterAbEd25519YaoExportSeedInputV1['custodyEnvelope'];
declare const passkeyAuthorization: Extract<
  RouterAbEd25519YaoExportSeedInputV1['authorization'],
  { kind: 'passkey' }
>;
declare const emailOtpAuthorization: Extract<
  RouterAbEd25519YaoExportSeedInputV1['authorization'],
  { kind: 'email_otp_factor' }
>;

const validPasskeyExport = {
  request: exportRequest,
  transport: exportTransport,
  custodyEnvelope,
  authorization: passkeyAuthorization,
} satisfies RouterAbEd25519YaoExportSeedInputV1;

const validEmailOtpExport = {
  request: exportRequest,
  transport: exportTransport,
  custodyEnvelope,
  authorization: emailOtpAuthorization,
} satisfies RouterAbEd25519YaoExportSeedInputV1;

void validPasskeyExport;
void validEmailOtpExport;
