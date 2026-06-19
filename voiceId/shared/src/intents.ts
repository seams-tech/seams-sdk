import { assertNever } from './assertNever.ts';
import {
  parseIsoDateTime,
  parseVoiceIdIntentDigest,
  type IsoDateTime,
  type VoiceIdIntentDigest,
} from './ids.ts';
import { parsePromptPhrase } from './prompts.ts';

type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

export type VoiceIdIntentNonce = Brand<string, 'VoiceIdIntentNonce'>;
export type VoiceIdTokenAmount = Brand<string, 'VoiceIdTokenAmount'>;
export type VoiceIdTokenSymbol = Brand<string, 'VoiceIdTokenSymbol'>;
export type VoiceIdPaymentRecipient = Brand<string, 'VoiceIdPaymentRecipient'>;
export type VoiceIdIntentDeviceId = Brand<string, 'VoiceIdIntentDeviceId'>;
export type VoiceIdRobotCommandText = Brand<string, 'VoiceIdRobotCommandText'>;
export type VoiceIdSpokenCommand = Brand<string, 'VoiceIdSpokenCommand'>;

export type VoiceIdIntentSchemaVersion = 'voice_id_intent_v1';

const spokenIntentDigitWords = new Map<string, string>([
  ['zero', '0'],
  ['oh', '0'],
  ['o', '0'],
  ['one', '1'],
  ['two', '2'],
  ['three', '3'],
  ['four', '4'],
  ['five', '5'],
  ['six', '6'],
  ['seven', '7'],
  ['eight', '8'],
  ['nine', '9'],
]);

export type VoiceIdTokenTransferIntent = {
  kind: 'token_transfer';
  schemaVersion: VoiceIdIntentSchemaVersion;
  amount: VoiceIdTokenAmount;
  tokenSymbol: VoiceIdTokenSymbol;
  recipient: VoiceIdPaymentRecipient;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
};

export type VoiceIdWalletSessionIntent = {
  kind: 'wallet_session';
  schemaVersion: VoiceIdIntentSchemaVersion;
  deviceId: VoiceIdIntentDeviceId;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
};

export type VoiceIdSwapApprovalIntent = {
  kind: 'swap_approval';
  schemaVersion: VoiceIdIntentSchemaVersion;
  sellAmount: VoiceIdTokenAmount;
  sellTokenSymbol: VoiceIdTokenSymbol;
  buyTokenSymbol: VoiceIdTokenSymbol;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
};

export type VoiceIdRobotCommandIntent = {
  kind: 'robot_command';
  schemaVersion: VoiceIdIntentSchemaVersion;
  command: VoiceIdRobotCommandText;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
};

export type VoiceIdIntent =
  | VoiceIdTokenTransferIntent
  | VoiceIdWalletSessionIntent
  | VoiceIdSwapApprovalIntent
  | VoiceIdRobotCommandIntent;

export type VoiceIdSpokenIntentBinding = {
  kind: 'voice_id_spoken_intent_binding_v1';
  spokenCommand: VoiceIdSpokenCommand;
  normalizedCommand: string;
  intent: VoiceIdIntent;
  intentDigest: VoiceIdIntentDigest;
};

export function buildVoiceIdTokenTransferIntent(input: {
  amount: VoiceIdTokenAmount;
  tokenSymbol: VoiceIdTokenSymbol;
  recipient: VoiceIdPaymentRecipient;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
}): VoiceIdTokenTransferIntent {
  return {
    kind: 'token_transfer',
    schemaVersion: 'voice_id_intent_v1',
    amount: input.amount,
    tokenSymbol: input.tokenSymbol,
    recipient: input.recipient,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
}

export function buildVoiceIdWalletSessionIntent(input: {
  deviceId: VoiceIdIntentDeviceId;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
}): VoiceIdWalletSessionIntent {
  return {
    kind: 'wallet_session',
    schemaVersion: 'voice_id_intent_v1',
    deviceId: input.deviceId,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
}

export function buildVoiceIdSwapApprovalIntent(input: {
  sellAmount: VoiceIdTokenAmount;
  sellTokenSymbol: VoiceIdTokenSymbol;
  buyTokenSymbol: VoiceIdTokenSymbol;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
}): VoiceIdSwapApprovalIntent {
  return {
    kind: 'swap_approval',
    schemaVersion: 'voice_id_intent_v1',
    sellAmount: input.sellAmount,
    sellTokenSymbol: input.sellTokenSymbol,
    buyTokenSymbol: input.buyTokenSymbol,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
}

export function buildVoiceIdRobotCommandIntent(input: {
  command: VoiceIdRobotCommandText;
  expiresAt: IsoDateTime;
  nonce: VoiceIdIntentNonce;
}): VoiceIdRobotCommandIntent {
  return {
    kind: 'robot_command',
    schemaVersion: 'voice_id_intent_v1',
    command: input.command,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  };
}

export function parseVoiceIdIntentNonce(value: unknown): VoiceIdIntentNonce {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(value)) {
    throw new Error('intent nonce must be an 8-128 character base64url-style string');
  }
  return value as VoiceIdIntentNonce;
}

export function parseVoiceIdTokenAmount(value: unknown): VoiceIdTokenAmount {
  const raw = typeof value === 'number' ? String(value) : value;
  if (typeof raw !== 'string' || !/^\d+(?:\.\d+)?$/.test(raw.trim())) {
    throw new Error('token amount must be a positive decimal string');
  }
  const normalized = normalizeDecimalAmount(raw.trim());
  if (!/[1-9]/.test(normalized)) {
    throw new Error('token amount must be greater than zero');
  }
  return normalized as VoiceIdTokenAmount;
}

export function parseVoiceIdTokenSymbol(value: unknown): VoiceIdTokenSymbol {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9]{0,15}$/.test(value.trim())) {
    throw new Error('token symbol must be 1-16 alphanumeric characters starting with a letter');
  }
  return value.trim().toUpperCase() as VoiceIdTokenSymbol;
}

export function parseVoiceIdPaymentRecipient(value: unknown): VoiceIdPaymentRecipient {
  if (typeof value !== 'string') {
    throw new Error('payment recipient must be a string');
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(normalized)) {
    throw new Error('payment recipient must be a non-empty account or contact id');
  }
  return normalized as VoiceIdPaymentRecipient;
}

export function parseVoiceIdIntentDeviceId(value: unknown): VoiceIdIntentDeviceId {
  if (typeof value !== 'string') {
    throw new Error('device id must be a string');
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(normalized)) {
    throw new Error('device id must be a non-empty device identifier');
  }
  return normalized as VoiceIdIntentDeviceId;
}

export function parseVoiceIdRobotCommandText(value: unknown): VoiceIdRobotCommandText {
  if (typeof value !== 'string') {
    throw new Error('robot command must be a string');
  }
  const normalized = normalizeSpokenIntentCommand(parsePromptPhrase(value));
  if (normalized.length === 0) {
    throw new Error('robot command must be non-empty');
  }
  return normalized as VoiceIdRobotCommandText;
}

export function parseVoiceIdSpokenCommand(value: unknown): VoiceIdSpokenCommand {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error('spoken command must be a non-empty string');
  }
  return value.trim() as VoiceIdSpokenCommand;
}

export function parseVoiceIdSpokenIntentCommand(input: {
  spokenCommand: VoiceIdSpokenCommand | string;
  expiresAt: IsoDateTime | string;
  nonce: VoiceIdIntentNonce | string;
}): VoiceIdIntent {
  const spokenCommand = parseVoiceIdSpokenCommand(input.spokenCommand);
  const normalized = normalizeSpokenIntentCommand(spokenCommand);
  const expiresAt = parseIsoDateTime(input.expiresAt);
  const nonce = parseVoiceIdIntentNonce(input.nonce);

  const transfer = /^send ([0-9]+(?:\.[0-9]+)?) ([a-z][a-z0-9]{0,15}) to ([a-z0-9][a-z0-9._-]{0,127})$/.exec(normalized);
  if (transfer !== null) {
    return buildVoiceIdTokenTransferIntent({
      amount: parseVoiceIdTokenAmount(transfer[1]),
      tokenSymbol: parseVoiceIdTokenSymbol(transfer[2]),
      recipient: parseVoiceIdPaymentRecipient(transfer[3]),
      expiresAt,
      nonce,
    });
  }

  const walletSession = /^authorize wallet session for device ([a-z0-9][a-z0-9._:-]{0,127})$/.exec(normalized);
  if (walletSession !== null) {
    return buildVoiceIdWalletSessionIntent({
      deviceId: parseVoiceIdIntentDeviceId(walletSession[1]),
      expiresAt,
      nonce,
    });
  }

  const swapApproval = /^approve swapping ([0-9]+(?:\.[0-9]+)?) ([a-z][a-z0-9]{0,15}) for ([a-z][a-z0-9]{0,15})$/.exec(normalized);
  if (swapApproval !== null) {
    return buildVoiceIdSwapApprovalIntent({
      sellAmount: parseVoiceIdTokenAmount(swapApproval[1]),
      sellTokenSymbol: parseVoiceIdTokenSymbol(swapApproval[2]),
      buyTokenSymbol: parseVoiceIdTokenSymbol(swapApproval[3]),
      expiresAt,
      nonce,
    });
  }

  const robotCommand = /^(?:robot command|command robot to|ask robot to) (.+)$/.exec(normalized);
  if (robotCommand !== null) {
    return buildVoiceIdRobotCommandIntent({
      command: parseVoiceIdRobotCommandText(robotCommand[1]),
      expiresAt,
      nonce,
    });
  }

  throw new Error('spoken command does not match a supported VoiceID intent');
}

export async function buildVoiceIdSpokenIntentBinding(input: {
  spokenCommand: VoiceIdSpokenCommand | string;
  expiresAt: IsoDateTime | string;
  nonce: VoiceIdIntentNonce | string;
}): Promise<VoiceIdSpokenIntentBinding> {
  const spokenCommand = parseVoiceIdSpokenCommand(input.spokenCommand);
  const intent = parseVoiceIdSpokenIntentCommand({
    spokenCommand,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  });
  return {
    kind: 'voice_id_spoken_intent_binding_v1',
    spokenCommand,
    normalizedCommand: normalizeSpokenIntentCommand(spokenCommand),
    intent,
    intentDigest: await buildVoiceIdIntentDigest(intent),
  };
}

export function canonicalizeVoiceIdIntent(intent: VoiceIdIntent): string {
  switch (intent.kind) {
    case 'token_transfer':
      return JSON.stringify({
        schemaVersion: intent.schemaVersion,
        kind: intent.kind,
        amount: intent.amount,
        tokenSymbol: intent.tokenSymbol,
        recipient: intent.recipient,
        expiresAt: intent.expiresAt,
        nonce: intent.nonce,
      });
    case 'wallet_session':
      return JSON.stringify({
        schemaVersion: intent.schemaVersion,
        kind: intent.kind,
        deviceId: intent.deviceId,
        expiresAt: intent.expiresAt,
        nonce: intent.nonce,
      });
    case 'swap_approval':
      return JSON.stringify({
        schemaVersion: intent.schemaVersion,
        kind: intent.kind,
        sellAmount: intent.sellAmount,
        sellTokenSymbol: intent.sellTokenSymbol,
        buyTokenSymbol: intent.buyTokenSymbol,
        expiresAt: intent.expiresAt,
        nonce: intent.nonce,
      });
    case 'robot_command':
      return JSON.stringify({
        schemaVersion: intent.schemaVersion,
        kind: intent.kind,
        command: intent.command,
        expiresAt: intent.expiresAt,
        nonce: intent.nonce,
      });
    default:
      return assertNever(intent);
  }
}

export async function buildVoiceIdIntentDigest(intent: VoiceIdIntent): Promise<VoiceIdIntentDigest> {
  const encoded = new TextEncoder().encode(canonicalizeVoiceIdIntent(intent));
  const digest = await requireSubtleCrypto().digest('SHA-256', encoded);
  return parseVoiceIdIntentDigest(base64UrlNoPadding(new Uint8Array(digest)));
}

function normalizeDecimalAmount(value: string): string {
  const [whole, fraction = ''] = value.split('.');
  const normalizedWhole = whole.replace(/^0+(?=\d)/, '');
  const normalizedFraction = fraction.replace(/0+$/, '');
  return normalizedFraction.length > 0 ? `${normalizedWhole}.${normalizedFraction}` : normalizedWhole;
}

function normalizeSpokenIntentCommand(command: VoiceIdSpokenCommand | string): string {
  return command
    .toLowerCase()
    .replace(/[^a-z0-9\s.]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => spokenIntentDigitWords.get(word) ?? word)
    .join(' ');
}

function requireSubtleCrypto(): SubtleCrypto {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi === undefined || cryptoApi.subtle === undefined) {
    throw new Error('WebCrypto subtle digest is required to build VoiceID intent digests');
  }
  return cryptoApi.subtle;
}

function base64UrlNoPadding(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let output = '';
  let index = 0;
  for (; index + 2 < bytes.length; index += 3) {
    const value = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2];
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += alphabet[(value >> 6) & 63];
    output += alphabet[value & 63];
  }
  if (index < bytes.length) {
    const first = bytes[index];
    output += alphabet[(first >> 2) & 63];
    if (index + 1 < bytes.length) {
      const second = bytes[index + 1];
      output += alphabet[((first & 3) << 4) | ((second >> 4) & 15)];
      output += alphabet[(second & 15) << 2];
    } else {
      output += alphabet[(first & 3) << 4];
    }
  }
  return output;
}
