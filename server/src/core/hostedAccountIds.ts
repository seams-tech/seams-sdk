import { isValidAccountId, toOptionalTrimmedString } from '@shared/utils/validation';

const DOMAIN = 'near_account_slug_v1';

const ADJECTIVES = [
  'amber',
  'arctic',
  'autumn',
  'brisk',
  'calm',
  'cedar',
  'clear',
  'cobalt',
  'coral',
  'cosmic',
  'crisp',
  'dawn',
  'deep',
  'ember',
  'fair',
  'fresh',
  'frost',
  'gentle',
  'golden',
  'green',
  'hidden',
  'high',
  'ivory',
  'jade',
  'keen',
  'kind',
  'lunar',
  'maple',
  'misty',
  'neon',
  'nimble',
  'noble',
  'opal',
  'quiet',
  'rapid',
  'river',
  'sage',
  'silver',
  'solar',
  'spruce',
  'steady',
  'stone',
  'sunny',
  'swift',
  'tidal',
  'true',
  'urban',
  'velvet',
  'vivid',
  'warm',
  'wild',
  'winter',
  'wise',
  'young',
  'zen',
  'azure',
  'bright',
  'cloud',
  'distant',
  'glad',
  'honest',
  'loyal',
  'prime',
  'zesty',
] as const;

const NOUNS = [
  'anchor',
  'ash',
  'bay',
  'beacon',
  'birch',
  'brook',
  'canyon',
  'cliff',
  'comet',
  'cove',
  'delta',
  'dune',
  'field',
  'flare',
  'forest',
  'grove',
  'harbor',
  'hill',
  'isle',
  'lagoon',
  'lake',
  'leaf',
  'light',
  'meadow',
  'mesa',
  'moon',
  'nova',
  'oasis',
  'orchid',
  'peak',
  'pine',
  'plain',
  'reef',
  'ridge',
  'river',
  'rock',
  'shell',
  'shore',
  'sky',
  'spark',
  'spring',
  'star',
  'stone',
  'summit',
  'sun',
  'thicket',
  'trail',
  'vale',
  'valley',
  'wave',
  'willow',
  'wind',
  'wood',
  'zephyr',
  'atlas',
  'bridge',
  'garden',
  'haven',
  'lantern',
  'maple',
  'signal',
  'silver',
  'tempo',
  'vista',
] as const;

function requireNonEmpty(label: string, value: unknown): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function bytesToUint32(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] || 0) * 0x1000000 +
      ((bytes[offset + 1] || 0) << 16) +
      ((bytes[offset + 2] || 0) << 8) +
      (bytes[offset + 3] || 0)) >>>
    0
  );
}

function bytesToBase36(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes.slice(8, 16)) {
    value = (value << 8n) + BigInt(byte);
  }
  return value.toString(36);
}

async function hmacSha256(secret: string, context: string): Promise<Uint8Array> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto (crypto.subtle) is unavailable in this runtime');
  }
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(context));
  return new Uint8Array(mac);
}

export async function deriveHostedNearAccountId(input: {
  accountIdDerivationSecret: string;
  relayerAccount: string;
  projectId: string;
  envId: string;
  authProvider: string;
  providerSubject?: string;
  verifiedEmail?: string;
  collisionCounter?: number;
}): Promise<string> {
  const secret = requireNonEmpty('ACCOUNT_ID_DERIVATION_SECRET', input.accountIdDerivationSecret);
  const relayerAccount = requireNonEmpty('relayerAccount', input.relayerAccount);
  if (!isValidAccountId(relayerAccount)) {
    throw new Error('Hosted account ID generation requires a valid relayerAccount');
  }
  const projectId = requireNonEmpty('projectId', input.projectId);
  const envId = requireNonEmpty('envId', input.envId);
  const authProvider = requireNonEmpty('authProvider', input.authProvider);
  const providerSubject = toOptionalTrimmedString(input.providerSubject);
  const verifiedEmail = toOptionalTrimmedString(input.verifiedEmail);
  const identity = providerSubject || verifiedEmail;
  if (!identity) {
    throw new Error('Hosted account ID generation requires providerSubject or verifiedEmail');
  }
  const collisionCounter = Math.max(0, Math.floor(Number(input.collisionCounter) || 0));
  const contextParts = [DOMAIN, projectId, envId, authProvider, identity];
  if (collisionCounter > 0) contextParts.push(`collision:${collisionCounter}`);

  const seed = await hmacSha256(secret, contextParts.join('\0'));
  const adjective = ADJECTIVES[bytesToUint32(seed, 0) % ADJECTIVES.length];
  const noun = NOUNS[bytesToUint32(seed, 4) % NOUNS.length];
  const suffix = bytesToBase36(seed).padStart(10, '0').slice(0, 10);
  const walletId = `${adjective}-${noun}-${suffix}.${relayerAccount}`;
  if (!isValidAccountId(walletId)) {
    throw new Error('Generated hosted NEAR account ID is invalid');
  }
  return walletId;
}
