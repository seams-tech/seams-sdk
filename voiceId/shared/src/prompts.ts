import type { VoiceIdPromptSetId } from './ids.ts';

export type VoiceIdPromptPhrase = string & { readonly __brand: 'VoiceIdPromptPhrase' };

export type VoiceIdPrompt = {
  promptSetId: VoiceIdPromptSetId;
  phrase: VoiceIdPromptPhrase;
};

export type VoiceIdEnrollmentPromptSequence = readonly [
  VoiceIdPromptPhrase,
  VoiceIdPromptPhrase,
  VoiceIdPromptPhrase,
  VoiceIdPromptPhrase,
];

const digitWords = new Map<string, string>([
  ['zero', '0'],
  ['oh', '0'],
  ['o', '0'],
  ['one', '1'],
  ['two', '2'],
  ['three', '3'],
  ['four', '4'],
  ['for', '4'],
  ['five', '5'],
  ['six', '6'],
  ['seven', '7'],
  ['eight', '8'],
  ['ate', '8'],
  ['nine', '9'],
]);

export function parsePromptPhrase(value: unknown): VoiceIdPromptPhrase {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error('prompt phrase must be a non-empty string');
  }

  return value.trim() as VoiceIdPromptPhrase;
}

export function normalizePromptPhrase(phrase: VoiceIdPromptPhrase | string): string {
  const normalizedWords = phrase
    .toLowerCase()
    .replace(/[^a-z0-9\s.]/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => digitWords.get(word) ?? word);

  const everyTokenIsDigit = normalizedWords.length > 0 && normalizedWords.every((word) => /^\d+$/.test(word));
  if (everyTokenIsDigit) {
    return normalizedWords.join('');
  }

  return normalizedWords.join(' ');
}

export function parseEnrollmentPromptSequence(value: unknown): VoiceIdEnrollmentPromptSequence {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new Error('enrollment prompt sequence must contain exactly four phrases');
  }

  return [
    parsePromptPhrase(value[0]),
    parsePromptPhrase(value[1]),
    parsePromptPhrase(value[2]),
    parsePromptPhrase(value[3]),
  ];
}

export function combineEnrollmentPromptSequence(
  prompts: VoiceIdEnrollmentPromptSequence,
): VoiceIdPromptPhrase {
  return parsePromptPhrase(prompts.join('. '));
}
