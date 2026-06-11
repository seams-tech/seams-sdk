export function assertNever(value: never): never {
  throw new Error(`Unexpected VoiceID branch: ${String(value)}`);
}
