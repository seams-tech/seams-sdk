export function assertNever(value: never): never {
  throw new Error(`Unhandled passkey registration button state: ${String(value)}`);
}
