export function coerceThemeMode(input: unknown): 'light' | 'dark' | undefined {
  return input === 'light' || input === 'dark' ? input : undefined;
}
