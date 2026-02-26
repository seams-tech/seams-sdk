function normalizeHex(dataHex: string | undefined): string {
  const raw = String(dataHex || '')
    .trim()
    .toLowerCase();
  if (!raw || raw === '0x') return '0x';
  return raw.startsWith('0x') ? raw : `0x${raw}`;
}

function splitIntoRows(hexWithoutPrefix: string, charsPerRow: number): string[] {
  const rows: string[] = [];
  for (let index = 0; index < hexWithoutPrefix.length; index += charsPerRow) {
    rows.push(hexWithoutPrefix.slice(index, index + charsPerRow));
  }
  return rows;
}

/**
 * EVM calldata starts with a 4-byte selector followed by ABI words (32-byte slots).
 * Render selector on the first line and then split remaining bytes into 32-byte rows.
 */
export function formatCalldataForDisplay(dataHex: string | undefined): string {
  const normalized = normalizeHex(dataHex);
  if (normalized === '0x') return 'data: 0x';

  const hex = normalized.slice(2);
  if (!hex) return 'data: 0x';

  if (hex.length <= 8) return `data: 0x${hex}`;

  const selector = hex.slice(0, 8);
  const abiEncodedArgs = hex.slice(8);
  const rows = splitIntoRows(abiEncodedArgs, 64);
  return [`data: 0x${selector}`, ...rows].join('\n');
}
