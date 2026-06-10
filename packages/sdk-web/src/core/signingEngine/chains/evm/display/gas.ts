function formatScaled(value: bigint, scale: bigint): string {
  const integer = value / scale;
  const remainder = value % scale;
  if (remainder === 0n) return integer.toString();

  const scaledRemainder = (remainder * 100n) / scale;
  if (scaledRemainder === 0n) return integer.toString();
  const fractional = scaledRemainder.toString().padStart(2, '0').replace(/0+$/, '');
  return fractional ? `${integer.toString()}.${fractional}` : integer.toString();
}

export function formatCompactGas(value: bigint): string {
  if (value >= 1_000_000n) return `${formatScaled(value, 1_000_000n)}mil`;
  if (value >= 1_000n) return `${formatScaled(value, 1_000n)}k`;
  return value.toString();
}
