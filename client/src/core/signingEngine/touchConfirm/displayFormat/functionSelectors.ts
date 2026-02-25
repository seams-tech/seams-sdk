const SELECTOR_HEX_RE = /^0x[0-9a-f]{8}$/;

// Best-effort mapping for common EVM selectors.
const KNOWN_FUNCTION_SIGNATURES: Readonly<Record<string, string>> = Object.freeze({
  '0x06fdde03': 'name()',
  '0x095ea7b3': 'approve(address,uint256)',
  '0x18160ddd': 'totalSupply()',
  '0x23b872dd': 'transferFrom(address,address,uint256)',
  '0x2e1a7d4d': 'withdraw(uint256)',
  '0x313ce567': 'decimals()',
  '0x42842e0e': 'safeTransferFrom(address,address,uint256)',
  '0x47e1da2a': 'executeBatch(address[],uint256[],bytes[])',
  '0x6352211e': 'ownerOf(uint256)',
  '0x70a08231': 'balanceOf(address)',
  '0x081812fc': 'getApproved(uint256)',
  '0x95d89b41': 'symbol()',
  '0xa22cb465': 'setApprovalForAll(address,bool)',
  '0xa9059cbb': 'transfer(address,uint256)',
  '0xb61d27f6': 'execute(address,uint256,bytes)',
  '0xb88d4fde': 'safeTransferFrom(address,address,uint256,bytes)',
  '0xd0e30db0': 'deposit()',
  '0xd505accf': 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
  '0xdd62ed3e': 'allowance(address,address)',
  '0xe985e9c5': 'isApprovedForAll(address,address)',
  '0xf2fde38b': 'transferOwnership(address)',
});

function normalizeSelector(selector: string | undefined): string | undefined {
  const normalized = String(selector || '').trim().toLowerCase();
  if (!SELECTOR_HEX_RE.test(normalized)) return undefined;
  return normalized;
}

export function selectorFromHexData(data: string | undefined): string | undefined {
  const normalized = String(data || '').trim().toLowerCase();
  if (!normalized.startsWith('0x') || normalized.length < 10) return undefined;
  const selector = normalized.slice(0, 10);
  return normalizeSelector(selector);
}

export function resolveFunctionSignature(selector: string | undefined): string | undefined {
  const normalized = normalizeSelector(selector);
  if (!normalized) return undefined;
  return KNOWN_FUNCTION_SIGNATURES[normalized];
}
