const SELECTOR_HEX_RE = /^0x[0-9a-f]{8}$/;
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;

const TEMPO_GREETING_CONTRACT = '0x96cfe92241481954ada6410409a86acb6e76a00e';
const ARC_GREETING_CONTRACT = '0xeb7ab5a6f761072c96147a54b8a15f012e836691';

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
  '0xe7897444': 'setUserToken(address)',
  '0xf2fde38b': 'transferOwnership(address)',
});

// Contract-specific selector map derived from known contract ABIs.
const KNOWN_CONTRACT_FUNCTION_SIGNATURES: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  [TEMPO_GREETING_CONTRACT]: Object.freeze({
    '0xa4136862': 'setGreeting(string)',
    '0xcfae3217': 'greet()',
  }),
  [ARC_GREETING_CONTRACT]: Object.freeze({
    '0xa4136862': 'setGreeting(string)',
    '0xcfae3217': 'greet()',
  }),
});

function normalizeSelector(selector: string | undefined): string | undefined {
  const normalized = String(selector || '').trim().toLowerCase();
  if (!SELECTOR_HEX_RE.test(normalized)) return undefined;
  return normalized;
}

function normalizeContractAddress(contractAddress: string | undefined): string | undefined {
  const normalized = String(contractAddress || '').trim().toLowerCase();
  if (!EVM_ADDRESS_RE.test(normalized)) return undefined;
  return normalized;
}

export function selectorFromHexData(data: string | undefined): string | undefined {
  const normalized = String(data || '').trim().toLowerCase();
  if (!normalized.startsWith('0x') || normalized.length < 10) return undefined;
  const selector = normalized.slice(0, 10);
  return normalizeSelector(selector);
}

export function resolveFunctionSignature(
  selector: string | undefined,
  contractAddress?: string,
): string | undefined {
  const normalized = normalizeSelector(selector);
  if (!normalized) return undefined;
  const normalizedContractAddress = normalizeContractAddress(contractAddress);
  if (normalizedContractAddress) {
    const contractMap = KNOWN_CONTRACT_FUNCTION_SIGNATURES[normalizedContractAddress];
    if (contractMap && contractMap[normalized]) return contractMap[normalized];
  }
  return KNOWN_FUNCTION_SIGNATURES[normalized];
}

export function resolveFunctionDisplayName(
  selector: string | undefined,
  contractAddress?: string,
): string | undefined {
  const signature = resolveFunctionSignature(selector, contractAddress);
  if (signature) {
    const idx = signature.indexOf('(');
    const name = idx > 0 ? signature.slice(0, idx) : signature;
    const normalizedName = name.trim();
    if (normalizedName) return `${normalizedName}()`;
  }

  const normalizedSelector = normalizeSelector(selector);
  if (normalizedSelector) return `function ${normalizedSelector}`;
  return undefined;
}
