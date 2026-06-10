const UINT64_MASK = (1n << 64n) - 1n;
const KECCAK_RATE_BYTES = 136; // Keccak-256 uses rate 1088 bits (136 bytes)
const KECCAK256_OUTPUT_BYTES = 32;

// Rotation offsets for the Rho step and destination indexes for Pi.
const ROTATION_OFFSETS = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI_LANE_INDEXES = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const ROUND_CONSTANTS = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

function rotateLeft64(value: bigint, shift: number): bigint {
  const n = BigInt(shift);
  return ((value << n) | (value >> (64n - n))) & UINT64_MASK;
}

function keccakF1600(state: bigint[]): void {
  const c = new Array<bigint>(5);
  const d = new Array<bigint>(5);

  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] =
        state[x] ^
        state[x + 5] ^
        state[x + 10] ^
        state[x + 15] ^
        state[x + 20];
    }

    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5]! ^ rotateLeft64(c[(x + 1) % 5]!, 1);
    }

    for (let y = 0; y < 5; y += 1) {
      const rowOffset = y * 5;
      for (let x = 0; x < 5; x += 1) {
        state[rowOffset + x] ^= d[x]!;
      }
    }

    let lane = state[1]!;
    for (let i = 0; i < 24; i += 1) {
      const targetIndex = PI_LANE_INDEXES[i]!;
      const nextLane = state[targetIndex]!;
      state[targetIndex] = rotateLeft64(lane, ROTATION_OFFSETS[i]!);
      lane = nextLane;
    }

    for (let y = 0; y < 5; y += 1) {
      const rowOffset = y * 5;
      const lane0 = state[rowOffset]!;
      const lane1 = state[rowOffset + 1]!;
      const lane2 = state[rowOffset + 2]!;
      const lane3 = state[rowOffset + 3]!;
      const lane4 = state[rowOffset + 4]!;

      state[rowOffset] = (lane0 ^ ((~lane1 & UINT64_MASK) & lane2)) & UINT64_MASK;
      state[rowOffset + 1] = (lane1 ^ ((~lane2 & UINT64_MASK) & lane3)) & UINT64_MASK;
      state[rowOffset + 2] = (lane2 ^ ((~lane3 & UINT64_MASK) & lane4)) & UINT64_MASK;
      state[rowOffset + 3] = (lane3 ^ ((~lane4 & UINT64_MASK) & lane0)) & UINT64_MASK;
      state[rowOffset + 4] = (lane4 ^ ((~lane0 & UINT64_MASK) & lane1)) & UINT64_MASK;
    }

    state[0] ^= ROUND_CONSTANTS[round]!;
  }
}

function absorbByte(state: bigint[], offset: number, byte: number): void {
  const laneIndex = Math.floor(offset / 8);
  const laneShift = BigInt((offset % 8) * 8);
  state[laneIndex] ^= BigInt(byte) << laneShift;
}

export function keccak256Bytes(input: Uint8Array): Uint8Array {
  const state = new Array<bigint>(25).fill(0n);
  let offset = 0;

  for (let i = 0; i < input.length; i += 1) {
    absorbByte(state, offset, input[i]!);
    offset += 1;
    if (offset === KECCAK_RATE_BYTES) {
      keccakF1600(state);
      offset = 0;
    }
  }

  // Keccak padding: domain separator 0x01, then final bit 0x80.
  absorbByte(state, offset, 0x01);
  absorbByte(state, KECCAK_RATE_BYTES - 1, 0x80);
  keccakF1600(state);

  const out = new Uint8Array(KECCAK256_OUTPUT_BYTES);
  for (let i = 0; i < KECCAK256_OUTPUT_BYTES; i += 1) {
    const lane = state[Math.floor(i / 8)]!;
    const laneShift = BigInt((i % 8) * 8);
    out[i] = Number((lane >> laneShift) & 0xffn);
  }
  return out;
}
