#!/usr/bin/env node

const VERSION_PATTERN = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/u;
const CONTRACT_FIELDS = Object.freeze(['gatewayApiContractVersion']);
const RANGE_FIELDS = Object.freeze(['maxInclusive', 'minInclusive']);

export const API_COMPATIBILITY_SCHEMA_VERSION = 1;

export function createFrontendApiContract(value) {
  const contract = parseFrontendApiContract(value);
  return deepFreeze({
    gatewayApiContractVersion: contract.gatewayApiContractVersion,
  });
}

export function parseFrontendApiContract(value) {
  assertExactKeys(value, CONTRACT_FIELDS, 'frontend API contract');
  if (!isRecord(value)) {
    throw new TypeError('frontend API contract is invalid');
  }
  const version = parseGatewayApiContractVersion(value.gatewayApiContractVersion);
  return deepFreeze({ gatewayApiContractVersion: version.value });
}

export function parseGatewayApiContractVersion(value) {
  if (typeof value !== 'string' || !VERSION_PATTERN.test(value)) {
    throw new TypeError(
      'gateway API contract version must use the MAJOR.MINOR.PATCH format with non-negative integers',
    );
  }
  const parts = value.split('.').map(Number);
  return deepFreeze({ major: parts[0], minor: parts[1], patch: parts[2], value });
}

export function parseSupportedFrontendApiContractRange(value) {
  assertExactKeys(value, RANGE_FIELDS, 'supported frontend API contract range');
  if (!isRecord(value)) {
    throw new TypeError('supported frontend API contract range is invalid');
  }
  const min = parseGatewayApiContractVersion(value.minInclusive);
  const max = parseGatewayApiContractVersion(value.maxInclusive);
  if (compareVersions(min, max) > 0) {
    throw new RangeError('supported frontend API contract range minimum exceeds maximum');
  }
  return deepFreeze({ minInclusive: min.value, maxInclusive: max.value });
}

export function assertFrontendApiCompatible(frontendValue, backendRangeValue) {
  const frontend = parseFrontendApiContract(frontendValue);
  const range = parseSupportedFrontendApiContractRange(backendRangeValue);
  const version = parseGatewayApiContractVersion(frontend.gatewayApiContractVersion);
  const minimum = parseGatewayApiContractVersion(range.minInclusive);
  const maximum = parseGatewayApiContractVersion(range.maxInclusive);
  if (compareVersions(version, minimum) < 0 || compareVersions(version, maximum) > 0) {
    throw new Error(
      `frontend Gateway API contract ${version.value} is outside supported range ${minimum.value}..${maximum.value}`,
    );
  }
  return deepFreeze({
    gatewayApiContractVersion: version.value,
    supportedFrontendApiContractRange: {
      minInclusive: minimum.value,
      maxInclusive: maximum.value,
    },
  });
}

export function compareGatewayApiContractVersions(leftValue, rightValue) {
  const left = parseGatewayApiContractVersion(leftValue);
  const right = parseGatewayApiContractVersion(rightValue);
  return compareVersions(left, right);
}

function compareVersions(left, right) {
  if (left.major !== right.major) return left.major - right.major;
  if (left.minor !== right.minor) return left.minor - right.minor;
  return left.patch - right.patch;
}

function assertExactKeys(value, expectedKeys, label) {
  if (!isRecord(value)) throw new TypeError(`${label} is invalid`);
  const actualKeys = Object.keys(value).sort();
  const canonicalExpectedKeys = [...expectedKeys].sort();
  if (actualKeys.length !== canonicalExpectedKeys.length) {
    throw new TypeError(`${label} fields are invalid`);
  }
  for (let index = 0; index < actualKeys.length; index += 1) {
    if (actualKeys[index] !== canonicalExpectedKeys[index]) {
      throw new TypeError(`${label} fields are invalid`);
    }
  }
}

function deepFreeze(value) {
  if (!isRecord(value) && !Array.isArray(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
