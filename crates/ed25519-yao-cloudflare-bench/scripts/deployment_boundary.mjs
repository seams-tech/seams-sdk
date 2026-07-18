const ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/;
const PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const REGION_LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CANONICAL_PATH = "/benchmark/activation";
const DEFAULT_SAMPLE_COUNT = 51;
const MAX_SAMPLE_COUNT = 1_000;
const FIXED_SCRIPT_NAMES = Object.freeze({
  "one-account": Object.freeze({
    a: "ed25519-yao-ab-benchmark-a",
    b: "ed25519-yao-ab-benchmark-b",
  }),
  "two-account": Object.freeze({
    a: "ed25519-yao-ab-benchmark-a-cross-account",
    b: "ed25519-yao-ab-benchmark-b-cross-account",
  }),
});

export class BoundaryError extends Error {
  constructor(message) {
    super(message);
    this.name = "BoundaryError";
  }
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new BoundaryError(`${name} is required`);
  }
  return value;
}

function optional(environment, name) {
  const value = environment[name];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new BoundaryError(`${name} must be omitted or non-empty`);
  }
  return value;
}

function exactChoice(raw, name, choices) {
  if (!choices.includes(raw)) {
    throw new BoundaryError(`${name} must be one of: ${choices.join(", ")}`);
  }
  return raw;
}

function boundedPattern(raw, name, pattern) {
  if (!pattern.test(raw)) {
    throw new BoundaryError(`${name} has an invalid format`);
  }
  return raw;
}

function accountId(environment, name) {
  return boundedPattern(required(environment, name), name, ACCOUNT_ID_PATTERN);
}

function profile(environment, name) {
  return boundedPattern(required(environment, name), name, PROFILE_PATTERN);
}

function scriptName(environment, name, expected) {
  const value = required(environment, name);
  if (value !== expected) {
    throw new BoundaryError(`${name} must equal ${expected}`);
  }
  return value;
}

function regionLabel(environment) {
  return boundedPattern(
    required(environment, "YAOS_AB_REGION_LABEL"),
    "YAOS_AB_REGION_LABEL",
    REGION_LABEL_PATTERN,
  );
}

function parsePositiveInteger(raw, name, minimum, maximum) {
  if (!/^[0-9]+$/.test(raw)) {
    throw new BoundaryError(`${name} must be an integer`);
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new BoundaryError(`${name} must be from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function sampleCount(environment) {
  const raw = optional(environment, "YAOS_AB_SAMPLE_COUNT");
  if (raw === undefined) {
    return DEFAULT_SAMPLE_COUNT;
  }
  return parsePositiveInteger(raw, "YAOS_AB_SAMPLE_COUNT", 2, MAX_SAMPLE_COUNT);
}

function validateHostnameLabels(hostname, name) {
  if (hostname.length > 253 || hostname.includes("..")) {
    throw new BoundaryError(`${name} has an invalid hostname`);
  }
  const labels = hostname.split(".");
  if (labels.length < 2 || labels.some(isInvalidHostLabel)) {
    throw new BoundaryError(`${name} must be a fully qualified DNS hostname`);
  }
}

function isInvalidHostLabel(label) {
  return !HOST_LABEL_PATTERN.test(label);
}

function hostname(environment, name) {
  const raw = required(environment, name);
  if (raw !== raw.toLowerCase()) {
    throw new BoundaryError(`${name} must be lowercase`);
  }
  validateHostnameLabels(raw, name);
  return raw;
}

function canonicalEndpoint(raw, name, expectedHostname, protocol) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new BoundaryError(`${name} must be an absolute ${protocol.toUpperCase()} URL`);
  }
  if (
    url.protocol !== `${protocol}:` ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.pathname !== CANONICAL_PATH ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname !== expectedHostname
  ) {
    throw new BoundaryError(
      `${name} must be ${protocol}://${expectedHostname}${CANONICAL_PATH}`,
    );
  }
  return url.href;
}

function publicAEndpoint(environment) {
  const raw = required(environment, "YAOS_AB_A_PUBLIC_ENDPOINT");
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new BoundaryError("YAOS_AB_A_PUBLIC_ENDPOINT must be an absolute HTTPS URL");
  }
  const host = parsed.hostname;
  validateHostnameLabels(host, "YAOS_AB_A_PUBLIC_ENDPOINT");
  return {
    endpoint: canonicalEndpoint(raw, "YAOS_AB_A_PUBLIC_ENDPOINT", host, "https"),
    hostname: host,
  };
}

function crossAccountBEndpoint(environment, aHostname) {
  const bHostname = hostname(environment, "YAOS_AB_B_HOSTNAME");
  if (bHostname === aHostname) {
    throw new BoundaryError("A and B hostnames must differ in two-account mode");
  }
  const endpoint = canonicalEndpoint(
    required(environment, "YAOS_AB_B_WEBSOCKET_ENDPOINT"),
    "YAOS_AB_B_WEBSOCKET_ENDPOINT",
    bHostname,
    "wss",
  );
  return { hostname: bHostname, endpoint };
}

function assertAccountTopology(topology, aAccount, bAccount, aProfile, bProfile) {
  if (topology === "one-account" && aAccount !== bAccount) {
    throw new BoundaryError("one-account mode requires equal A and B account IDs");
  }
  if (topology === "two-account" && aAccount === bAccount) {
    throw new BoundaryError("two-account mode requires distinct A and B account IDs");
  }
  if (topology === "two-account" && aProfile === bProfile) {
    throw new BoundaryError("two-account mode requires distinct A and B profiles");
  }
}

export function parseDeploymentEnvironment(environment) {
  const topology = exactChoice(required(environment, "YAOS_AB_TOPOLOGY"), "YAOS_AB_TOPOLOGY", [
    "one-account",
    "two-account",
  ]);
  const aAccount = accountId(environment, "YAOS_AB_A_ACCOUNT_ID");
  const bAccount = accountId(environment, "YAOS_AB_B_ACCOUNT_ID");
  const aProfile = profile(environment, "YAOS_AB_A_PROFILE");
  const bProfile = profile(environment, "YAOS_AB_B_PROFILE");
  assertAccountTopology(topology, aAccount, bAccount, aProfile, bProfile);
  const aPublic = publicAEndpoint(environment);
  const bPublic =
    topology === "two-account"
      ? crossAccountBEndpoint(environment, aPublic.hostname)
      : undefined;
  const fixedScriptNames = FIXED_SCRIPT_NAMES[topology];
  return Object.freeze({
    topology,
    expectedTopologyLabel:
      topology === "one-account"
        ? "same-account-service-binding-websocket"
        : "cross-account-websocket",
    a: Object.freeze({
      accountId: aAccount,
      profile: aProfile,
      scriptName: scriptName(
        environment,
        "YAOS_AB_A_SCRIPT_NAME",
        fixedScriptNames.a,
      ),
      publicHostname: aPublic.hostname,
      publicEndpoint: aPublic.endpoint,
    }),
    b: Object.freeze({
      accountId: bAccount,
      profile: bProfile,
      scriptName: scriptName(
        environment,
        "YAOS_AB_B_SCRIPT_NAME",
        fixedScriptNames.b,
      ),
      publicHostname: bPublic?.hostname,
      publicEndpoint: bPublic?.endpoint,
    }),
    sampleCount: sampleCount(environment),
    regionLabel: regionLabel(environment),
  });
}

export function parseIsoInstant(raw, name) {
  const timestamp = Date.parse(raw);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== raw) {
    throw new BoundaryError(`${name} must be a canonical ISO-8601 UTC instant`);
  }
  return Object.freeze({ raw, timestamp });
}

export function parseAnalyticsWindow(environment) {
  const start = parseIsoInstant(required(environment, "YAOS_AB_ANALYTICS_START"), "YAOS_AB_ANALYTICS_START");
  const end = parseIsoInstant(required(environment, "YAOS_AB_ANALYTICS_END"), "YAOS_AB_ANALYTICS_END");
  if (start.timestamp >= end.timestamp) {
    throw new BoundaryError("YAOS_AB_ANALYTICS_START must precede YAOS_AB_ANALYTICS_END");
  }
  return Object.freeze({ start: start.raw, end: end.raw });
}

export function requireAnalyticsToken(environment, role, allowAForB) {
  const name = role === "a" ? "CLOUDFLARE_ANALYTICS_TOKEN_A" : "CLOUDFLARE_ANALYTICS_TOKEN_B";
  const direct = optional(environment, name);
  const fallback = allowAForB ? optional(environment, "CLOUDFLARE_ANALYTICS_TOKEN_A") : undefined;
  const token = direct ?? fallback;
  if (token === undefined || token.length < 16 || token.length > 4096 || /\s/.test(token)) {
    throw new BoundaryError(`${name} must contain a non-whitespace API token`);
  }
  return token;
}

export const deploymentConstants = Object.freeze({
  canonicalPath: CANONICAL_PATH,
  defaultSampleCount: DEFAULT_SAMPLE_COUNT,
  maxSampleCount: MAX_SAMPLE_COUNT,
});
