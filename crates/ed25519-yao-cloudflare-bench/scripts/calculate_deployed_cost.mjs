import { pathToFileURL } from "node:url";

import {
  BoundaryError,
  parseDeploymentEnvironment,
  parseIsoInstant,
} from "./deployment_boundary.mjs";
import {
  deploymentReceiptEvidence,
  deploymentReceiptPath,
  readDeploymentReceipt,
} from "./deployment_receipt.mjs";

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new BoundaryError(`${name} is required`);
  }
  return value;
}

function decimal(environment, name) {
  const raw = required(environment, name);
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(raw)) {
    throw new BoundaryError(`${name} must be a nonnegative decimal`);
  }
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new BoundaryError(`${name} is outside the supported range`);
  }
  return value;
}

function positiveSafeInteger(environment, name) {
  const raw = required(environment, name);
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new BoundaryError(`${name} must be a positive integer`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) {
    throw new BoundaryError(`${name} must be a positive safe integer`);
  }
  return value;
}

function positiveDecimal(environment, name) {
  const value = decimal(environment, name);
  if (value <= 0) {
    throw new BoundaryError(`${name} must be greater than zero`);
  }
  return value;
}

function effectiveDate(environment) {
  const raw = required(environment, "YAOS_AB_PRICE_EFFECTIVE_DATE");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new BoundaryError("YAOS_AB_PRICE_EFFECTIVE_DATE must be YYYY-MM-DD");
  }
  const canonical = new Date(`${raw}T00:00:00.000Z`).toISOString().slice(0, 10);
  if (canonical !== raw) {
    throw new BoundaryError("YAOS_AB_PRICE_EFFECTIVE_DATE is not a calendar date");
  }
  return raw;
}

function pricingSource(environment) {
  const raw = boundedText(environment, "YAOS_AB_PRICE_SOURCE", 512);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new BoundaryError("YAOS_AB_PRICE_SOURCE must be an absolute HTTPS URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.hostname === "example" ||
    parsed.hostname.endsWith(".example")
  ) {
    throw new BoundaryError("YAOS_AB_PRICE_SOURCE must be a non-placeholder HTTPS URL");
  }
  return parsed.href;
}

function topology(environment) {
  const value = required(environment, "YAOS_AB_TOPOLOGY");
  if (value !== "one-account" && value !== "two-account") {
    throw new BoundaryError("YAOS_AB_TOPOLOGY must be one-account or two-account");
  }
  return value;
}

function boundedText(environment, name, maximum) {
  const value = required(environment, name);
  if (value.length > maximum || /[\r\n\0]/.test(value)) {
    throw new BoundaryError(`${name} has an invalid format`);
  }
  return value;
}

function accountRates(environment, suffix) {
  return Object.freeze({
    requestsUsdPerMillion: positiveDecimal(
      environment,
      `YAOS_AB_PRICE_REQUESTS_USD_PER_MILLION_${suffix}`,
    ),
    cpuUsdPerMillionMs: positiveDecimal(
      environment,
      `YAOS_AB_PRICE_CPU_USD_PER_MILLION_MS_${suffix}`,
    ),
    includedRequests: decimal(environment, `YAOS_AB_INCLUDED_REQUESTS_${suffix}`),
    includedCpuMs: decimal(environment, `YAOS_AB_INCLUDED_CPU_MS_${suffix}`),
  });
}

export function parseCostEnvironment(environment) {
  const selectedTopology = topology(environment);
  const usageModel = required(environment, "YAOS_AB_PRICE_USAGE_MODEL");
  if (usageModel !== "standard") {
    throw new BoundaryError("YAOS_AB_PRICE_USAGE_MODEL must be standard for this request model");
  }
  return Object.freeze({
    topology: selectedTopology,
    ceremonies: positiveSafeInteger(environment, "YAOS_AB_COST_CEREMONIES"),
    measured: Object.freeze({
      requestsAPerCeremony: decimal(environment, "YAOS_AB_MEASURED_REQUESTS_A_PER_CEREMONY"),
      requestsBPerCeremony: decimal(environment, "YAOS_AB_MEASURED_REQUESTS_B_PER_CEREMONY"),
      cpuAMsPerCeremony: decimal(environment, "YAOS_AB_MEASURED_CPU_A_MS_PER_CEREMONY"),
      cpuBMsPerCeremony: decimal(environment, "YAOS_AB_MEASURED_CPU_B_MS_PER_CEREMONY"),
      networkBytesPerCeremony: decimal(environment, "YAOS_AB_MEASURED_NETWORK_BYTES_PER_CEREMONY"),
      statistic: boundedText(environment, "YAOS_AB_MEASURED_CPU_STATISTIC", 64),
    }),
    rates: Object.freeze({
      usageModel,
      a: accountRates(environment, "A"),
      b: accountRates(environment, "B"),
      networkUsdPerGb: decimal(environment, "YAOS_AB_PRICE_NETWORK_USD_PER_GB"),
      effectiveDate: effectiveDate(environment),
      source: pricingSource(environment),
    }),
  });
}

function billable(total, included) {
  return Math.max(0, total - included);
}

function requestCost(requests, included, rate) {
  return (billable(requests, included) / 1_000_000) * rate;
}

function cpuCost(cpuMs, included, rate) {
  return (billable(cpuMs, included) / 1_000_000) * rate;
}

function accountCost(requests, cpuMs, rates) {
  const billableRequests = billable(requests, rates.includedRequests);
  const billableCpuMs = billable(cpuMs, rates.includedCpuMs);
  const requestsUsd = requestCost(requests, rates.includedRequests, rates.requestsUsdPerMillion);
  const cpuUsd = cpuCost(cpuMs, rates.includedCpuMs, rates.cpuUsdPerMillionMs);
  return Object.freeze({
    measured_requests: requests,
    measured_cpu_ms: cpuMs,
    included_requests: rates.includedRequests,
    included_cpu_ms: rates.includedCpuMs,
    billable_requests: billableRequests,
    billable_cpu_ms: billableCpuMs,
    requests_usd: requestsUsd,
    cpu_usd: cpuUsd,
    subtotal_usd: requestsUsd + cpuUsd,
  });
}

function expectedRequestShape(selectedTopology) {
  return selectedTopology === "one-account"
    ? Object.freeze({ a: 1, b: 0 })
    : Object.freeze({ a: 1, b: 1 });
}

function expectedTopologyLabel(selectedTopology) {
  return selectedTopology === "one-account"
    ? "same-account-service-binding"
    : "cross-account-https";
}

export function costEvidenceMetadata(deploymentConfiguration, receipt, generatedAt) {
  const deployment = deploymentReceiptEvidence(receipt);
  if (deployment.topology !== deploymentConfiguration.expectedTopologyLabel) {
    throw new BoundaryError("cost evidence deployment topology does not match configuration");
  }
  return Object.freeze({
    deployment,
    regionLabel: deploymentConfiguration.regionLabel,
    generatedAt: parseIsoInstant(generatedAt, "generated_at").raw,
  });
}

function requireCostEvidenceMetadata(configuration, metadata) {
  if (
    metadata === null ||
    typeof metadata !== "object" ||
    Array.isArray(metadata) ||
    metadata.deployment === null ||
    typeof metadata.deployment !== "object" ||
    metadata.deployment.topology !== expectedTopologyLabel(configuration.topology) ||
    typeof metadata.regionLabel !== "string" ||
    metadata.regionLabel.length === 0
  ) {
    throw new BoundaryError("cost evidence metadata does not match the measured topology");
  }
  parseIsoInstant(metadata.generatedAt, "generated_at");
  return metadata;
}

function sameAccountCosts(configuration) {
  const requests =
    configuration.ceremonies *
    (configuration.measured.requestsAPerCeremony + configuration.measured.requestsBPerCeremony);
  const cpuMs =
    configuration.ceremonies *
    (configuration.measured.cpuAMsPerCeremony + configuration.measured.cpuBMsPerCeremony);
  return Object.freeze({
    a_account_combined: accountCost(requests, cpuMs, configuration.rates.a),
    b_account: null,
  });
}

function twoAccountCosts(configuration) {
  return Object.freeze({
    a_account_combined: accountCost(
      configuration.ceremonies * configuration.measured.requestsAPerCeremony,
      configuration.ceremonies * configuration.measured.cpuAMsPerCeremony,
      configuration.rates.a,
    ),
    b_account: accountCost(
      configuration.ceremonies * configuration.measured.requestsBPerCeremony,
      configuration.ceremonies * configuration.measured.cpuBMsPerCeremony,
      configuration.rates.b,
    ),
  });
}

function costSubtotal(accountCosts) {
  return (
    accountCosts.a_account_combined.subtotal_usd +
    (accountCosts.b_account?.subtotal_usd ?? 0)
  );
}

function requireFiniteCalculated(value, name) {
  if (!Number.isFinite(value)) {
    throw new BoundaryError(`${name} exceeds the supported calculation range`);
  }
  return value;
}

export function calculateCost(configuration, rawEvidenceMetadata) {
  const evidenceMetadata = requireCostEvidenceMetadata(configuration, rawEvidenceMetadata);
  const expected = expectedRequestShape(configuration.topology);
  const accountCosts =
    configuration.topology === "one-account"
      ? sameAccountCosts(configuration)
      : twoAccountCosts(configuration);
  const networkGb =
    (configuration.ceremonies * configuration.measured.networkBytesPerCeremony) / 1_000_000_000;
  const networkUsd = networkGb * configuration.rates.networkUsdPerGb;
  const totalUsd = costSubtotal(accountCosts) + networkUsd;
  requireFiniteCalculated(networkGb, "modeled network volume");
  requireFiniteCalculated(networkUsd, "modeled network cost");
  requireFiniteCalculated(totalUsd, "modeled total cost");
  return Object.freeze({
    benchmark: "phase9b-cloudflare-cost-model",
    benchmark_only: true,
    topology: configuration.topology,
    deployment: evidenceMetadata.deployment,
    region_label: evidenceMetadata.regionLabel,
    generated_at: evidenceMetadata.generatedAt,
    ceremonies: configuration.ceremonies,
    measured_cpu_statistic: configuration.measured.statistic,
    measured: configuration.measured,
    request_model: Object.freeze({
      expected_per_ceremony: expected,
      measured_per_ceremony: Object.freeze({
        a: configuration.measured.requestsAPerCeremony,
        b: configuration.measured.requestsBPerCeremony,
      }),
      matches_expected:
        configuration.measured.requestsAPerCeremony === expected.a &&
        configuration.measured.requestsBPerCeremony === expected.b,
      same_account_note:
        "A inbound is billed once; the Service Binding invocation is not a second billed request; A and B CPU are combined in one account.",
      two_account_note:
        "A inbound and B public HTTPS inbound are billed in their respective accounts; A's outbound subrequest is not a third billed request.",
    }),
    pricing: Object.freeze({
      usage_model: configuration.rates.usageModel,
      effective_date: configuration.rates.effectiveDate,
      source: configuration.rates.source,
      user_supplied: true,
      network_usd_per_gb: configuration.rates.networkUsdPerGb,
      accounts: Object.freeze({
        a: configuration.rates.a,
        b: configuration.rates.b,
      }),
    }),
    account_costs: accountCosts,
    network: Object.freeze({
      measured_bytes: configuration.ceremonies * configuration.measured.networkBytesPerCeremony,
      decimal_gb: networkGb,
      usd: networkUsd,
      note:
        "Cloudflare Workers currently documents no added bandwidth/egress charge. Supply zero only after checking the effective pricing source; the calculator does not hardcode it.",
    }),
    total_usd: totalUsd,
    usd_per_ceremony: totalUsd / configuration.ceremonies,
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

function main() {
  const deploymentConfiguration = parseDeploymentEnvironment(process.env);
  const configuration = parseCostEnvironment(process.env);
  const receipt = readDeploymentReceipt(
    deploymentReceiptPath(process.env),
    deploymentConfiguration,
    true,
  );
  const evidenceMetadata = costEvidenceMetadata(
    deploymentConfiguration,
    receipt,
    new Date().toISOString(),
  );
  process.stdout.write(`${JSON.stringify(calculateCost(configuration, evidenceMetadata), null, 2)}\n`);
}

function handleFatal(error) {
  const message = error instanceof BoundaryError ? error.message : "cost calculation failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
