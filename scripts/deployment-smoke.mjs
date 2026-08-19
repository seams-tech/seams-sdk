/**
 * Shared post-deployment readiness checks for the backend and frontend lanes.
 *
 * A freshly deployed Cloudflare Worker or Pages project is not immediately
 * consistent: the deployment API returns success before every edge serves the
 * new version, so an endpoint can answer 5xx for a short window and then
 * recover with no further action. A single-shot check races that window and
 * reports a healthy deployment as failed.
 *
 * That false negative is expensive in production, where the lane has already
 * applied forward-only migrations and deployed every component by the time
 * smoke runs, and where "rollback" means a revert commit plus a full rebuild.
 * So each check is retried until it passes or the readiness budget expires,
 * and the attempt count is reported so a slow-but-healthy deployment is
 * distinguishable from a broken one.
 */

const READINESS_BUDGET_MS = 180_000;
const RETRY_INTERVAL_MS = 5_000;
const REQUEST_TIMEOUT_MS = 5_000;

/**
 * Run every check concurrently, retrying each until it passes or the readiness
 * budget expires. Returns one result per check, in the order supplied.
 */
export async function runReadinessChecks(checks, options = {}) {
  const budgetMs = options.budgetMs ?? READINESS_BUDGET_MS;
  const intervalMs = options.intervalMs ?? RETRY_INTERVAL_MS;
  return Promise.all(checks.map((check) => runReadinessCheck(check, budgetMs, intervalMs)));
}

export function isFailedCheck(result) {
  return !result.ok;
}

export function formatFailedCheck(result) {
  return result.name;
}

async function runReadinessCheck(check, budgetMs, intervalMs) {
  const deadline = Date.now() + budgetMs;
  let attempts = 0;
  for (;;) {
    attempts += 1;
    const result = await runHttpCheck(check);
    if (result.ok || Date.now() >= deadline) {
      return { ...result, attempts };
    }
    await sleep(intervalMs);
  }
}

async function runHttpCheck(check) {
  try {
    const response = await fetch(check.url, {
      ...check.request,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return {
      name: check.name,
      ok: check.isReady
        ? await check.isReady(response)
        : response.status >= 200 && response.status < 400,
      status: response.status,
    };
  } catch (error) {
    return { name: check.name, ok: false, error: formatError(error) };
  }
}

function sleep(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}
