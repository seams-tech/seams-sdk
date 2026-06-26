import { ensureConsoleAccountD1Schema } from '../../console/account/d1';
import { ensureConsoleApiKeysD1Schema } from '../../console/apiKeys/d1';
import { ensureConsoleApprovalsD1Schema } from '../../console/approvals/d1';
import { ensureConsoleAuditD1Schema } from '../../console/audit/d1';
import { ensureConsoleBillingD1Schema } from '../../console/billing/d1';
import {
  ensureConsoleBillingPrepaidReservationD1Schema,
} from '../../console/billingPrepaidReservations/d1';
import { ensureConsoleBootstrapTokensD1Schema } from '../../console/bootstrapTokens/d1';
import { ensureConsoleOrgProjectEnvD1Schema } from '../../console/orgProjectEnv/d1';
import { ensureConsolePolicyD1Schema } from '../../console/policies/d1';
import { ensureConsoleRuntimeSnapshotsD1Schema } from '../../console/runtimeSnapshots/d1';
import { ensureConsoleSponsoredCallD1Schema } from '../../console/sponsoredCalls/d1';
import { ensureConsoleSponsorshipSpendCapD1Schema } from '../../console/sponsorshipSpendCaps/d1';
import { ensureConsoleTeamRbacD1Schema } from '../../console/teamRbac/d1';
import { ensureConsoleWalletsD1Schema } from '../../console/wallets/d1';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { CfExecutionContext } from './cloudflare.types';
import { ThresholdStoreDurableObject } from './durableObjects/thresholdStore';

export { ThresholdStoreDurableObject };

interface LocalD1DevEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SIGNER_DB: D1DatabaseLike;
  readonly THRESHOLD_STORE: unknown;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
}

type TableCountRow = {
  readonly table_count?: unknown;
};

function jsonResponse(body: Record<string, unknown>, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...(init?.headers || {}),
    },
  });
}

function parseReadyTableCount(row: TableCountRow | null): number {
  const count = Number(row?.table_count);
  if (!Number.isInteger(count) || count < 0) return 0;
  return count;
}

async function assertSignerD1Schema(database: D1DatabaseLike): Promise<void> {
  const row = await database
    .prepare(
      `SELECT COUNT(*) AS table_count
         FROM sqlite_master
        WHERE type = 'table'
          AND name = 'signer_signing_root_secret_shares'`,
    )
    .first<TableCountRow>();
  if (parseReadyTableCount(row) !== 1) {
    throw new Error('local SIGNER_DB migration has not created signer_signing_root_secret_shares');
  }
}

async function ensureLocalD1Schemas(env: LocalD1DevEnv): Promise<void> {
  await ensureConsoleOrgProjectEnvD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleTeamRbacD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleAccountD1Schema({ database: env.CONSOLE_DB });
  await ensureConsolePolicyD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleWalletsD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleApiKeysD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleApprovalsD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleAuditD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleBootstrapTokensD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleBillingD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleBillingPrepaidReservationD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleSponsorshipSpendCapD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleSponsoredCallD1Schema({ database: env.CONSOLE_DB });
  await ensureConsoleRuntimeSnapshotsD1Schema({ database: env.CONSOLE_DB });
  await assertSignerD1Schema(env.SIGNER_DB);
}

async function handleReady(env: LocalD1DevEnv): Promise<Response> {
  await ensureLocalD1Schemas(env);
  return jsonResponse({
    ok: true,
    backend: 'cloudflare_d1_do',
    namespace: env.SEAMS_TENANT_STORAGE_NAMESPACE || 'seams-local',
    bindings: {
      console: 'CONSOLE_DB',
      signer: 'SIGNER_DB',
      thresholdStore: 'THRESHOLD_STORE',
    },
  });
}

async function fetch(
  request: Request,
  env: LocalD1DevEnv,
  _ctx: CfExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') return jsonResponse({ ok: true });
  if (url.pathname === '/readyz') return await handleReady(env);
  return jsonResponse(
    {
      ok: true,
      service: 'seams-sdk-d1-local',
      endpoints: ['/healthz', '/readyz'],
    },
    { status: 200 },
  );
}

export default { fetch };
