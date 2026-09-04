import type {
  RouterAbEd25519YaoExportAdmissionRequestV1,
  RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { TenantRootActiveLineageV1 } from '../tenantRoot/tenantRootCustodyLineage';

export type RouterAbEd25519YaoTenantRootResolutionInputV1 =
  | {
      readonly operation: 'registration';
      readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    }
  | {
      readonly operation: 'recovery';
      readonly admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
    }
  | {
      readonly operation: 'export';
      readonly admissionRequest: RouterAbEd25519YaoExportAdmissionRequestV1;
    };

export type RouterAbEd25519YaoTenantRootResolverV1 = (
  input: RouterAbEd25519YaoTenantRootResolutionInputV1,
) => Promise<TenantRootActiveLineageV1>;

export type RouterAbEd25519YaoRegistrationExecuteAdmissionContextV1 =
  RouterAbEd25519YaoRegistrationAdmissionRequestV1;

export type RouterAbEd25519YaoRecoveryExecuteAdmissionContextV1 =
  RouterAbEd25519YaoRecoveryAdmissionRequestV1;

export type RouterAbEd25519YaoExportExecuteAdmissionContextV1 =
  RouterAbEd25519YaoExportAdmissionRequestV1;
