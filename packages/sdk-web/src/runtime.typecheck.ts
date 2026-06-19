import { createSigningRuntime, createSigningRuntimeStatePorts } from './runtime';
import type {
  SigningRuntime,
  SigningRuntimeConfig,
  SigningRuntimeDeps,
  SigningRuntimeEcdsaStatePorts,
  SigningRuntimeUiDeps,
  SigningRuntimeWarmSessionUiPorts,
  SigningRuntimeStatePorts,
} from './runtime';

declare const runtime: SigningRuntime;
declare const deps: SigningRuntimeDeps;
declare const config: SigningRuntimeConfig;
declare const ecdsaStatePorts: SigningRuntimeEcdsaStatePorts;
declare const uiDeps: SigningRuntimeUiDeps;
declare const warmSessionUiPorts: SigningRuntimeWarmSessionUiPorts;

const runtimeDeps: SigningRuntimeDeps = runtime;
const runtimeConfig: SigningRuntimeConfig = runtime.config;
const runtimeUiDeps: SigningRuntimeUiDeps = runtime.ui;
const runtimeStatePorts: SigningRuntimeStatePorts = createSigningRuntimeStatePorts();
const runtimeEcdsaStatePorts: SigningRuntimeEcdsaStatePorts = runtimeStatePorts.ecdsaSessions;
const createdRuntime: SigningRuntime = createSigningRuntime(deps);

const depsConfig: SigningRuntimeConfig = deps.config;
const explicitStatePorts: SigningRuntimeStatePorts = {
  ecdsaSessions: ecdsaStatePorts,
};
const explicitUiDeps: SigningRuntimeUiDeps = {
  warmSessions: warmSessionUiPorts,
};

void runtimeDeps;
void runtimeConfig;
void runtimeUiDeps;
void runtimeEcdsaStatePorts;
void createdRuntime;
void depsConfig;
void explicitStatePorts;
void explicitUiDeps;
void config;
void uiDeps;
