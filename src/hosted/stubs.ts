/**
 * Hosted / paid / cloud surfaces — explicit NotImplemented stubs per build
 * contract. These document the production seams; none of them pretend to work.
 */
import { CharterError } from "../errors.ts";

export class NotImplemented extends CharterError {
  readonly reason: string;
  constructor(surface: string, reason: string) {
    super("UNSUPPORTED_COMPOSITION", `${surface}: ${reason}`);
    this.name = "NotImplemented";
    this.reason = reason;
  }
}

/**
 * Cloudflare Worker front-end. The OSS core runs as `serve --local`; the
 * hosted Worker (TLS termination, global rate limiting, DO routing) requires
 * the LatticeAGI hosted control plane.
 */
export function createWorkerFetch(): never {
  throw new NotImplemented(
    "hosted-worker",
    "Cloudflare Worker deployment is a hosted surface; use `charter serve --local` for the OSS gateway.",
  );
}

/**
 * CharterTenantDO production binding. The local engine (src/engine/tenant.ts)
 * is the reference realization of the same §7 contract on node:sqlite.
 */
export function createDurableObjectNamespace(): never {
  throw new NotImplemented(
    "durable-object",
    "Durable Object bindings require the hosted Cloudflare control plane; the local SQLite engine implements the identical semantics.",
  );
}

/** Production RECORDS adapter (real records service client). */
export function createProductionAdapter(): never {
  throw new NotImplemented(
    "production-adapter",
    "The production RECORDS adapter is not part of the OSS core; the fixture adapter (src/adapter/fixture.ts) is the supported local adapter.",
  );
}

/** Hosted registry client (remote policy/pin distribution). */
export function createHostedRegistry(): never {
  throw new NotImplemented(
    "hosted-registry",
    "The hosted registry is a paid surface; local publish/fetch operate on the tenant store directly.",
  );
}

/** Proof service integration — export/import contract only, no live webhook. */
export function createProofClient(): never {
  throw new NotImplemented(
    "proof-service",
    "Proof integration is export/import only in v1; there is no live Proof dependency.",
  );
}
