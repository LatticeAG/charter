/**
 * §11.1 fixture RECORDS adapter — deterministic in-memory records used by the
 * local engine and the conformance corpus. Implements the five RECORDS
 * operations; default fixture behavior is {status:"ok", output:{value:"ok"}}.
 */
import type { AdapterRequest, AdapterResponse, Json } from "../types.ts";

export interface FixtureAdapter {
  run(req: AdapterRequest): Promise<AdapterResponse>;
  /** Test introspection. */
  initiated: AdapterRequest[];
}

/** In-memory record store — the honest local RECORDS semantics. */
export class RecordsAdapter implements FixtureAdapter {
  initiated: AdapterRequest[] = [];
  private records = new Map<string, Json>();

  async run(req: AdapterRequest): Promise<AdapterResponse> {
    this.initiated.push(req);
    switch (req.operation) {
      case "get": {
        const v = this.records.get(req.resource);
        return v === undefined
          ? { status: "error", output: { error: "not_found" } }
          : { status: "ok", output: { value: v } };
      }
      case "put": {
        this.records.set(req.resource, (req.args.value as Json) ?? null);
        return { status: "ok", output: { value: "ok" } };
      }
      case "delete": {
        this.records.delete(req.resource);
        return { status: "ok", output: { value: "ok" } };
      }
      case "list": {
        const keys = [...this.records.keys()].filter((k) => k.startsWith(req.resource)).sort();
        return { status: "ok", output: { value: keys } };
      }
      case "export": {
        return { status: "ok", output: { value: [...this.records.keys()].sort().length } };
      }
    }
  }
}

/** §11.1 scripted fixture adapter: static or test-programmed responses. */
export class FixtureRecordsAdapter implements FixtureAdapter {
  initiated: AdapterRequest[] = [];
  private programmed: ((req: AdapterRequest) => AdapterResponse | Promise<AdapterResponse>) | null = null;

  /** Script the next response (or a deferred promise for blocked-adapter tests). */
  program(fn: (req: AdapterRequest) => AdapterResponse | Promise<AdapterResponse>): void {
    this.programmed = fn;
  }

  async run(req: AdapterRequest): Promise<AdapterResponse> {
    this.initiated.push(req);
    if (this.programmed) {
      const fn = this.programmed;
      this.programmed = null;
      return fn(req);
    }
    // §11.1 default fixture response.
    return { status: "ok", output: { value: "ok" } };
  }
}
