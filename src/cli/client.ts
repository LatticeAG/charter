/** CLI transport over `charter.http/1` — one-to-one route wrapper only. */
import { CharterError } from "../errors.ts";
import { canonicalize } from "../json/jcs.ts";
import type { Json } from "../types.ts";
import type { StoredResponse } from "../engine/tenant.ts";

export interface Client {
  call(method: string, path: string, body: Json | null, query?: Record<string, string>): Promise<StoredResponse>;
}

/** HTTP client over `charter.http/1`. */
export class HttpClient implements Client {
  private base: string;
  private token: string;
  private timeoutMs: number;
  constructor(base: string, token: string, timeoutMs: number) {
    this.base = base; this.token = token; this.timeoutMs = timeoutMs;
  }

  async call(method: string, path: string, body: Json | null, query: Record<string, string> = {}): Promise<StoredResponse> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          authorization: `Bearer ${this.token}`,
          ...(body !== null ? { "content-type": "application/json" } : {}),
        },
        ...(body !== null ? { body: canonicalize(body) } : {}),
        signal: ctrl.signal,
      });
      const text = await res.text();
      let parsed: Json;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new CharterError("PARSE", "non-JSON response");
      }
      return { status: res.status, body: parsed };
    } catch (e) {
      if (e instanceof CharterError) throw e;
      if (e instanceof Error && e.name === "AbortError") {
        throw new CharterError("AUDIT_UNAVAILABLE", "request timeout");
      }
      throw new CharterError("AUDIT_UNAVAILABLE", "endpoint unreachable");
    } finally {
      clearTimeout(t);
    }
  }
}
