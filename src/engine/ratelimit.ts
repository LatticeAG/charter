/** §3.1 token buckets — DO-time driven. */
import { CharterError } from "../errors.ts";

class Bucket {
  private tokens: number;
  private last: number;
  private ratePerSec: number;
  private burst: number;
  constructor(ratePerSec: number, burst: number, now: number) {
    this.ratePerSec = ratePerSec;
    this.burst = burst;
    this.tokens = burst;
    this.last = now;
  }
  take(now: number): boolean {
    const elapsed = Math.max(0, now - this.last);
    this.tokens = Math.min(this.burst, this.tokens + (elapsed * this.ratePerSec) / 1000);
    this.last = now;
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

export class RateLimiter {
  private tenantMut = new Map<string, Bucket>();
  private principal = new Map<string, Bucket>();
  private operatorCtl = new Map<string, Bucket>();
  private reads = new Map<string, Bucket>();
  private validate = new Map<string, Bucket>();

  private take(map: Map<string, Bucket>, key: string, rate: number, burst: number, now: number): boolean {
    let b = map.get(key);
    if (!b) {
      b = new Bucket(rate, burst, now);
      map.set(key, b);
    }
    return b.take(now);
  }

  /** Ordinary first-time mutations: tenant 50/s burst 100 + principal 10/s burst 20. */
  mutation(tenant: string, principal: string, now: number): void {
    if (!this.take(this.tenantMut, tenant, 50, 100, now) ||
        !this.take(this.principal, principal, 10, 20, now)) {
      throw new CharterError("BUSY", "rate limit");
    }
  }

  /** Pause/revoke restrictive ops: separate operator bucket 10/s burst 20. */
  operatorControl(operator: string, now: number): void {
    if (!this.take(this.operatorCtl, operator, 10, 20, now)) throw new CharterError("BUSY", "rate limit");
  }

  read(tenant: string, now: number): void {
    if (!this.take(this.reads, tenant, 100, 200, now)) throw new CharterError("BUSY", "rate limit");
  }

  validation(tenant: string, now: number): void {
    if (!this.take(this.validate, tenant, 5, 10, now)) throw new CharterError("BUSY", "rate limit");
  }
}
