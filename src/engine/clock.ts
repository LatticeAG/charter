/** §7.2 authoritative time: high-water clamp, regression latch, monotonic check. */
import { msTime } from "../scalars.ts";
import type { Store } from "./store.ts";

const MAX_CLAMP_MS = 1_000;
const MAX_MONOTONIC_SKEW_MS = 5_000;

export class Clock {
  private unsafe = false;
  private wallBase: number;
  private monoBase: number;
  /** Test hook: deterministic time source. */
  inject: (() => number) | null = null;

  private store: Store;
  constructor(store: Store) {
    this.store = store;
    this.wallBase = Date.now();
    this.monoBase = performance.now();
  }

  /** Persisted high-water mark. */
  highWater(): number {
    return this.store.get<{ last_time_ms: number }>("SELECT last_time_ms FROM meta WHERE singleton=1")!.last_time_ms;
  }

  markUnsafe(): void {
    this.unsafe = true;
  }

  isUnsafe(): boolean {
    return this.unsafe;
  }

  /** Raw sample before clamping. */
  private raw(): number {
    return this.inject ? this.inject() : Date.now();
  }

  /**
   * Sample authoritative ms: persist greatest time, clamp regressions ≤1000 ms,
   * latch CLOCK_UNSAFE beyond that. Monotonic cross-check only applies to the
   * live wall clock (not injected test time).
   */
  sample(): number {
    const hw = this.highWater();
    let now = this.raw();
    if (!this.inject) {
      const wallElapsed = now - this.wallBase;
      const monoElapsed = performance.now() - this.monoBase;
      if (Math.abs(wallElapsed - monoElapsed) > MAX_MONOTONIC_SKEW_MS) {
        this.unsafe = true;
      }
    }
    if (now < hw) {
      if (hw - now <= MAX_CLAMP_MS) {
        now = hw;
      } else {
        this.unsafe = true;
        now = hw;
      }
    } else if (now > hw) {
      this.store.run("UPDATE meta SET last_time_ms=? WHERE singleton=1", now);
    }
    return now;
  }

  /** Sampled Time string. */
  now(): string {
    return msTime(this.sample());
  }
}
