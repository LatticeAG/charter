/** §6.1 durable layout — one transactional SQLite store per tenant. */
import { DatabaseSync } from "node:sqlite";
import { CharterError } from "../errors.ts";
import type { Json } from "../types.ts";

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), storage_version INTEGER NOT NULL CHECK(storage_version=1), deployment_jcs BLOB NOT NULL, head_version INTEGER NOT NULL, next_seq INTEGER NOT NULL, head_hash TEXT NOT NULL, last_time_ms INTEGER NOT NULL, root_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policies (version INTEGER PRIMARY KEY, policy_hash TEXT NOT NULL UNIQUE, previous_hash TEXT, bundle_jcs BLOB NOT NULL, published_seq INTEGER NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS controls (audit_seq INTEGER PRIMARY KEY, control_hash TEXT NOT NULL UNIQUE, artifact_jcs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS revocations (epoch INTEGER PRIMARY KEY, target_kind TEXT NOT NULL CHECK(target_kind IN ('policy','credential','policy_key')), target_id TEXT NOT NULL, record_jcs BLOB NOT NULL, effective_seq INTEGER NOT NULL UNIQUE, UNIQUE(target_kind,target_id));
CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, operation TEXT NOT NULL, body_hash TEXT NOT NULL, response_enc BLOB, response_until_ms INTEGER NOT NULL, result_jcs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS calls (request_id TEXT PRIMARY KEY REFERENCES requests(request_id), owner_id TEXT NOT NULL, input_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('DENIED','COMMITTED','SUCCEEDED','FAILED','INDETERMINATE','NOT_SENT')), decision_jcs BLOB NOT NULL, deadline_ms INTEGER NOT NULL, output_enc BLOB, output_hash TEXT, audit_seqs_jcs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body_jcs BLOB NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS disputes (dispute_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, receipt_seq INTEGER NOT NULL UNIQUE, record_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS instances (instance_id TEXT PRIMARY KEY, counter INTEGER NOT NULL, received_ms INTEGER, observation_jcs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (through_seq INTEGER PRIMARY KEY, checkpoint_jcs BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS encryption_state (key_id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, writes INTEGER NOT NULL CHECK(writes BETWEEN 0 AND 16777216));
CREATE TABLE IF NOT EXISTS encryption_nonces (key_id TEXT NOT NULL REFERENCES encryption_state(key_id), nonce BLOB NOT NULL CHECK(length(nonce)=12), PRIMARY KEY(key_id,nonce));
CREATE INDEX IF NOT EXISTS requests_owner ON requests(owner_id,request_id);
CREATE INDEX IF NOT EXISTS requests_expiry ON requests(response_until_ms);
CREATE INDEX IF NOT EXISTS calls_pending ON calls(state,deadline_ms);
CREATE INDEX IF NOT EXISTS calls_owner ON calls(owner_id,request_id);
CREATE INDEX IF NOT EXISTS disputes_owner_seq ON disputes(owner_id,receipt_seq);
CREATE INDEX IF NOT EXISTS audit_actor_seq ON audit(json_extract(CAST(body_jcs AS TEXT),'$.actor_id'),seq);
`;

export class Store {
  readonly db: DatabaseSync;
  constructor(path: string, opts: { readonly?: boolean } = {}) {
    this.db = new DatabaseSync(path, { readOnly: opts.readonly ?? false });
    this.db.exec("PRAGMA foreign_keys = ON");
    if (!opts.readonly) {
      this.db.exec("PRAGMA journal_mode = WAL");
      this.db.exec(SCHEMA_SQL);
    }
  }

  close(): void {
    this.db.close();
  }

  /** Run fn inside IMMEDIATE transaction; roll back fully on error. */
  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const v = fn();
      this.db.exec("COMMIT");
      return v;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // already rolled back
      }
      throw e;
    }
  }

  get<T extends object>(sql: string, ...params: (string | number | Uint8Array | null)[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }

  all<T extends object>(sql: string, ...params: (string | number | Uint8Array | null)[]): T[] {
    return this.db.prepare(sql).all(...params) as T[];
  }

  run(sql: string, ...params: (string | number | Uint8Array | null)[]): void {
    this.db.prepare(sql).run(...params);
  }

  /** Approximate durable bytes for capacity accounting (§6.2). */
  usedBytes(): number {
    const pc = this.get<{ v: number }>("SELECT page_count AS v FROM pragma_page_count")!.v;
    const ps = this.get<{ v: number }>("SELECT page_size AS v FROM pragma_page_size")!.v;
    return pc * ps;
  }
}

/** Kill switch for fault-injection tests. */
export class InjectedFault extends Error {
  constructor(what: string) {
    super(what);
    this.name = "InjectedFault";
  }
}
