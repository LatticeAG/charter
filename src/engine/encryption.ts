/** §6.1 AES-256-GCM envelope encryption with nonce/key persistence. */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { CharterError } from "../errors.ts";
import { canonicalize } from "../json/jcs.ts";
import { sha256Hex } from "../crypto/digest.ts";
import type { EncryptionKeys } from "../types.ts";
import type { Store } from "./store.ts";

const MAX_WRITES = 16_777_216; // 2^24

export class Encrypter {
  private keys: Map<string, Uint8Array>;
  private active: string;
  private store: Store;
  private tenantId: string;

  constructor(store: Store, tenantId: string, keysFile: EncryptionKeys) {
    this.store = store;
    this.tenantId = tenantId;
    this.keys = new Map(keysFile.keys.map((k) => [k.key_id, Buffer.from(k.key_base64url, "base64url")]));
    this.active = keysFile.active_key_id;
    // Ensure key state rows exist (permanent key-ID binding).
    for (const [id, raw] of this.keys) {
      const kh = sha256Hex(raw);
      const row = this.store.get<{ key_hash: string }>("SELECT key_hash FROM encryption_state WHERE key_id=?", id);
      if (row && row.key_hash !== kh) {
        throw new CharterError("SCHEMA", `encryption key ${id} rebound to different bytes`);
      }
      if (!row) {
        this.store.run("INSERT INTO encryption_state(key_id,key_hash,writes) VALUES(?,?,0)", id, kh);
      }
    }
  }

  private aad(table: string, primaryKey: string, column: string): Buffer {
    return Buffer.from(
      canonicalize({ tenant_id: this.tenantId, table, primary_key: primaryKey, column }),
      "utf8",
    );
  }

  /** Encrypt UTF-8 text → envelope JSON text. Caller must be inside tx. */
  encrypt(table: string, primaryKey: string, column: string, plaintext: string): string {
    const st = this.store.get<{ writes: number }>("SELECT writes FROM encryption_state WHERE key_id=?", this.active);
    if (!st) throw new CharterError("AUDIT_UNAVAILABLE", "no active encryption key");
    if (st.writes >= MAX_WRITES) {
      throw new CharterError("AUDIT_UNAVAILABLE", "encryption write cap reached; rotate key");
    }
    const key = this.keys.get(this.active)!;
    for (let attempt = 0; attempt < 4; attempt++) {
      const nonce = randomBytes(12);
      const hit = this.store.get<{ key_id: string }>(
        "SELECT key_id FROM encryption_nonces WHERE key_id=? AND nonce=?", this.active, nonce,
      );
      if (hit) continue; // fresh randomness on collision; never overwrite a pair
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(this.aad(table, primaryKey, column));
      const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
      this.store.run("INSERT INTO encryption_nonces(key_id,nonce) VALUES(?,?)", this.active, nonce);
      this.store.run("UPDATE encryption_state SET writes=writes+1 WHERE key_id=?", this.active);
      return canonicalize({
        version: 1,
        key_id: this.active,
        nonce_base64url: nonce.toString("base64url"),
        ciphertext_base64url: ct.toString("base64url"),
      });
    }
    throw new CharterError("AUDIT_UNAVAILABLE", "nonce generation failed");
  }

  /** Decrypt an envelope produced by encrypt(); throws AUDIT_UNAVAILABLE on bad key/auth. */
  decrypt(table: string, primaryKey: string, column: string, envelopeText: string): string {
    let env: { key_id: string; nonce_base64url: string; ciphertext_base64url: string };
    try {
      env = JSON.parse(envelopeText);
    } catch {
      throw new CharterError("AUDIT_UNAVAILABLE", "corrupt envelope");
    }
    const key = this.keys.get(env.key_id);
    if (!key) throw new CharterError("AUDIT_UNAVAILABLE", `encryption key ${env.key_id} unavailable`);
    try {
      const nonce = Buffer.from(env.nonce_base64url, "base64url");
      const ct = Buffer.from(env.ciphertext_base64url, "base64url");
      const tag = ct.subarray(ct.length - 16);
      const body = ct.subarray(0, ct.length - 16);
      const dec = createDecipheriv("aes-256-gcm", key, nonce);
      dec.setAAD(this.aad(table, primaryKey, column));
      dec.setAuthTag(tag);
      return Buffer.concat([dec.update(body), dec.final()]).toString("utf8");
    } catch {
      throw new CharterError("AUDIT_UNAVAILABLE", "envelope authentication failed");
    }
  }
}
