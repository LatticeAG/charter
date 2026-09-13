/** Config + secret-reference loading. Secrets resolve only via env:NAME refs. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { CharterError } from "./errors.ts";
import { parseJsonText } from "./json/strict.ts";
import { parseYamlSubset } from "./yaml/subset.ts";
import { vAuthFile, vConfig, vEncryptionKeys, vManifest, vRootFile } from "./schema/validate.ts";
import type { AuthFile, Config, EncryptionKeys, Manifest, RootFile } from "./types.ts";

/** Resolve a `env:NAME` secret reference to bytes (never logged). */
export function secretRef(ref: string): Uint8Array {
  if (!ref.startsWith("env:")) throw new CharterError("SCHEMA", "secret ref must be env:NAME");
  const name = ref.slice(4);
  const v = process.env[name];
  if (v === undefined) throw new CharterError("SCHEMA", `secret ref ${name} unset`);
  return new TextEncoder().encode(v);
}

function jsonFromSecret(ref: string): unknown {
  const raw = new TextDecoder().decode(secretRef(ref));
  try {
    return parseJsonText(raw);
  } catch {
    // tolerate base64url-wrapped JSON in env storage
    try {
      return parseJsonText(Buffer.from(raw, "base64url").toString("utf8"));
    } catch {
      throw new CharterError("SCHEMA", "secret ref does not decode to JSON");
    }
  }
}

export function loadConfig(path: string): Config {
  const text = readFileSync(path, "utf8");
  let v: unknown;
  if (/\.(json)$/i.test(path) || text.trimStart().startsWith("{")) {
    v = parseJsonText(text);
  } else {
    v = parseYamlSubset(text);
  }
  return vConfig(v, "$.config");
}

export interface LoadedTenant {
  config: Config;
  root: RootFile;
  manifest: Manifest;
  auth: AuthFile;
  encryptionKeys: EncryptionKeys;
  auditSeed: Uint8Array;
  /** Raw bearer token for the local CLI client. */
  clientToken: string;
}

export function loadTenant(configPath: string): LoadedTenant {
  const config = loadConfig(configPath);
  const dir = dirname(resolve(configPath));
  const root = vRootFile(parseJsonText(readFileSync(resolve(dir, config.root_file), "utf8")), "$.root");
  const manifest = vManifest(parseJsonText(readFileSync(resolve(dir, config.manifest_file), "utf8")), "$.manifest");
  const auth = vAuthFile(jsonFromSecret(config.auth_records_ref), "$.auth");
  const encryptionKeys = vEncryptionKeys(jsonFromSecret(config.response_keys_ref), "$.keys");
  const auditSeedRaw = secretRef(config.audit_seed_ref);
  const auditSeed = Buffer.from(new TextDecoder().decode(auditSeedRaw), "base64url");
  if (auditSeed.length !== 32 || auditSeed.toString("base64url") !== new TextDecoder().decode(auditSeedRaw)) {
    throw new CharterError("SCHEMA", "audit seed must be canonical base64url of 32 bytes");
  }
  if (config.environment === "production") rejectFixtureMaterial(root, manifest, auditSeed);
  const clientToken = new TextDecoder().decode(secretRef(config.client_credential_ref));
  return { config, root, manifest, auth, encryptionKeys, auditSeed: new Uint8Array(auditSeed), clientToken };
}

/**
 * §5.2/§11.1: production MUST reject the public fixture key set, fixture
 * adapter build digest, and fixture seeds. These are public RFC 8032 test
 * vectors — rejection names the material class, never secret bytes.
 */
const FIXTURE_PUBS = new Set([
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
]);
const FIXTURE_SEEDS = new Set([
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
]);

function rejectFixtureMaterial(root: RootFile, manifest: Manifest, auditSeed: Uint8Array): void {
  const pubs = [
    ...root.bootstrap.keys.map((k) => k.public_key),
    ...root.audit_keys.map((k) => k.public_key),
  ];
  if (pubs.some((p) => FIXTURE_PUBS.has(p))) {
    throw new CharterError("SCHEMA", "production config uses RFC 8032 fixture key material");
  }
  const adapterHash = createHash("sha256").update("charter-fixture-records/1").digest("hex");
  if (manifest.adapter_build_hash === adapterHash) {
    throw new CharterError("SCHEMA", "production config pins the fixture adapter build");
  }
  if (FIXTURE_SEEDS.has(Buffer.from(auditSeed).toString("hex"))) {
    throw new CharterError("SCHEMA", "production config uses a fixture audit seed");
  }
}
