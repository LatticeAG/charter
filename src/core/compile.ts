/** Semantic compiler (§1.3, §1.6): manifest contract, tool refs, predicate types. */
import { CharterError } from "../errors.ts";
import { digest } from "../crypto/digest.ts";
import { isInt, isNfc, timeMs, utf8Bytes } from "../scalars.ts";
import type { Compiled, Field, Manifest, Policy, Rule, Tool } from "../types.ts";
import { ENGINE } from "../types.ts";

const DAY_MS = 86_400_000;
const MAX_SPAN_MS = 90 * DAY_MS;

/** The v1 manifest tool contract (§1.3/§3.7) — exact five record tools. */
export const V1_TOOLS: ReadonlyMap<string, { operation: Tool["operation"]; args: Field[] }> = new Map([
  ["record.delete", { operation: "delete", args: [] }],
  ["record.export", { operation: "export", args: [{ name: "destination", kind: "string", max_bytes: 64 }] }],
  ["record.get", { operation: "get", args: [] }],
  ["record.list", { operation: "list", args: [{ name: "limit", kind: "integer", min: 1, max: 100 }] }],
  ["record.put", { operation: "put", args: [{ name: "value", kind: "string", max_bytes: 4096 }] }],
]);

function fieldsEqual(a: Field, b: Field): boolean {
  if (a.kind !== b.kind || a.name !== b.name) return false;
  if (a.kind === "string" && b.kind === "string") return a.max_bytes === b.max_bytes;
  if (a.kind === "integer" && b.kind === "integer") return a.min === b.min && a.max === b.max;
  return true;
}

/** Enforce the exact v1 manifest contract. */
export function checkManifestContract(manifest: Manifest): void {
  const names = manifest.tools.map((t) => t.tool);
  const want = [...V1_TOOLS.keys()].sort();
  if (names.length !== want.length || !want.every((n, i) => n === names[i])) {
    throw new CharterError("SCHEMA", "manifest: v1 requires exactly record.delete/export/get/list/put");
  }
  for (const t of manifest.tools) {
    const spec = V1_TOOLS.get(t.tool)!;
    if (t.binding !== "RECORDS" || t.operation !== spec.operation) {
      throw new CharterError("SCHEMA", `manifest: ${t.tool} operation/binding mismatch`);
    }
    if (t.args.length !== spec.args.length || !spec.args.every((f, i) => fieldsEqual(f, t.args[i]!))) {
      throw new CharterError("SCHEMA", `manifest: ${t.tool} argument contract mismatch`);
    }
  }
}

function checkRule(rule: Rule, manifest: Manifest): void {
  const tools = new Map(manifest.tools.map((t) => [t.tool, t]));
  for (const tn of rule.tools) {
    if (!tools.has(tn)) throw new CharterError("SCHEMA", `rule ${rule.id}: tool ${tn} not installed`);
  }
  for (const pred of rule.when) {
    for (const tn of rule.tools) {
      const tool = tools.get(tn)!;
      const field = tool.args.find((f) => f.name === pred.arg);
      if (!field) {
        throw new CharterError("SCHEMA", `rule ${rule.id}: tool ${tn} does not declare arg ${pred.arg}`);
      }
      if (pred.op === "int_lte") {
        if (field.kind !== "integer") {
          throw new CharterError("SCHEMA", `rule ${rule.id}: int_lte on non-integer ${pred.arg}`);
        }
      } else {
        // eq: value must match the field type and sit inside declared bounds
        if (field.kind === "integer") {
          if (!isInt(pred.value) || pred.value < field.min || pred.value > field.max) {
            throw new CharterError("SCHEMA", `rule ${rule.id}: eq value outside integer bounds`);
          }
        } else if (field.kind === "string") {
          if (typeof pred.value !== "string" || utf8Bytes(pred.value) > field.max_bytes) {
            throw new CharterError("SCHEMA", `rule ${rule.id}: eq value outside string bounds`);
          }
        } else if (typeof pred.value !== "boolean") {
          throw new CharterError("SCHEMA", `rule ${rule.id}: eq value not boolean`);
        }
      }
    }
  }
}

/**
 * compile(policy, manifest) → Compiled. Runs every manifest-dependent semantic
 * check; throws CharterError (SCHEMA / HASH_MISMATCH) on failure.
 */
export function compile(policy: Policy, manifest: Manifest): Compiled {
  const manifest_hash = digest("manifest", manifest);
  if (manifest_hash !== policy.manifest_hash) {
    throw new CharterError("HASH_MISMATCH", "policy.manifest_hash != digest(manifest)");
  }
  checkManifestContract(manifest);
  // Authority key aliases cannot create independence: two names for one
  // public key are forbidden (TV-C-14).
  const pubSeen = new Set<string>();
  for (const k of policy.next_authority.keys) {
    if (pubSeen.has(k.public_key)) {
      throw new CharterError("SCHEMA", "authority: duplicate public_key under distinct key_id");
    }
    pubSeen.add(k.public_key);
  }
  const issued = timeMs(policy.issued_at);
  const nb = timeMs(policy.not_before);
  const na = timeMs(policy.not_after);
  if (!(issued <= nb && nb < na)) {
    throw new CharterError("SCHEMA", "policy: requires issued_at <= not_before < not_after");
  }
  if (na - nb > MAX_SPAN_MS) {
    throw new CharterError("SCHEMA", "policy: validity span exceeds 90 days");
  }
  for (const r of policy.hard_denies) checkRule(r, manifest);
  for (const r of policy.scope_rules) checkRule(r, manifest);
  return { policy_hash: digest("policy", policy), manifest_hash, engine: ENGINE };
}
