/** charter.eval/1 — deterministic 10-step evaluation order (§1.6). */
import { CharterError } from "../errors.ts";
import { digest } from "../crypto/digest.ts";
import { jsonEqual } from "../json/jcs.ts";
import { isInt, timeMs, utf8Bytes } from "../scalars.ts";
import type {
  Decision, EvalInput, Field, Manifest, Predicate, Rule, Scalar, Selector, Tool,
} from "../types.ts";
import { ENGINE } from "../types.ts";

const DEADLINE_MAX_AHEAD_MS = 30_000;

function selectorMatches(sel: Selector, resource: string): boolean {
  switch (sel.match) {
    case "all": return true;
    case "exact": return resource === sel.value;
    case "segment_prefix":
      return resource === sel.value || resource.startsWith(sel.value + "/");
  }
}

function predicateMatches(pred: Predicate, args: Record<string, Scalar>): boolean {
  const v = args[pred.arg];
  if (pred.op === "eq") {
    // scalar type-and-value equality; no coercion
    return v !== undefined && typeof v === typeof pred.value && v === pred.value;
  }
  return isInt(v) && v <= pred.value;
}

function ruleMatches(rule: Rule, input: EvalInput): boolean {
  const { request, principal } = input;
  const principalOk =
    rule.principals.length === 1 && rule.principals[0] === "*"
      ? true
      : (rule.principals as string[]).includes(principal.principal_id);
  if (!principalOk) return false;
  if (!rule.tools.includes(request.tool)) return false;
  const scopeOk =
    rule.scopes.length === 1 && rule.scopes[0] === "*"
      ? true
      : (rule.scopes as string[]).includes(request.scope);
  if (!scopeOk) return false;
  if (!rule.resources.some((s) => selectorMatches(s, request.resource))) return false;
  return rule.when.every((p) => predicateMatches(p, request.args));
}

/** Exactness of request args against the tool's declared fields (§1.3/§3.7). */
export function checkArgs(tool: Tool, args: Record<string, Scalar>): void {
  const declared = tool.args;
  const names = Object.keys(args);
  if (names.length !== declared.length) {
    throw new CharterError("SCHEMA", "args must be exactly the declared fields");
  }
  for (const f of declared) {
    if (!(f.name in args)) throw new CharterError("SCHEMA", `missing arg ${f.name}`);
    const v = args[f.name]!;
    if (f.kind === "string") {
      if (typeof v !== "string" || utf8Bytes(v) > f.max_bytes) {
        throw new CharterError("SCHEMA", `arg ${f.name} violates string bounds`);
      }
    } else if (f.kind === "integer") {
      if (!isInt(v) || v < f.min || v > f.max) {
        throw new CharterError("SCHEMA", `arg ${f.name} violates integer bounds`);
      }
    } else if (typeof v !== "boolean") {
      throw new CharterError("SCHEMA", `arg ${f.name} not boolean`);
    }
  }
}

export function installedTool(manifest: Manifest, name: string): Tool | undefined {
  return manifest.tools.find((t) => t.tool === name);
}

/**
 * Pure evaluation. Argument-shape failures for known tools throw SCHEMA before
 * decision evaluation; unknown tools reach UNKNOWN_TOOL inside the order.
 */
export function evaluate(input: EvalInput): Decision {
  const { policy, manifest, active_pin, request, principal, now } = input;

  // Pre-step: known-tool argument schema (before decision evaluation).
  const tool = installedTool(manifest, request.tool);
  if (tool) checkArgs(tool, request.args);

  const deny = (reason: Decision["reason"], rule_ids: string[] = []): Decision =>
    ({ verdict: "DENY", reason, rule_ids: rule_ids as Decision["rule_ids"] });

  // 1. request pin == active pin in every field
  if (!jsonEqual(request.pin, active_pin)) return deny("PIN_MISMATCH");

  // 2. recompute policy/manifest identities == pin, installed engine
  const policyHash = digest("policy", policy);
  const manifestHash = digest("manifest", manifest);
  if (
    policyHash !== active_pin.policy_hash ||
    manifestHash !== active_pin.manifest_hash ||
    policy.charter_id !== active_pin.charter_id ||
    policy.version !== active_pin.version ||
    policy.engine !== ENGINE || manifest.engine !== ENGINE ||
    active_pin.engine !== ENGINE
  ) {
    return deny("MANIFEST_MISMATCH");
  }

  // 3. revocation dimensions
  if (input.policy_revoked) return deny("POLICY_REVOKED");
  if (!input.policy_signatures_valid) return deny("POLICY_KEY_REVOKED");

  // 4. policy validity window (half-open)
  const nowMs = timeMs(now);
  if (nowMs < timeMs(policy.not_before)) return deny("POLICY_NOT_YET_VALID");
  if (nowMs >= timeMs(policy.not_after)) return deny("POLICY_EXPIRED");

  // 5. request deadline
  const deadlineMs = timeMs(request.deadline);
  if (nowMs >= deadlineMs || deadlineMs - nowMs > DEADLINE_MAX_AHEAD_MS) {
    return deny("DEADLINE");
  }

  // 6. scope membership in authenticated principal scopes
  if (!principal.scopes.includes(request.scope)) return deny("PRINCIPAL_SCOPE");

  // 7. installed tool
  if (!tool) return deny("UNKNOWN_TOOL");

  // 8. all hard denies
  const denies = policy.hard_denies.filter((r) => ruleMatches(r, input)).map((r) => r.id);
  if (denies.length > 0) return deny("HARD_DENY", denies.sort());

  // 9. all scope rules
  const allows = policy.scope_rules.filter((r) => ruleMatches(r, input)).map((r) => r.id);
  if (allows.length > 0) {
    return { verdict: "ALLOW", reason: "ALLOW_SCOPE", rule_ids: allows.sort() };
  }

  // 10. default deny — no fabricated rule (default-deny/1 invariant)
  return deny("NO_SCOPE");
}
