/** Immutable citations (§1.3): pin + zero-based pointer + clause digest. */
import { CharterError } from "../errors.ts";
import { digest } from "../crypto/digest.ts";
import type { Bundle, Citation, Pin, RuleId } from "../types.ts";
import { ENGINE } from "../types.ts";

export function pinFor(bundle: Bundle): Pin {
  return {
    charter_id: bundle.policy.charter_id,
    version: bundle.policy.version,
    policy_hash: digest("policy", bundle.policy),
    manifest_hash: digest("manifest", bundle.manifest),
    engine: ENGINE,
  };
}

export function cite(bundle: Bundle, rule_id: RuleId): Citation {
  const hd = bundle.policy.hard_denies.findIndex((r) => r.id === rule_id);
  const sr = bundle.policy.scope_rules.findIndex((r) => r.id === rule_id);
  if (hd < 0 && sr < 0) throw new CharterError("NOT_FOUND", `rule ${rule_id} not in policy`);
  const pointer = hd >= 0 ? `/hard_denies/${hd}` : `/scope_rules/${sr}`;
  const rule = hd >= 0 ? bundle.policy.hard_denies[hd]! : bundle.policy.scope_rules[sr]!;
  return {
    schema: "charter.citation/1",
    pin: pinFor(bundle),
    rule_id,
    pointer,
    clause_hash: digest("clause", rule),
    rule,
  };
}
