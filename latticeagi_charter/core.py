"""Core logic: compiler (§1.3/§1.6), charter.eval/1 10-step evaluator,
citations, diff, bundle verification, and the §9 offline evidence verifier."""
import base64

from .errors import CharterError
from .digest import digest, sign_message, sha256_hex
from .ed25519 import verify_bytes
from .jcs import canonicalize, json_equal
from .scalars import is_int, time_ms, utf8_bytes
from .schema import (
    ENGINE, v_audit_entry, v_bundle, v_checkpoint, v_control_artifact,
    v_root_file,
)

DAY_MS = 86_400_000
MAX_SPAN_MS = 90 * DAY_MS
DEADLINE_MAX_AHEAD_MS = 30_000
ZERO_HASH = "0" * 64

# The v1 manifest tool contract (§1.3/§3.7) — exact five record tools.
V1_TOOLS = {
    "record.delete": ("delete", []),
    "record.export": ("export", [{"name": "destination", "kind": "string", "max_bytes": 64}]),
    "record.get": ("get", []),
    "record.list": ("list", [{"name": "limit", "kind": "integer", "min": 1, "max": 100}]),
    "record.put": ("put", [{"name": "value", "kind": "string", "max_bytes": 4096}]),
}


def _fields_equal(a, b):
    if a["kind"] != b["kind"] or a["name"] != b["name"]:
        return False
    if a["kind"] == "string":
        return a["max_bytes"] == b["max_bytes"]
    if a["kind"] == "integer":
        return a["min"] == b["min"] and a["max"] == b["max"]
    return True


def check_manifest_contract(manifest):
    names = [t["tool"] for t in manifest["tools"]]
    want = sorted(V1_TOOLS.keys())
    if names != want:
        raise CharterError("SCHEMA", "manifest: v1 requires exactly record.delete/export/get/list/put")
    for t in manifest["tools"]:
        operation, spec_args = V1_TOOLS[t["tool"]]
        if t["binding"] != "RECORDS" or t["operation"] != operation:
            raise CharterError("SCHEMA", f"manifest: {t['tool']} operation/binding mismatch")
        if len(t["args"]) != len(spec_args) or not all(
                _fields_equal(f, a) for f, a in zip(spec_args, t["args"])):
            raise CharterError("SCHEMA", f"manifest: {t['tool']} argument contract mismatch")


def _check_rule(rule, manifest):
    tools = {t["tool"]: t for t in manifest["tools"]}
    for tn in rule["tools"]:
        if tn not in tools:
            raise CharterError("SCHEMA", f"rule {rule['id']}: tool {tn} not installed")
    for pred in rule["when"]:
        for tn in rule["tools"]:
            tool = tools[tn]
            field = next((f for f in tool["args"] if f["name"] == pred["arg"]), None)
            if field is None:
                raise CharterError("SCHEMA",
                                   f"rule {rule['id']}: tool {tn} does not declare arg {pred['arg']}")
            if pred["op"] == "int_lte":
                if field["kind"] != "integer":
                    raise CharterError("SCHEMA",
                                       f"rule {rule['id']}: int_lte on non-integer {pred['arg']}")
            elif field["kind"] == "integer":
                v = pred["value"]
                if not is_int(v) or v < field["min"] or v > field["max"]:
                    raise CharterError("SCHEMA",
                                       f"rule {rule['id']}: eq value outside integer bounds")
            elif field["kind"] == "string":
                v = pred["value"]
                if not isinstance(v, str) or utf8_bytes(v) > field["max_bytes"]:
                    raise CharterError("SCHEMA",
                                       f"rule {rule['id']}: eq value outside string bounds")
            elif not isinstance(pred["value"], bool):
                raise CharterError("SCHEMA", f"rule {rule['id']}: eq value not boolean")


def compile(policy, manifest):  # noqa: A001 — spec name
    """compile(policy, manifest) → Compiled. Every manifest-dependent semantic
    check; raises CharterError (SCHEMA / HASH_MISMATCH) on failure."""
    manifest_hash = digest("manifest", manifest)
    if manifest_hash != policy["manifest_hash"]:
        raise CharterError("HASH_MISMATCH", "policy.manifest_hash != digest(manifest)")
    check_manifest_contract(manifest)
    pub_seen = set()
    for k in policy["next_authority"]["keys"]:
        if k["public_key"] in pub_seen:
            raise CharterError("SCHEMA", "authority: duplicate public_key under distinct key_id")
        pub_seen.add(k["public_key"])
    issued = time_ms(policy["issued_at"])
    nb = time_ms(policy["not_before"])
    na = time_ms(policy["not_after"])
    if not (issued <= nb < na):
        raise CharterError("SCHEMA", "policy: requires issued_at <= not_before < not_after")
    if na - nb > MAX_SPAN_MS:
        raise CharterError("SCHEMA", "policy: validity span exceeds 90 days")
    for r in policy["hard_denies"]:
        _check_rule(r, manifest)
    for r in policy["scope_rules"]:
        _check_rule(r, manifest)
    return {"policy_hash": digest("policy", policy), "manifest_hash": manifest_hash,
            "engine": ENGINE}


# ---------- evaluator (charter.eval/1, §1.6) ----------

def _selector_matches(sel, resource):
    m = sel["match"]
    if m == "all":
        return True
    if m == "exact":
        return resource == sel["value"]
    return resource == sel["value"] or resource.startswith(sel["value"] + "/")


def _predicate_matches(pred, args):
    v = args.get(pred["arg"])
    if pred["op"] == "eq":
        pv = pred["value"]
        if isinstance(v, bool) or isinstance(pv, bool):
            return v is pv if isinstance(v, bool) and isinstance(pv, bool) else False
        return v is not None and type(v) is type(pv) and v == pv
    return is_int(v) and v <= pred["value"]


def _rule_matches(rule, input_):
    request, principal = input_["request"], input_["principal"]
    if not (len(rule["principals"]) == 1 and rule["principals"][0] == "*"):
        if principal["principal_id"] not in rule["principals"]:
            return False
    if request["tool"] not in rule["tools"]:
        return False
    if not (len(rule["scopes"]) == 1 and rule["scopes"][0] == "*"):
        if request["scope"] not in rule["scopes"]:
            return False
    if not any(_selector_matches(s, request["resource"]) for s in rule["resources"]):
        return False
    return all(_predicate_matches(p, request["args"]) for p in rule["when"])


def check_args(tool, args):
    declared = tool["args"]
    if len(args) != len(declared):
        raise CharterError("SCHEMA", "args must be exactly the declared fields")
    for f in declared:
        if f["name"] not in args:
            raise CharterError("SCHEMA", f"missing arg {f['name']}")
        v = args[f["name"]]
        if f["kind"] == "string":
            if not isinstance(v, str) or utf8_bytes(v) > f["max_bytes"]:
                raise CharterError("SCHEMA", f"arg {f['name']} violates string bounds")
        elif f["kind"] == "integer":
            if not is_int(v) or v < f["min"] or v > f["max"]:
                raise CharterError("SCHEMA", f"arg {f['name']} violates integer bounds")
        elif not isinstance(v, bool):
            raise CharterError("SCHEMA", f"arg {f['name']} not boolean")


def installed_tool(manifest, name):
    return next((t for t in manifest["tools"] if t["tool"] == name), None)


def evaluate(input_):
    """Pure evaluation, 10-step order (§1.6). Argument-shape failures for known
    tools raise SCHEMA before decision evaluation; unknown tools reach
    UNKNOWN_TOOL inside the order."""
    policy = input_["policy"]
    manifest = input_["manifest"]
    active_pin = input_["active_pin"]
    request = input_["request"]
    principal = input_["principal"]
    now = input_["now"]

    tool = installed_tool(manifest, request["tool"])
    if tool:
        check_args(tool, request["args"])

    def deny(reason, rule_ids=None):
        return {"verdict": "DENY", "reason": reason, "rule_ids": rule_ids or []}

    # 1. request pin == active pin in every field
    if not json_equal(request["pin"], active_pin):
        return deny("PIN_MISMATCH")
    # 2. recompute policy/manifest identities == pin, installed engine
    if (digest("policy", policy) != active_pin["policy_hash"]
            or digest("manifest", manifest) != active_pin["manifest_hash"]
            or policy["charter_id"] != active_pin["charter_id"]
            or policy["version"] != active_pin["version"]
            or policy["engine"] != ENGINE or manifest["engine"] != ENGINE
            or active_pin["engine"] != ENGINE):
        return deny("MANIFEST_MISMATCH")
    # 3. revocation dimensions
    if input_["policy_revoked"]:
        return deny("POLICY_REVOKED")
    if not input_["policy_signatures_valid"]:
        return deny("POLICY_KEY_REVOKED")
    # 4. policy validity window (half-open)
    now_ms = time_ms(now)
    if now_ms < time_ms(policy["not_before"]):
        return deny("POLICY_NOT_YET_VALID")
    if now_ms >= time_ms(policy["not_after"]):
        return deny("POLICY_EXPIRED")
    # 5. request deadline
    deadline_ms = time_ms(request["deadline"])
    if now_ms >= deadline_ms or deadline_ms - now_ms > DEADLINE_MAX_AHEAD_MS:
        return deny("DEADLINE")
    # 6. scope membership
    if request["scope"] not in principal["scopes"]:
        return deny("PRINCIPAL_SCOPE")
    # 7. installed tool
    if not tool:
        return deny("UNKNOWN_TOOL")
    # 8. all hard denies
    denies = sorted(r["id"] for r in policy["hard_denies"] if _rule_matches(r, input_))
    if denies:
        return deny("HARD_DENY", denies)
    # 9. all scope rules
    allows = sorted(r["id"] for r in policy["scope_rules"] if _rule_matches(r, input_))
    if allows:
        return {"verdict": "ALLOW", "reason": "ALLOW_SCOPE", "rule_ids": allows}
    # 10. default deny — no fabricated rule (default-deny/1 invariant)
    return deny("NO_SCOPE")


# ---------- citation / diff (§1.3, §3.7) ----------

def pin_for(bundle):
    return {
        "charter_id": bundle["policy"]["charter_id"],
        "version": bundle["policy"]["version"],
        "policy_hash": digest("policy", bundle["policy"]),
        "manifest_hash": digest("manifest", bundle["manifest"]),
        "engine": ENGINE,
    }


def cite(bundle, rule_id):
    hd = next((i for i, r in enumerate(bundle["policy"]["hard_denies"]) if r["id"] == rule_id), -1)
    sr = next((i for i, r in enumerate(bundle["policy"]["scope_rules"]) if r["id"] == rule_id), -1)
    if hd < 0 and sr < 0:
        raise CharterError("NOT_FOUND", f"rule {rule_id} not in policy")
    pointer = f"/hard_denies/{hd}" if hd >= 0 else f"/scope_rules/{sr}"
    rule = bundle["policy"]["hard_denies"][hd] if hd >= 0 else bundle["policy"]["scope_rules"][sr]
    return {
        "schema": "charter.citation/1",
        "pin": pin_for(bundle),
        "rule_id": rule_id,
        "pointer": pointer,
        "clause_hash": digest("clause", rule),
        "rule": rule,
    }


def _escape_pointer(seg):
    return seg.replace("~", "~0").replace("/", "~1")


def _walk(base, a, b, out):
    if json_equal(a, b):
        return
    a_obj = isinstance(a, dict)
    b_obj = isinstance(b, dict)
    if a_obj and b_obj:
        for k in sorted(set(a) | set(b)):
            p = base + "/" + _escape_pointer(k)
            if k not in a or k not in b:
                out.append({"pointer": p, "before": a.get(k), "after": b.get(k)})
            else:
                _walk(p, a[k], b[k], out)
        return
    # Arrays compare whole; scalars compare directly.
    out.append({"pointer": base, "before": a, "after": b})


def diff(old_policy, new_policy):
    changes = []
    _walk("", old_policy, new_policy, changes)
    changes.sort(key=lambda c: c["pointer"].encode("utf-8"))
    return {"old_hash": digest("policy", old_policy),
            "new_hash": digest("policy", new_policy), "changes": changes}


# ---------- verifyBundle (§3.7) ----------

def _authority_for(bundle, root, predecessors, seen):
    policy = bundle["policy"]
    if policy["version"] == 1:
        if policy["previous_hash"] is not None:
            raise CharterError("SCHEMA", "genesis requires previous_hash=null")
        return root["bootstrap"]
    prev = next((b for b in predecessors if b["policy"]["version"] == policy["version"] - 1), None)
    if prev is None:
        raise CharterError("VERSION_CONFLICT", "missing predecessor bundle")
    if prev["policy"]["version"] not in seen:
        seen.add(prev["policy"]["version"])
        verify_bundle(prev, root, predecessors, None, seen)
    if digest("policy", prev["policy"]) != policy["previous_hash"]:
        raise CharterError("VERSION_CONFLICT", "previous_hash does not bind predecessor")
    if (prev["policy"]["charter_id"] != policy["charter_id"]
            or prev["policy"]["tenant_id"] != policy["tenant_id"]):
        raise CharterError("SCHEMA", "predecessor identity mismatch")
    return prev["policy"]["next_authority"]


def verify_bundle(raw_bundle, root, predecessors, at=None, _seen=None):
    """Historical cryptographic validity + authority continuity. `at` supplies
    the reference time for warning computation only (default issued_at)."""
    bundle = v_bundle(raw_bundle, "$.bundle")
    policy, manifest = bundle["policy"], bundle["manifest"]

    if policy["tenant_id"] != root["tenant_id"] or policy["charter_id"] != root["charter_id"]:
        raise CharterError("SCHEMA", "policy identity does not match root")
    if manifest["gateway_id"] != root["gateway_id"]:
        raise CharterError("SCHEMA", "manifest gateway does not match root")
    if digest("manifest", manifest) != policy["manifest_hash"]:
        raise CharterError("HASH_MISMATCH", "manifest digest mismatch")

    authority = _authority_for(bundle, root, predecessors, _seen or {policy["version"]})

    # Permanent key_id↔public_key binding across the provided chain.
    key_bytes = {}
    for b in [bundle, *predecessors]:
        for k in b["policy"]["next_authority"]["keys"]:
            prev = key_bytes.get(k["key_id"])
            if prev is not None and prev != k["public_key"]:
                raise CharterError("SCHEMA",
                                   f"key {k['key_id']} rebound to different public bytes")
            key_bytes[k["key_id"]] = k["public_key"]
    for k in root["bootstrap"]["keys"]:
        prev = key_bytes.get(k["key_id"])
        if prev is not None and prev != k["public_key"]:
            raise CharterError("SCHEMA", f"key {k['key_id']} rebound vs bootstrap")
        key_bytes[k["key_id"]] = k["public_key"]

    seen = set()
    for s in bundle["signatures"]:
        if s["key_id"] in seen:
            raise CharterError("SIGNATURE_DUPLICATE", s["key_id"])
        seen.add(s["key_id"])

    auth_keys = {k["key_id"]: k["public_key"] for k in authority["keys"]}
    for s in bundle["signatures"]:
        if s["key_id"] not in auth_keys:
            raise CharterError("KEY_UNKNOWN", s["key_id"])

    msg = sign_message("policy", policy)
    valid = 0
    for s in bundle["signatures"]:
        sig = base64.urlsafe_b64decode(s["signature"] + "=" * (-len(s["signature"]) % 4))
        if not verify_bytes(msg, sig, bytes.fromhex(auth_keys[s["key_id"]])):
            raise CharterError("SIGNATURE_INVALID", s["key_id"])
        valid += 1

    if valid < authority["threshold"]:
        raise CharterError("QUORUM", f"{valid} < {authority['threshold']}")

    compile(policy, manifest)

    ref = time_ms(at) if at is not None else time_ms(policy["issued_at"])
    warnings = set()
    if len(policy["scope_rules"]) == 0:
        warnings.add("NO_ALLOW_RULES")
    if authority["threshold"] == 1:
        warnings.add("SINGLE_SIGNER")
    na = time_ms(policy["not_after"])
    if na > ref and na - ref <= DAY_MS:
        warnings.add("EXPIRY_WITHIN_24H")

    return {
        "valid": True,
        "pin": pin_for(bundle),
        "signatures": valid,
        "required": authority["threshold"],
        "warnings": sorted(warnings),
    }


def check_signature_set(signatures, authority, message):
    """Signature-set check shared with pin verification."""
    seen = set()
    for s in signatures:
        if s["key_id"] in seen:
            raise CharterError("SIGNATURE_DUPLICATE", s["key_id"])
        seen.add(s["key_id"])
    auth_keys = {k["key_id"]: k["public_key"] for k in authority["keys"]}
    for s in signatures:
        if s["key_id"] not in auth_keys:
            raise CharterError("KEY_UNKNOWN", s["key_id"])
    valid = 0
    for s in signatures:
        sig = base64.urlsafe_b64decode(s["signature"] + "=" * (-len(s["signature"]) % 4))
        if not verify_bytes(message, sig, bytes.fromhex(auth_keys[s["key_id"]])):
            raise CharterError("SIGNATURE_INVALID", s["key_id"])
        valid += 1
    if valid < authority["threshold"]:
        raise CharterError("QUORUM", f"{valid} < {authority['threshold']}")
    return valid


# ---------- §9 offline evidence verifier ----------

def _bad():
    return {"integrity": "INVALID", "replay": "NOT_REQUESTED", "through_seq": 0,
            "checkpoint_match": False, "truth": "NOT_ATTESTED"}


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_checkpoint(cp, root):
    key = next((k for k in root["audit_keys"]
                if k["from_seq"] <= cp["body"]["through_seq"]
                and (k["through_seq"] is None or cp["body"]["through_seq"] <= k["through_seq"])),
               None)
    if key is None or key["key_id"] != cp["key_id"]:
        return False
    return verify_bytes(sign_message("checkpoint", cp["body"]),
                        _b64(cp["signature"]), bytes.fromhex(key["public_key"]))


def verify_evidence(ev, trusted_root, end_checkpoint, replay):
    try:
        return _verify_inner(ev, trusted_root, end_checkpoint, replay)
    except CharterError:
        return _bad()


def _verify_inner(ev, trusted_root, end_checkpoint, want_replay):
    root = v_root_file(trusted_root, "$.trusted_root")
    if not json_equal(ev["root"], root):
        return _bad()

    bundles = [v_bundle(b, f"$.bundles[{i}]") for i, b in enumerate(ev["bundles"])]
    entries = [v_audit_entry(e, f"$.entries[{i}]") for i, e in enumerate(ev["entries"])]
    start = None if ev["start"] is None else v_checkpoint(ev["start"], "$.start")
    end = v_checkpoint(ev["end"], "$.end")
    controls = [v_control_artifact(c, f"$.controls[{i}]") for i, c in enumerate(ev["controls"])]

    # bundle verification
    bundle_by_version = {}
    bundle_by_hash = {}
    for b in bundles:
        if digest("manifest", b["manifest"]) != b["policy"]["manifest_hash"]:
            return _bad()
        if b["manifest"]["engine"] != ENGINE or b["policy"]["engine"] != ENGINE:
            return _bad()
        if (b["policy"]["tenant_id"] != root["tenant_id"]
                or b["policy"]["charter_id"] != root["charter_id"]
                or b["manifest"]["gateway_id"] != root["gateway_id"]):
            return _bad()
        ph = digest("policy", b["policy"])
        if b["policy"]["version"] in bundle_by_version or ph in bundle_by_hash:
            return _bad()
        if b["policy"]["version"] > 1:
            prev = bundle_by_version.get(b["policy"]["version"] - 1)
            if prev is None or b["policy"]["previous_hash"] != digest("policy", prev["policy"]):
                return _bad()
        elif b["policy"]["previous_hash"] is not None:
            return _bad()
        authority = (root["bootstrap"] if b["policy"]["version"] == 1
                     else bundle_by_version[b["policy"]["version"] - 1]["policy"]["next_authority"])
        try:
            check_signature_set(b["signatures"], authority, sign_message("policy", b["policy"]))
            compile(b["policy"], b["manifest"])
        except CharterError:
            return _bad()
        bundle_by_version[b["policy"]["version"]] = b
        bundle_by_hash[ph] = b

    # audit chain
    first_want = (start["body"]["through_seq"] if start else 0) + 1
    prev_hash = ZERO_HASH if start is None else start["body"]["head_hash"]
    if start is not None:
        if (start["body"]["tenant_id"] != root["tenant_id"]
                or start["body"]["log_id"] != root["log_id"]):
            return _bad()
        if not _verify_checkpoint(start, root):
            return _bad()
    last_ms = float("-inf")
    expect_seq = first_want
    for e in entries:
        b = e["body"]
        if b["tenant_id"] != root["tenant_id"] or b["log_id"] != root["log_id"]:
            return _bad()
        if b["seq"] != expect_seq or b["prev_hash"] != prev_hash:
            return _bad()
        if digest("audit", b) != e["hash"]:
            return _bad()
        key = next((k for k in root["audit_keys"]
                    if k["from_seq"] <= b["seq"]
                    and (k["through_seq"] is None or b["seq"] <= k["through_seq"])), None)
        if key is None or key["key_id"] != e["key_id"]:
            return _bad()
        if not verify_bytes(sign_message("audit", b), _b64(e["signature"]),
                            bytes.fromhex(key["public_key"])):
            return _bad()
        ms = time_ms(b["time"])
        if ms < last_ms:
            return _bad()
        last_ms = ms
        prev_hash = e["hash"]
        expect_seq += 1
    through = entries[-1]["body"]["seq"] if entries else (start["body"]["through_seq"] if start else 0)

    # control artifacts bound to referencing events, in referencing order
    control_i = 0
    for e in entries:
        ch = e["body"]["event"].get("value", {}).get("control_hash") \
            if isinstance(e["body"]["event"].get("value"), dict) else None
        if ch is None:
            continue
        if control_i >= len(controls):
            return {"integrity": "INCOMPLETE", "replay": "NOT_REQUESTED",
                    "through_seq": e["body"]["seq"], "checkpoint_match": False,
                    "truth": "NOT_ATTESTED"}
        if digest("control", controls[control_i]) != ch:
            return _bad()
        control_i += 1

    # end checkpoint: fewer entries than claimed head = missing suffix
    # (INCOMPLETE); more entries or bad signature = corruption (INVALID).
    if not _verify_checkpoint(end, root):
        return _bad()
    if through < end["body"]["through_seq"]:
        return {"integrity": "INCOMPLETE", "replay": "NOT_REQUESTED",
                "through_seq": through, "checkpoint_match": False, "truth": "NOT_ATTESTED"}
    if through > end["body"]["through_seq"]:
        return _bad()
    checkpoint_match = (
        end["body"]["tenant_id"] == root["tenant_id"]
        and end["body"]["log_id"] == root["log_id"]
        and end["body"]["head_hash"] == prev_hash
        and (end_checkpoint is None or json_equal(end, end_checkpoint)))
    if not checkpoint_match:
        return _bad()

    replay_result = "NOT_REQUESTED"
    if want_replay:
        if start is not None:
            replay_result = "CONTEXT_MISSING"
        else:
            inputs = {i["request"]["request_id"]: i for i in ev["inputs"]}
            replay_result = _replay_with_inputs(root, bundle_by_hash, entries, inputs)

    return {"integrity": "VALID", "replay": replay_result, "through_seq": through,
            "checkpoint_match": True, "truth": "NOT_ATTESTED"}


def _replay_with_inputs(root, bundle_by_hash, entries, inputs):
    active_pin = None
    for e in entries:
        b = e["body"]
        ev = b["event"]
        if ev["type"] == "PinActivated":
            active_pin = ev["value"]["pin"]
        elif ev["type"] in ("CheckEvaluated", "CallDenied", "CallCommitted"):
            dd = ev["value"]
            inp = inputs.get(dd["request_id"])
            if inp is None:
                return "INPUTS_MISSING"
            if active_pin is None:
                return "CONTEXT_MISSING"
            bundle = bundle_by_hash.get(active_pin["policy_hash"])
            if bundle is None:
                return "CONTEXT_MISSING"
            rev_policies = set()
            rev_keys = set()
            for e2 in entries:
                if e2["body"]["seq"] >= b["seq"]:
                    break
                ev2 = e2["body"]["event"]
                if (ev2["type"] == "TargetRevoked"
                        and ev2["value"]["epoch"] <= dd["revocation_epoch"]):
                    t = ev2["value"]["target"]
                    if t["kind"] == "policy":
                        rev_policies.add(t["policy_hash"])
                    elif t["kind"] == "policy_key":
                        rev_keys.add(t["key_id"])
            authority = (root["bootstrap"] if bundle["policy"]["version"] == 1
                         else (bundle_by_hash.get(bundle["policy"]["previous_hash"] or "", {})
                               .get("policy", {}).get("next_authority")))
            if authority is None:
                return "CONTEXT_MISSING"
            auth_keys = {k["key_id"] for k in authority["keys"]}
            seen = set()
            eligible = 0
            for s in bundle["signatures"]:
                if s["key_id"] in rev_keys or s["key_id"] in seen or s["key_id"] not in auth_keys:
                    continue
                seen.add(s["key_id"])
                eligible += 1
            recomputed = evaluate({
                "policy": bundle["policy"], "manifest": bundle["manifest"],
                "active_pin": active_pin, "request": inp["request"],
                "principal": inp["principal"], "now": dd["evaluated_at"],
                "policy_revoked": active_pin["policy_hash"] in rev_policies,
                "policy_signatures_valid": eligible >= authority["threshold"],
            })
            if not json_equal(recomputed, dd["decision"]):
                return "MISMATCH"
    return "MATCH"
