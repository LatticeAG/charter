"""Closed-schema validators (§1.1): every declared field required including
nullables; unknown properties rejected; set arrays sorted and unique on
arrival. All failures are CharterError(SCHEMA).
"""
import base64
import re

from .errors import CharterError, ERROR_CODES
from .jcs import canonicalize
from .scalars import (
    is_hash, is_id, is_int, is_label, is_nfc, is_public, is_repository,
    is_resource, is_scalar, is_signature, is_time, is_tool_name, utf8_bytes,
)

ENGINE = "charter.eval/1"


def fail(path, what):
    raise CharterError("SCHEMA", f"{path}: {what}")


def obj(v, path, spec):
    """Closed object: exact key set, every declared field required."""
    if not isinstance(v, dict):
        fail(path, "not an object")
    want = sorted(spec.keys())
    got = sorted(v.keys())
    if want != got:
        missing = [k for k in want if k not in v]
        extra = [k for k in got if k not in spec]
        fail(path, f"closed object violation (missing: {','.join(missing) or '-'};"
                   f" unknown: {','.join(extra) or '-'})")
    return {k: spec[k](v[k], f"{path}.{k}") for k in want}


def arr(v, path, item, min=None, max=None, sort_cmp=None, unique_cmp=None):
    if not isinstance(v, list):
        fail(path, "not an array")
    if min is not None and len(v) < min:
        fail(path, f"fewer than {min} elements")
    if max is not None and len(v) > max:
        fail(path, f"more than {max} elements")
    out = [item(x, f"{path}[{i}]") for i, x in enumerate(v)]
    cmp = sort_cmp or unique_cmp
    if cmp:
        for i in range(1, len(out)):
            c = cmp(out[i - 1], out[i])
            if unique_cmp and c == 0:
                fail(path, "duplicate set member")
            if sort_cmp and c >= 0:
                fail(path, "set not strictly sorted")
    return out


def byte_cmp(a, b):
    ab, bb = a.encode("utf-8"), b.encode("utf-8")
    return (ab > bb) - (ab < bb)


def canon_cmp(a, b):
    return byte_cmp(canonicalize(a), canonicalize(b))


def _int(v, p):
    return v if is_int(v) else fail(p, "not Int")


def _bounded_int(lo, hi):
    return lambda v, p: v if is_int(v) and lo <= v <= hi else fail(p, f"int outside [{lo},{hi}]")


def _str(v, p):
    return v if isinstance(v, str) and is_nfc(v) else fail(p, "not NFC string")


def _bool(v, p):
    return v if isinstance(v, bool) else fail(p, "not boolean")


def _nul(v, p):
    return None if v is None else fail(p, "not null")


def _hash(v, p):
    return v if is_hash(v) else fail(p, "not Hash")


def _pub(v, p):
    return v if is_public(v) else fail(p, "not Public")


def _sig(v, p):
    return v if is_signature(v) else fail(p, "not Signature")


def _time(v, p):
    return v if is_time(v) else fail(p, "not Time")


def _label(v, p):
    return v if is_label(v) else fail(p, "not Label")


def _tool_name(v, p):
    return v if is_tool_name(v) else fail(p, "not ToolName")


def _resource(v, p):
    return v if is_resource(v) else fail(p, "not Resource")


def _id_of(prefix):
    return lambda v, p: v if is_id(v, prefix) else fail(p, f"not ID<{prefix}>")


def _scalar(v, p):
    ok = is_scalar(v) and (not isinstance(v, str) or is_nfc(v))
    return v if ok else fail(p, "not Scalar")


def _nullable(inner):
    return lambda v, p: None if v is None else inner(v, p)


def _one_of(*xs):
    return lambda v, p: v if v in xs else fail(p, f"not one of {'|'.join(xs)}")


def _max_bytes_str(n):
    return lambda v, p: v if isinstance(v, str) and is_nfc(v) and utf8_bytes(v) <= n \
        else fail(p, f"string > {n} bytes")


def _ranged_str(lo, hi):
    def check(v, p):
        if isinstance(v, str) and is_nfc(v) and lo <= utf8_bytes(v) <= hi:
            return v
        return fail(p, f"string outside {lo}..{hi} bytes")
    return check


def v_json(v, p):
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if is_int(v) else fail(p, "not Int")
    if isinstance(v, str):
        return v if is_nfc(v) else fail(p, "not NFC")
    if isinstance(v, list):
        if len(v) > 256:
            fail(p, "array > 256")
        return [v_json(x, f"{p}[{i}]") for i, x in enumerate(v)]
    if isinstance(v, dict):
        if len(v) > 256:
            fail(p, "members > 256")
        out = {}
        for k, x in v.items():
            if not is_nfc(k):
                fail(p, "non-NFC member name")
            out[k] = v_json(x, f"{p}.{k}")
        return out
    return fail(p, "not Json")


# ---------- §1.3 objects ----------

def v_key(v, p):
    return obj(v, p, {"key_id": _id_of("cky"), "public_key": _pub})


def v_authority(v, p):
    a = obj(v, p, {
        "threshold": _bounded_int(1, 8),
        "keys": lambda x, pp: arr(x, pp, v_key, min=1, max=8,
                                  sort_cmp=lambda a2, b2: byte_cmp(a2["key_id"], b2["key_id"]),
                                  unique_cmp=lambda a2, b2: byte_cmp(a2["key_id"], b2["key_id"])),
    })
    if a["threshold"] > len(a["keys"]):
        fail(f"{p}.threshold", "exceeds key count")
    pubs = {k["public_key"] for k in a["keys"]}
    if len(pubs) != len(a["keys"]):
        fail(f"{p}.keys", "public-key alias")
    return a


def v_detached(v, p):
    return obj(v, p, {"key_id": _id_of("cky"), "signature": _sig})


def v_detached_set(v, p):
    """1–8 entries in non-decreasing key_id order; repeated key_id stays
    structurally valid so the signature stage reports SIGNATURE_DUPLICATE."""
    out = arr(v, p, v_detached, min=1, max=8)
    for i in range(1, len(out)):
        if byte_cmp(out[i - 1]["key_id"], out[i]["key_id"]) > 0:
            fail(p, "unsorted signature set")
    return out


def v_source(v, p):
    return obj(v, p, {
        "repository": lambda x, pp: x if is_repository(x) else fail(pp, "not repository"),
        "pull_request": _bounded_int(1, 2147483647),
        "commit": lambda x, pp: x if isinstance(x, str) and re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", x)
        else fail(pp, "not 40|64 hex commit"),
    })


def v_selector(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    if v.get("match") == "all":
        return obj(v, p, {"match": _one_of("all")})
    return obj(v, p, {"match": _one_of("exact", "segment_prefix"), "value": _resource})


def v_predicate(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    op = v.get("op")
    if op == "eq":
        return obj(v, p, {"arg": _label, "op": _one_of("eq"), "value": _scalar})
    if op == "int_lte":
        return obj(v, p, {"arg": _label, "op": _one_of("int_lte"), "value": _int})
    fail(p, "unknown predicate op")


def _principal_or_star(v, p):
    return v if v == "*" or is_id(v, "cpr") else fail(p, "not PrincipalId|*")


def _scope_or_star(v, p):
    return v if v == "*" or is_label(v) else fail(p, "not Label|*")


def v_rule(hard):
    def check(v, p):
        r = obj(v, p, {
            "id": _id_of("crl"),
            "text": _ranged_str(1, 512),
            "principals": lambda x, pp: arr(x, pp, _principal_or_star, min=1, max=32,
                                            sort_cmp=byte_cmp, unique_cmp=byte_cmp),
            "tools": lambda x, pp: arr(x, pp, _tool_name, min=1, max=32,
                                       sort_cmp=byte_cmp, unique_cmp=byte_cmp),
            "scopes": lambda x, pp: arr(x, pp, _scope_or_star, min=1, max=32,
                                        sort_cmp=byte_cmp, unique_cmp=byte_cmp),
            "resources": lambda x, pp: arr(x, pp, v_selector, min=1, max=16,
                                           sort_cmp=canon_cmp, unique_cmp=canon_cmp),
            "when": lambda x, pp: arr(x, pp, v_predicate, min=0, max=16,
                                      sort_cmp=canon_cmp, unique_cmp=canon_cmp),
        })
        if "*" in r["principals"] and len(r["principals"]) != 1:
            fail(f"{p}.principals", "'*' must stand alone")
        if "*" in r["scopes"] and len(r["scopes"]) != 1:
            fail(f"{p}.scopes", "'*' must stand alone")
        if not hard:
            if "*" in r["scopes"]:
                fail(f"{p}.scopes", "wildcard scope in allow rule")
            if any(s["match"] == "all" for s in r["resources"]):
                fail(f"{p}.resources", "selector 'all' in allow rule")
        return r
    return check


def v_field(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    kind = v.get("kind")
    if kind == "string":
        return obj(v, p, {"name": _label, "kind": _one_of("string"), "max_bytes": _int})
    if kind == "integer":
        f = obj(v, p, {"name": _label, "kind": _one_of("integer"), "min": _int, "max": _int})
        if f["min"] > f["max"]:
            fail(p, "min > max")
        return f
    if kind == "boolean":
        return obj(v, p, {"name": _label, "kind": _one_of("boolean")})
    fail(p, "unknown field kind")


def v_tool(v, p):
    return obj(v, p, {
        "tool": _tool_name,
        "binding": _one_of("RECORDS"),
        "operation": _one_of("get", "put", "delete", "list", "export"),
        "args": lambda x, pp: arr(x, pp, v_field, max=16,
                                  sort_cmp=lambda a, b: byte_cmp(a["name"], b["name"]),
                                  unique_cmp=lambda a, b: byte_cmp(a["name"], b["name"])),
    })


def v_manifest(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.manifest/1"),
        "gateway_id": _id_of("cgw"),
        "engine": _one_of(ENGINE),
        "resource_grammar": _one_of("segments/1"),
        "adapter_build_hash": _hash,
        "tools": lambda x, pp: arr(x, pp, v_tool, min=1, max=32,
                                   sort_cmp=lambda a, b: byte_cmp(a["tool"], b["tool"]),
                                   unique_cmp=lambda a, b: byte_cmp(a["tool"], b["tool"])),
    })


def v_policy(v, p):
    pol = obj(v, p, {
        "schema": _one_of("charter.policy/1"),
        "tenant_id": _id_of("cte"),
        "charter_id": _id_of("cch"),
        "version": _bounded_int(1, MAX_SAFE_V := 9007199254740991),
        "previous_hash": _nullable(_hash),
        "engine": _one_of(ENGINE),
        "manifest_hash": _hash,
        "issued_at": _time,
        "not_before": _time,
        "not_after": _time,
        "source": v_source,
        "description": _ranged_str(1, 2048),
        "next_authority": v_authority,
        "hard_denies": lambda x, pp: arr(x, pp, v_rule(True), max=128,
                                         sort_cmp=lambda a, b: byte_cmp(a["id"], b["id"]),
                                         unique_cmp=lambda a, b: byte_cmp(a["id"], b["id"])),
        "scope_rules": lambda x, pp: arr(x, pp, v_rule(False), max=128,
                                         sort_cmp=lambda a, b: byte_cmp(a["id"], b["id"]),
                                         unique_cmp=lambda a, b: byte_cmp(a["id"], b["id"])),
    })
    if len(pol["hard_denies"]) + len(pol["scope_rules"]) > 128:
        fail(p, "more than 128 rules")
    ids = {r["id"] for r in pol["hard_denies"] + pol["scope_rules"]}
    if len(ids) != len(pol["hard_denies"]) + len(pol["scope_rules"]):
        fail(p, "rule id reused across lists")
    if pol["version"] == 1:
        ok = pol["previous_hash"] is None
    else:
        ok = is_hash(pol["previous_hash"])
    if not ok:
        fail(f"{p}.previous_hash", "genesis requires null; successor requires hash")
    return pol


def v_bundle(v, p):
    return obj(v, p, {"policy": v_policy, "manifest": v_manifest, "signatures": v_detached_set})


def v_pin(v, p):
    return obj(v, p, {
        "charter_id": _id_of("cch"), "version": _bounded_int(1, 9007199254740991),
        "policy_hash": _hash, "manifest_hash": _hash, "engine": _one_of(ENGINE),
    })


def v_citation(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.citation/1"), "pin": v_pin, "rule_id": _id_of("crl"),
        "pointer": lambda x, pp: x if isinstance(x, str)
        and re.match(r"^/(hard_denies|scope_rules)/(0|[1-9][0-9]*)$", x) else fail(pp, "bad pointer"),
        "clause_hash": _hash,
        "rule": v_rule(True),
    })


# ---------- §1.4 control/identity ----------

def v_pin_command(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.pin/1"), "tenant_id": _id_of("cte"), "gateway_id": _id_of("cgw"),
        "request_id": _id_of("crq"), "expected_revision": _int, "expected_revocation_epoch": _int,
        "authority_policy_hash": _hash, "target": v_pin, "expires_at": _time,
    })


def v_signed_pin(v, p):
    return obj(v, p, {"command": v_pin_command, "signatures": v_detached_set})


def v_pause_request(v, p):
    return obj(v, p, {"request_id": _id_of("crq"), "expected_revision": _int,
                      "reason": _ranged_str(1, 256)})


def v_revoke_target(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    kind = v.get("kind")
    if kind == "policy":
        return obj(v, p, {"kind": _one_of("policy"), "policy_hash": _hash})
    if kind == "credential":
        return obj(v, p, {"kind": _one_of("credential"), "credential_id": _id_of("ccr")})
    if kind == "policy_key":
        return obj(v, p, {"kind": _one_of("policy_key"), "key_id": _id_of("cky")})
    fail(p, "unknown revoke target kind")


def v_revoke_request(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "expected_revocation_epoch": _int,
        "target": v_revoke_target, "reason": _ranged_str(1, 256),
    })


def v_revocation(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "expected_revocation_epoch": _int, "target": v_revoke_target,
        "reason": _ranged_str(1, 256), "epoch": _bounded_int(1, 9007199254740991),
        "actor_id": _id_of("cpr"), "effective_seq": _int, "recorded_at": _time,
    })


def v_deployment(v, p):
    return obj(v, p, {
        "gateway_id": _id_of("cgw"), "revision": _int, "revocation_epoch": _int,
        "state": _one_of("UNPINNED", "ACTIVE", "PAUSED"), "pin": _nullable(v_pin),
        "installed_manifest_hash": _hash, "in_flight": _int,
    })


def v_principal(v, p):
    return obj(v, p, {
        "principal_id": _id_of("cpr"), "credential_id": _id_of("ccr"), "instance_id": _id_of("cin"),
        "scopes": lambda x, pp: arr(x, pp, _label, max=32, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
    })


def v_call_request(v, p):
    def args(x, pp):
        if not isinstance(x, dict):
            fail(pp, "not object")
        if len(x) > 256:
            fail(pp, "args members > 256")
        out = {}
        for k, av in x.items():
            if not is_label(k):
                fail(pp, "arg name not Label")
            out[k] = _scalar(av, f"{pp}.{k}")
        return out
    return obj(v, p, {
        "request_id": _id_of("crq"), "pin": v_pin, "scope": _label, "tool": _tool_name,
        "resource": _resource, "args": args, "deadline": _time,
    })


_REASONS = (
    "ALLOW_SCOPE", "HARD_DENY", "NO_SCOPE", "PIN_MISMATCH", "MANIFEST_MISMATCH",
    "POLICY_REVOKED", "POLICY_KEY_REVOKED", "POLICY_NOT_YET_VALID", "POLICY_EXPIRED",
    "DEADLINE", "PRINCIPAL_SCOPE", "UNKNOWN_TOOL",
)


def v_decision(v, p):
    return obj(v, p, {
        "verdict": _one_of("ALLOW", "DENY"), "reason": _one_of(*_REASONS),
        "rule_ids": lambda x, pp: arr(x, pp, _id_of("crl"), max=128,
                                      sort_cmp=byte_cmp, unique_cmp=byte_cmp),
    })


def v_call_result(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"),
        "state": _one_of("DENIED", "COMMITTED", "SUCCEEDED", "FAILED", "INDETERMINATE", "NOT_SENT"),
        "decision": v_decision, "input_hash": _hash, "output": v_json, "output_available": _bool,
        "output_hash": _nullable(_hash),
        "audit_seqs": lambda x, pp: arr(x, pp, _int, min=1, max=4),
    })


def v_check_result(v, p):
    return obj(v, p, {"decision": v_decision, "input_hash": _hash,
                      "enforcement": lambda x, pp: False if x is False else fail(pp, "not false"),
                      "audit_seq": _int})


def v_control_result(v, p):
    return obj(v, p, {"deployment": v_deployment, "audit_seq": _int})


def v_revoke_result(v, p):
    return obj(v, p, {"revocation": v_revocation, "deployment": v_deployment})


# ---------- §1.5 fleet/disputes/audit/evidence ----------

def v_heartbeat(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "instance_id": _id_of("cin"),
        "counter": _bounded_int(1, 9007199254740991),
        "observed_pin": _nullable(v_pin), "manifest_hash": _hash,
    })


def v_instance_view(v, p):
    return obj(v, p, {
        "instance_id": _id_of("cin"), "counter": _int, "received_at": _nullable(_time),
        "expires_at": _nullable(_time), "observed_pin": _nullable(v_pin),
        "manifest_hash": _nullable(_hash),
        "state": _one_of("MISSING", "MATCHED", "MISMATCH"),
    })


def v_fleet(v, p):
    return obj(v, p, {
        "as_of": _time, "desired_pin": _nullable(v_pin),
        "status": _one_of("EMPTY", "HEALTHY", "SPLIT", "MISSING"),
        "instances": lambda x, pp: arr(x, pp, v_instance_view, max=32,
                                       sort_cmp=lambda a, b: byte_cmp(a["instance_id"], b["instance_id"]),
                                       unique_cmp=lambda a, b: byte_cmp(a["instance_id"], b["instance_id"])),
    })


def v_heartbeat_result(v, p):
    return obj(v, p, {"counter": _int, "expires_at": _time,
                      "state": _one_of("MISSING", "MATCHED", "MISMATCH"), "audit_seq": _int})


def v_dispute_request(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "dispute_id": _id_of("cds"), "pin": v_pin, "cited_seq": _int,
        "category": _one_of("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"),
        "statement": _ranged_str(1, 4096),
        "evidence_hashes": lambda x, pp: arr(x, pp, _hash, max=16, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
    })


def v_dispute(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "dispute_id": _id_of("cds"), "pin": v_pin, "cited_seq": _int,
        "category": _one_of("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"),
        "statement": _ranged_str(1, 4096),
        "evidence_hashes": lambda x, pp: arr(x, pp, _hash, max=16, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
        "actor_id": _id_of("cpr"), "recorded_at": _time, "status": _one_of("RECORDED_ADVISORY"),
        "receipt_seq": _int,
    })


def _decision_data(x, pp):
    return obj(x, pp, {
        "request_id": _id_of("crq"), "input_hash": _hash, "evaluated_at": _time,
        "decision": v_decision, "revision": _int, "revocation_epoch": _int, "instance_counter": _int,
    })


def v_audit_event(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    t = v.get("type")
    if t == "PolicyPublished":
        return obj(v, p, {"type": _one_of("PolicyPublished"),
                          "value": lambda x, pp: obj(x, pp, {"pin": v_pin, "source": v_source})})
    if t == "PinActivated":
        return obj(v, p, {"type": _one_of("PinActivated"),
                          "value": lambda x, pp: obj(x, pp, {
                              "revision": _int, "revocation_epoch": _int,
                              "previous_pin": _nullable(v_pin), "pin": v_pin,
                              "control_hash": _hash, "in_flight": _int})})
    if t == "GatewayPaused":
        return obj(v, p, {"type": _one_of("GatewayPaused"),
                          "value": lambda x, pp: obj(x, pp, {
                              "revision": _int, "control_hash": _hash, "in_flight": _int})})
    if t == "TargetRevoked":
        return obj(v, p, {"type": _one_of("TargetRevoked"),
                          "value": lambda x, pp: obj(x, pp, {
                              "epoch": _int, "target": v_revoke_target,
                              "control_hash": _hash, "in_flight": _int})})
    if t in ("CheckEvaluated", "CallDenied", "CallCommitted"):
        return obj(v, p, {"type": _one_of(t), "value": _decision_data})
    if t == "CallFinished":
        return obj(v, p, {"type": _one_of("CallFinished"),
                          "value": lambda x, pp: obj(x, pp, {
                              "request_id": _id_of("crq"),
                              "state": _one_of("SUCCEEDED", "FAILED", "INDETERMINATE", "NOT_SENT"),
                              "output_hash": _nullable(_hash)})})
    if t == "InstanceObserved":
        return obj(v, p, {"type": _one_of("InstanceObserved"),
                          "value": lambda x, pp: obj(x, pp, {
                              "heartbeat": v_heartbeat, "expires_at": _time})})
    if t == "DisputeRecorded":
        return obj(v, p, {"type": _one_of("DisputeRecorded"),
                          "value": lambda x, pp: obj(x, pp, {
                              "dispute_id": _id_of("cds"), "cited_seq": _int,
                              "category": _one_of("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"),
                              "statement_hash": _hash})})
    if t == "CommandRejected":
        return obj(v, p, {"type": _one_of("CommandRejected"),
                          "value": lambda x, pp: obj(x, pp, {
                              "operation": _str, "request_hash": _hash,
                              "code": _one_of(*ERROR_CODES)})})
    if t == "StorageMigrated":
        return obj(v, p, {"type": _one_of("StorageMigrated"),
                          "value": lambda x, pp: obj(x, pp, {
                              "from_version": _int, "to_version": _int, "migration_hash": _hash})})
    fail(p, f"unknown audit event type {t}")


def v_audit_body(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.audit/1"), "tenant_id": _id_of("cte"), "log_id": _id_of("clg"),
        "seq": _bounded_int(1, 9007199254740991), "prev_hash": _hash, "time": _time,
        "actor_id": _id_of("cpr"), "policy_pin": _nullable(v_pin), "event": v_audit_event,
    })


def v_audit_entry(v, p):
    return obj(v, p, {"body": v_audit_body, "hash": _hash, "key_id": _id_of("cky"), "signature": _sig})


def v_checkpoint_body(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.checkpoint/1"), "tenant_id": _id_of("cte"), "log_id": _id_of("clg"),
        "through_seq": _int, "head_hash": _hash, "time": _time,
    })


def v_checkpoint(v, p):
    return obj(v, p, {"body": v_checkpoint_body, "key_id": _id_of("cky"), "signature": _sig})


def v_control_artifact(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    kind = v.get("kind")
    if kind == "pin":
        return obj(v, p, {"kind": _one_of("pin"), "value": v_signed_pin})
    if kind == "pause":
        return obj(v, p, {"kind": _one_of("pause"), "value": v_pause_request})
    if kind == "revoke":
        return obj(v, p, {"kind": _one_of("revoke"), "value": v_revoke_request})
    fail(p, "unknown control kind")


def v_audit_page(v, p):
    return obj(v, p, {
        "entries": lambda x, pp: arr(x, pp, v_audit_entry, max=100),
        "controls": lambda x, pp: arr(x, pp, v_control_artifact, max=256),
        "through_seq": _int, "next_after": _nullable(_int),
    })


def v_evidence(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.evidence/1"), "root": v_root_file,
        "bundles": lambda x, pp: arr(x, pp, v_bundle, max=256),
        "start": _nullable(v_checkpoint),
        "entries": lambda x, pp: arr(x, pp, v_audit_entry, max=256),
        "controls": lambda x, pp: arr(x, pp, v_control_artifact, max=256),
        "end": v_checkpoint,
        "inputs": lambda x, pp: arr(x, pp, lambda xi, ppi: obj(xi, ppi, {
            "request": v_call_request, "principal": v_principal}), max=256),
    })


def v_verification(v, p):
    return obj(v, p, {
        "integrity": _one_of("VALID", "INVALID", "INCOMPLETE"),
        "replay": _one_of("MATCH", "MISMATCH", "NOT_REQUESTED", "INPUTS_MISSING", "CONTEXT_MISSING"),
        "through_seq": _int, "checkpoint_match": _bool, "truth": _one_of("NOT_ATTESTED"),
    })


# ---------- §5 config/root/auth ----------

def v_audit_key(v, p):
    k = obj(v, p, {"key_id": _id_of("cky"), "public_key": _pub,
                   "from_seq": _bounded_int(1, 9007199254740991), "through_seq": _nullable(_int)})
    if k["through_seq"] is not None and k["through_seq"] < k["from_seq"]:
        fail(p, "through_seq < from_seq")
    return k


def v_root_file(v, p):
    r = obj(v, p, {
        "schema": _one_of("charter.root/1"), "tenant_id": _id_of("cte"), "charter_id": _id_of("cch"),
        "gateway_id": _id_of("cgw"), "log_id": _id_of("clg"), "bootstrap": v_authority,
        "audit_keys": lambda x, pp: arr(x, pp, v_audit_key, min=1, max=16,
                                        sort_cmp=lambda a, b: a["from_seq"] - b["from_seq"],
                                        unique_cmp=lambda a, b: a["from_seq"] - b["from_seq"]),
    })
    keys = r["audit_keys"]
    for i in range(1, len(keys)):
        prev = keys[i - 1]
        if prev["through_seq"] is None:
            fail(f"{p}.audit_keys", "non-final open range")
        if prev["through_seq"] + 1 != keys[i]["from_seq"]:
            fail(f"{p}.audit_keys", "gap/overlap in ranges")
    boot_pubs = {k["public_key"] for k in r["bootstrap"]["keys"]}
    boot_ids = {k["key_id"] for k in r["bootstrap"]["keys"]}
    for ak in keys:
        if ak["public_key"] in boot_pubs or ak["key_id"] in boot_ids:
            fail(f"{p}.audit_keys", "audit key overlaps bootstrap")
    return r


def v_auth_record(v, p):
    r = obj(v, p, {
        "credential_id": _id_of("ccr"), "token_hash": _hash, "tenant_id": _id_of("cte"),
        "principal_id": _id_of("cpr"),
        "role": _one_of("reader", "publisher", "operator", "agent", "instance"),
        "scopes": lambda x, pp: arr(x, pp, _label, max=32, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
        "instance_id": _nullable(_id_of("cin")), "expires_at": _time,
    })
    if r["role"] in ("agent", "instance"):
        if r["instance_id"] is None:
            fail(f"{p}.instance_id", "agent/instance requires bound installation")
        if r["role"] == "agent" and not (1 <= len(r["scopes"]) <= 32):
            fail(f"{p}.scopes", "agent needs 1-32 scopes")
    else:
        if r["instance_id"] is not None:
            fail(f"{p}.instance_id", "non-agent role must have null instance")
        if len(r["scopes"]) != 0:
            fail(f"{p}.scopes", "non-agent roles must have empty scopes")
    return r


def v_auth_file(v, p):
    f = obj(v, p, {
        "schema": _one_of("charter.auth/1"),
        "records": lambda x, pp: arr(x, pp, v_auth_record, min=1, max=256),
    })
    ids = {r["credential_id"] for r in f["records"]}
    hashes = {r["token_hash"] for r in f["records"]}
    if len(ids) != len(f["records"]) or len(hashes) != len(f["records"]):
        fail(f"{p}.records", "duplicate credential id/hash")
    return f


def _v_enc_key(x, pp):
    def b64(xv, ppp):
        if not isinstance(xv, str):
            fail(ppp, "not string")
        try:
            raw = base64.urlsafe_b64decode(xv + "=" * (-len(xv) % 4))
        except Exception:
            fail(ppp, "not canonical base64url(32)")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != xv:
            fail(ppp, "not canonical base64url(32)")
        return xv
    return obj(x, pp, {"key_id": _label, "key_base64url": b64})


def v_encryption_keys(v, p):
    e = obj(v, p, {
        "active_key_id": _label,
        "keys": lambda x, pp: arr(x, pp, _v_enc_key, min=1, max=8,
                                  sort_cmp=lambda a, b: byte_cmp(a["key_id"], b["key_id"]),
                                  unique_cmp=lambda a, b: byte_cmp(a["key_id"], b["key_id"])),
    })
    if not any(k["key_id"] == e["active_key_id"] for k in e["keys"]):
        fail(f"{p}.active_key_id", "absent from keys")
    return e


RE_SECRET_REF = re.compile(r"^env:[A-Z][A-Z0-9_]{0,63}$")


def _secret_ref(x, pp):
    return x if isinstance(x, str) and RE_SECRET_REF.match(x) else fail(pp, "not env:NAME")


def v_config(v, p):
    c = obj(v, p, {
        "schema": _one_of("charter.config/1"),
        "environment": _one_of("local", "production"),
        "endpoint": _str,
        "tenant_id": _id_of("cte"), "gateway_id": _id_of("cgw"), "instance_id": _id_of("cin"),
        "system_principal_id": _id_of("cpr"), "root_file": _str, "manifest_file": _str,
        "instance_inventory": lambda x, pp: arr(x, pp, _id_of("cin"), min=1, max=32,
                                                sort_cmp=byte_cmp, unique_cmp=byte_cmp),
        "client_credential_ref": _secret_ref,
        "auth_records_ref": _secret_ref,
        "audit_seed_ref": _secret_ref,
        "audit_key_id": _id_of("cky"),
        "response_keys_ref": _secret_ref,
        "storage_soft_limit_bytes": _bounded_int(67108864, 8589934592),
        "max_in_flight": _bounded_int(1, 32),
        "metrics_enabled": _bool,
    })
    if c["instance_id"] not in c["instance_inventory"]:
        fail(f"{p}.instance_inventory", "must contain instance_id")
    if c["environment"] == "local":
        if not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?/?$", c["endpoint"]):
            fail(f"{p}.endpoint", "local profile is HTTP loopback only")
    else:
        if not re.match(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?/?$", c["endpoint"]):
            fail(f"{p}.endpoint", "production endpoint must be bare HTTPS origin")
    return c


# ---------- §3.7 adapter ----------

def v_adapter_request(v, p):
    return obj(v, p, {
        "request_id": _id_of("crq"), "principal_id": _id_of("cpr"), "scope": _label, "pin": v_pin,
        "input_hash": _hash, "operation": _one_of("get", "put", "delete", "list", "export"),
        "resource": _resource,
        "args": lambda x, pp: ({k: _scalar(av, f"{pp}.{k}") for k, av in x.items()}
                               if isinstance(x, dict) else fail(pp, "not object")),
        "deadline": _time,
    })


def v_adapter_response(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    status = v.get("status")
    if status in ("ok", "error"):
        return obj(v, p, {"status": _one_of("ok", "error"), "output": v_json})
    if status == "unknown":
        return obj(v, p, {"status": _one_of("unknown")})
    fail(p, "unknown adapter status")


# ---------- §9 observability + export stream ----------

def v_metric_snapshot(v, p):
    return obj(v, p, {
        "window_seconds": lambda x, pp: 60 if x == 60 else fail(pp, "not 60"),
        "calls": _int, "allows": _int, "denies": _int, "indeterminate": _int, "not_sent": _int,
        "audit_failures": _int, "pin_revision": _int, "revocation_epoch": _int,
        "instances_matched": _int, "instances_missing": _int, "instances_mismatch": _int,
    })


def v_validated(v, p):
    return obj(v, p, {
        "valid": lambda x, pp: True if x is True else fail(pp, "not true"),
        "pin": v_pin, "signatures": _int, "required": _int,
        "warnings": lambda x, pp: arr(x, pp, _one_of("NO_ALLOW_RULES", "SINGLE_SIGNER", "EXPIRY_WITHIN_24H"),
                                      max=3, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
    })


def v_compiled(v, p):
    return obj(v, p, {"policy_hash": _hash, "manifest_hash": _hash, "engine": _one_of(ENGINE)})


def v_proof_link(v, p):
    return obj(v, p, {
        "schema": _one_of("charter.proof-link/1"), "tenant_id": _id_of("cte"), "log_id": _id_of("clg"),
        "seq": _int, "audit_hash": _hash, "policy_pin": _nullable(v_pin), "input_hash": _nullable(_hash),
        "parent_hashes": lambda x, pp: arr(x, pp, _hash, max=3, sort_cmp=byte_cmp, unique_cmp=byte_cmp),
        "evidence_profile": _one_of("charter.stream/1"), "execution_truth": _one_of("NOT_ATTESTED"),
    })


def v_export_header(v, p):
    return obj(v, p, {"record": _one_of("header"), "schema": _one_of("charter.stream/1"),
                      "root": v_root_file, "start": _nullable(v_checkpoint), "end": v_checkpoint})


def v_export_bundle(v, p):
    return obj(v, p, {"record": _one_of("bundle"), "bundle": v_bundle})


def v_export_control(v, p):
    return obj(v, p, {"record": _one_of("control"), "control": v_control_artifact})


def v_export_entry(v, p):
    return obj(v, p, {"record": _one_of("entry"), "entry": v_audit_entry})


def v_export_input(v, p):
    return obj(v, p, {"record": _one_of("input"),
                      "input": lambda x, pp: obj(x, pp, {"request": v_call_request, "principal": v_principal})})


def v_export_trailer(v, p):
    return obj(v, p, {"record": _one_of("trailer"), "bundles": _int, "controls": _int,
                      "entries": _int, "inputs": _int, "through_seq": _int})


def v_export_record(v, p):
    if not isinstance(v, dict):
        fail(p, "not object")
    rec = v.get("record")
    f = {"header": v_export_header, "bundle": v_export_bundle, "control": v_export_control,
         "entry": v_export_entry, "input": v_export_input, "trailer": v_export_trailer}.get(rec)
    if f is None:
        fail(p, "unknown stream record")
    return f(v, p)
