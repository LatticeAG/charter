"""`python -m latticeagi_charter` — the §4 CLI contract (charter/1).

JSON mode emits one canonical object plus LF to stdout; diagnostics go to
stderr and contain no secret/raw argument values. Output files use
create-exclusive temporary writes and atomic install.
"""
import base64
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from os.path import dirname, exists, join, realpath

from . import (
    CharterError, canonical_bytes, cite as _cite, compile as _compile,
    diff as _diff, digest, evaluate as _evaluate, exit_code_for,
    parse_json_text, parse_yaml_subset, pin_for, retryable, sign_message,
    sign_bytes, verify_bundle as _verify_bundle, verify_evidence as _verify_evidence,
    verify_bytes,
)
from .core import ZERO_HASH
from .jcs import canonicalize, json_equal
from .schema import (
    v_audit_entry, v_auth_file, v_bundle, v_checkpoint, v_config,
    v_dispute_request, v_encryption_keys, v_heartbeat, v_manifest,
    v_pause_request, v_pin_command, v_policy, v_revoke_request, v_root_file,
    v_signed_pin, v_call_request,
)
from .errors import api_error
from .scalars import is_id, is_time, time_ms

VERSION = "0.1.0"
USAGE = """charter — LatticeAGI Charter zone core (charter/1)

Usage: charter [--config PATH] [--json] [--timeout-ms N] <command> ...

Commands:
  policy lint FILE --manifest FILE --root FILE [--predecessor FILE]...
  policy canonicalize FILE --out FILE
  policy diff OLD NEW --manifest FILE
  policy sign FILE --manifest FILE --key-id cky_* --key-ref env:NAME --out FILE
  policy bundle FILE --manifest FILE --root FILE --signature FILE... --out FILE [--predecessor FILE]...
  policy verify BUNDLE --root FILE [--predecessor FILE]... [--at TIME]
  policy publish BUNDLE --request-id crq_*
  policy versions [--after N] [--limit N]
  policy fetch VERSION --out FILE
  policy cite VERSION RULE_ID
  pin sign FILE --key-id cky_* --key-ref env:NAME --out FILE
  pin assemble FILE --root FILE --bundle FILE --signature FILE... --out FILE
  pin activate FILE
  gateway status
  gateway pause FILE
  gateway check FILE
  gateway call FILE
  gateway result crq_*
  revoke FILE --yes
  revocations list [--after-epoch N] [--limit N]
  dispute record FILE
  dispute list [--after-seq N] [--limit N]
  fleet heartbeat FILE
  fleet status [--watch-ms N]
  audit export --through-seq N --out FILE [--start-checkpoint FILE] [--inputs FILE]
  audit verify FILE --root FILE [--end-checkpoint FILE] [--replay]
  metrics
  config validate
  serve --local
  storage verify --backup FILE --end-checkpoint FILE --root FILE
"""


# ---------- argv / helpers ----------

class _Args:
    def __init__(self, argv):
        self.flags = {}
        self.pos = []
        self.argv = list(argv)
        i = 0
        while i < len(argv):
            a = argv[i]
            if a in ("--json", "--help", "--version", "--local", "--replay", "--yes"):
                self.flags[a[2:]] = True
            elif a.startswith("--"):
                if "=" in a:
                    k, v = a[2:].split("=", 1)
                    self.flags[k] = v
                elif i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    self.flags[a[2:]] = argv[i + 1]
                    i += 1
                else:
                    self.flags[a[2:]] = True
            else:
                self.pos.append(a)
            i += 1

    def str(self, name):
        v = self.flags.get(name)
        return v if isinstance(v, str) else None

    def str_req(self, name):
        v = self.str(name)
        if v is None:
            raise CharterError("SCHEMA", f"missing --{name}")
        return v

    def int_req(self, name):
        v = self.str_req(name)
        if not re.match(r"^[0-9]+$", v):
            raise CharterError("SCHEMA", f"bad --{name}")
        n = int(v)
        if n > 9007199254740991:
            raise CharterError("SCHEMA", f"bad --{name}")
        return n

    def int_opt(self, name, d):
        v = self.str(name)
        if v is None:
            return d
        if not re.match(r"^[0-9]+$", v):
            raise CharterError("SCHEMA", f"bad --{name}")
        return int(v)

    def str_all(self, name):
        out = []
        av = self.argv
        for i in range(len(av)):
            if av[i] == f"--{name}" and i + 1 < len(av):
                out.append(av[i + 1])
            elif av[i].startswith(f"--{name}="):
                out.append(av[i][len(name) + 3:])
        return out


def _pos_int(v, name):
    s = v if v is not None else _missing(name)
    if not re.match(r"^[0-9]+$", s):
        raise CharterError("SCHEMA", f"bad {name}")
    n = int(s)
    if n > 9007199254740991:
        raise CharterError("SCHEMA", f"bad {name}")
    return n


def _missing(name):
    raise CharterError("SCHEMA", f"missing {name}")


def _read_json_file(path):
    with open("/dev/stdin" if path == "-" else path, "r", encoding="utf-8") as f:
        return parse_json_text(f.read())


def _read_structured_file(path):
    with open("/dev/stdin" if path == "-" else path, "r", encoding="utf-8") as f:
        text = f.read()
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        return parse_json_text(text)
    return parse_yaml_subset(text)


def _write_out(path, text):
    """Atomic create-exclusive output write; existing path → SCHEMA (exit 2)."""
    if exists(path):
        raise CharterError("SCHEMA", f"output exists: {path}")
    d = dirname(realpath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".charter-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        if exists(path):
            raise CharterError("SCHEMA", f"output exists: {path}")
        os.link(tmp, path)  # atomic install of a nonexistent destination
        os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------- secret refs / config loading ----------

def _secret_ref(ref):
    if not ref.startswith("env:"):
        raise CharterError("SCHEMA", "secret ref must be env:NAME")
    v = os.environ.get(ref[4:])
    if v is None:
        raise CharterError("SCHEMA", f"secret ref {ref[4:]} unset")
    return v


def _json_from_secret(ref):
    raw = _secret_ref(ref)
    try:
        return parse_json_text(raw)
    except CharterError:
        try:
            return parse_json_text(base64.urlsafe_b64decode(raw).decode("utf-8"))
        except Exception:
            raise CharterError("SCHEMA", "secret ref does not decode to JSON")


_FIXTURE_PUBS = {
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
}
_FIXTURE_SEED_SET = {
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
}
_FIXTURE_ADAPTER_HASH = __import__("hashlib").sha256(b"charter-fixture-records/1").hexdigest()


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith(".json") or text.lstrip().startswith("{"):
        v = parse_json_text(text)
    else:
        v = parse_yaml_subset(text)
    return v_config(v, "$.config")


def load_tenant(config_path):
    config = load_config(config_path)
    d = dirname(realpath(config_path))
    root = v_root_file(parse_json_text(open(join(d, config["root_file"]), encoding="utf-8").read()), "$.root")
    manifest = v_manifest(parse_json_text(open(join(d, config["manifest_file"]), encoding="utf-8").read()), "$.manifest")
    auth = v_auth_file(_json_from_secret(config["auth_records_ref"]), "$.auth")
    enc_keys = v_encryption_keys(_json_from_secret(config["response_keys_ref"]), "$.keys")
    seed_raw = _secret_ref(config["audit_seed_ref"])
    audit_seed = base64.urlsafe_b64decode(seed_raw + "=" * (-len(seed_raw) % 4))
    if len(audit_seed) != 32 or base64.urlsafe_b64encode(audit_seed).rstrip(b"=").decode() != seed_raw:
        raise CharterError("SCHEMA", "audit seed must be canonical base64url of 32 bytes")
    if config["environment"] == "production":
        pubs = [k["public_key"] for k in root["bootstrap"]["keys"]] + \
               [k["public_key"] for k in root["audit_keys"]]
        if any(p in _FIXTURE_PUBS for p in pubs):
            raise CharterError("SCHEMA", "production config uses RFC 8032 fixture key material")
        if manifest["adapter_build_hash"] == _FIXTURE_ADAPTER_HASH:
            raise CharterError("SCHEMA", "production config pins the fixture adapter build")
        if audit_seed.hex() in _FIXTURE_SEED_SET:
            raise CharterError("SCHEMA", "production config uses a fixture audit seed")
    client_token = _secret_ref(config["client_credential_ref"])
    return {"config": config, "root": root, "manifest": manifest, "auth": auth,
            "encryption_keys": enc_keys, "audit_seed": audit_seed,
            "client_token": client_token}


# ---------- HTTP client ----------

class _HttpClient:
    def __init__(self, base, token, timeout_ms):
        self.base = base
        self.token = token
        self.timeout = timeout_ms / 1000.0

    def call(self, method, path, body, query=None):
        url = self.base + path
        if query:
            from urllib.parse import urlencode
            url += "?" + urlencode(query)
        data = None if body is None else canonicalize(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("content-type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                text = res.read().decode("utf-8")
                return {"status": res.status, "body": json.loads(text) if text else None}
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8")
            try:
                parsed = json.loads(text)
            except Exception:
                raise CharterError("PARSE", "non-JSON response")
            return {"status": e.code, "body": parsed}
        except urllib.error.URLError as e:
            if "timed out" in str(e.reason):
                raise CharterError("AUDIT_UNAVAILABLE", "request timeout")
            raise CharterError("AUDIT_UNAVAILABLE", "endpoint unreachable")
        except TimeoutError:
            raise CharterError("AUDIT_UNAVAILABLE", "request timeout")


def _ok(resp):
    if resp["status"] >= 400:
        err = (resp["body"] or {}).get("error", {})
        raise CharterError(err.get("code", "AUDIT_UNAVAILABLE"),
                           audit_seq=err.get("audit_seq"))
    return resp["body"]


def _sign_detached(key_ref, key_id, message):
    raw = _secret_ref(key_ref)
    seed = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(seed) != 32 or base64.urlsafe_b64encode(seed).rstrip(b"=").decode() != raw:
        raise CharterError("SCHEMA", "key seed must be canonical base64url of 32 bytes")
    return {"key_id": key_id,
            "signature": base64.urlsafe_b64encode(sign_bytes(message, seed)).rstrip(b"=").decode()}


def _warnings(policy, at_ms):
    w = set()
    if len(policy["scope_rules"]) == 0:
        w.add("NO_ALLOW_RULES")
    if policy["next_authority"]["threshold"] == 1:
        w.add("SINGLE_SIGNER")
    if time_ms(policy["not_after"]) - at_ms <= 86_400_000:
        w.add("EXPIRY_WITHIN_24H")
    return sorted(w)


def _lint_lineage(policy, root, preds):
    if policy["tenant_id"] != root["tenant_id"] or policy["charter_id"] != root["charter_id"]:
        raise CharterError("SCHEMA", "policy identity mismatch vs root")
    if policy["version"] == 1:
        if policy["previous_hash"] is not None:
            raise CharterError("SCHEMA", "version 1 must have previous_hash null")
        return
    prev = next((b for b in preds if b["policy"]["version"] == policy["version"] - 1), None)
    if prev is None:
        raise CharterError("VERSION_CONFLICT", "missing predecessor")
    if policy["previous_hash"] != digest("policy", prev["policy"]):
        raise CharterError("HASH_MISMATCH", "previous_hash does not bind predecessor")


def _v_detached_file(v):
    if not isinstance(v, dict) or not is_id(v.get("key_id"), "cky") \
            or not isinstance(v.get("signature"), str):
        raise CharterError("SCHEMA", "bad Detached file")
    return {"key_id": v["key_id"], "signature": v["signature"]}


def _evidence_from_ndjson(text):
    if not text.endswith("\n"):
        raise CharterError("SCHEMA", "stream must end with LF")
    lines = text[:-1].split("\n")
    root = start = end = None
    bundles, controls, entries, inputs = [], [], [], []
    saw_trailer = False
    for line in lines:
        rec = parse_json_text(line)
        r = rec.get("record")
        if r == "header":
            root, start, end = rec["root"], rec["start"], rec["end"]
        elif r == "bundle":
            bundles.append(rec["bundle"])
        elif r == "control":
            controls.append(rec["control"])
        elif r == "entry":
            entries.append(v_audit_entry(rec["entry"], "$.entry"))
        elif r == "input":
            inputs.append(rec["input"])
        elif r == "trailer":
            if saw_trailer:
                raise CharterError("SCHEMA", "duplicate trailer")
            saw_trailer = True
        else:
            raise CharterError("SCHEMA", "unknown stream record")
    if root is None or end is None or not saw_trailer:
        raise CharterError("SCHEMA", "incomplete stream")
    return {"schema": "charter.evidence/1", "root": root, "bundles": bundles,
            "start": start, "entries": entries, "controls": controls,
            "end": end, "inputs": inputs}


def _verify_exit(v):
    if v["integrity"] == "INVALID":
        return 4
    if v["integrity"] == "INCOMPLETE":
        return 8
    if v["replay"] == "MISMATCH":
        return 4
    if v["replay"] in ("INPUTS_MISSING", "CONTEXT_MISSING"):
        return 8
    return 0


def _check_exit(body):
    d = (body or {}).get("decision")
    return 3 if d and d.get("verdict") == "DENY" else 0


def _call_exit(body):
    state = (body or {}).get("state")
    return {"SUCCEEDED": 0, "DENIED": 3, "FAILED": 9, "NOT_SENT": 9,
            "COMMITTED": 8, "INDETERMINATE": 8}.get(state, 0)


def _fleet_exit(body):
    s = (body or {}).get("status")
    return 3 if s in ("EMPTY", "MISSING", "SPLIT") else 0


def _storage_verify(backup_path, end_cp, root):
    import sqlite3
    con = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    try:
        ic = con.execute("PRAGMA integrity_check").fetchone()
        if not ic or ic[0] != "ok":
            raise CharterError("AUDIT_UNAVAILABLE", "sqlite integrity_check failed")
        meta = con.execute(
            "SELECT storage_version,head_hash,next_seq,root_hash FROM meta WHERE singleton=1").fetchone()
        if not meta or meta[0] != 1:
            raise CharterError("UNSUPPORTED_VERSION", "storage_version != 1")
        if meta[3] != __import__("hashlib").sha256(canonical_bytes(root)).hexdigest():
            raise CharterError("HASH_MISMATCH", "store root does not match --root")
        rows = con.execute(
            "SELECT seq,hash,body_jcs,key_id,signature FROM audit ORDER BY seq").fetchall()
        prev = ZERO_HASH
        expect = 1
        for seq, h, body_jcs, key_id, signature in rows:
            body = json.loads(body_jcs)
            if seq != expect or h != digest("audit", body) or body["prev_hash"] != prev:
                raise CharterError("AUDIT_UNAVAILABLE", "audit chain broken")
            expect += 1
            key = next((k for k in root["audit_keys"]
                        if k["from_seq"] <= seq
                        and (k["through_seq"] is None or seq <= k["through_seq"])), None)
            if key is None or key["key_id"] != key_id or not verify_bytes(
                    sign_message("audit", body),
                    base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                    bytes.fromhex(key["public_key"])):
                raise CharterError("SIGNATURE_INVALID", "audit signature")
            prev = h
        through = len(rows)
        key = next((k for k in root["audit_keys"]
                    if k["from_seq"] <= end_cp["body"]["through_seq"]
                    and (k["through_seq"] is None
                         or end_cp["body"]["through_seq"] <= k["through_seq"])), None)
        if key is None or key["key_id"] != end_cp["key_id"] or not verify_bytes(
                sign_message("checkpoint", end_cp["body"]),
                base64.urlsafe_b64decode(end_cp["signature"] + "=" * (-len(end_cp["signature"]) % 4)),
                bytes.fromhex(key["public_key"])):
            raise CharterError("SIGNATURE_INVALID", "end checkpoint")
        if end_cp["body"]["through_seq"] != through or end_cp["body"]["head_hash"] != prev:
            raise CharterError("HASH_MISMATCH", "checkpoint does not match store head")
        return {"valid": True, "storage_version": 1, "through_seq": through}
    finally:
        con.close()


# ---------- dispatch ----------

def _dispatch(cmd, a, ctx):
    def need_client():
        loaded = load_tenant(ctx["config_path"])
        ep = loaded["config"]["endpoint"]
        if not re.match(r"^https?://", ep):
            raise CharterError("SCHEMA", "endpoint must be an http(s) origin")
        return _HttpClient(ep.rstrip("/"), loaded["client_token"], ctx["timeout_ms"]), loaded

    def predecessors():
        return [v_bundle(_read_json_file(f), "$.predecessor") for f in a.str_all("predecessor")]

    if cmd == "policy lint":
        policy = v_policy(_read_structured_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.policy")
        manifest = v_manifest(_read_structured_file(a.str_req("manifest")), "$.manifest")
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        _lint_lineage(policy, root, predecessors())
        _compile(policy, manifest)
        import time as _t
        return {"valid": True, "policy_hash": digest("policy", policy),
                "manifest_hash": digest("manifest", manifest),
                "warnings": _warnings(policy, int(_t.time() * 1000))}, 0
    if cmd == "policy canonicalize":
        policy = v_policy(_read_structured_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.policy")
        text = canonicalize(policy)
        o = a.str_req("out")
        _write_out(o, text)
        return {"policy_hash": digest("policy", policy), "bytes": len(text.encode("utf-8")), "out": o}, 0
    if cmd == "policy diff":
        old_p = v_policy(_read_structured_file(a.pos[1] if len(a.pos) > 1 else _missing("OLD")), "$.old")
        new_p = v_policy(_read_structured_file(a.pos[2] if len(a.pos) > 2 else _missing("NEW")), "$.new")
        manifest = v_manifest(_read_structured_file(a.str_req("manifest")), "$.manifest")
        _compile(old_p, manifest)
        _compile(new_p, manifest)
        return _diff(old_p, new_p), 0
    if cmd == "policy sign":
        policy = v_policy(_read_structured_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.policy")
        manifest = v_manifest(_read_structured_file(a.str_req("manifest")), "$.manifest")
        _compile(policy, manifest)
        key_id = a.str_req("key-id")
        det = _sign_detached(a.str_req("key-ref"), key_id, sign_message("policy", policy))
        o = a.str_req("out")
        _write_out(o, canonicalize(det))
        return {"policy_hash": digest("policy", policy), "key_id": key_id, "out": o}, 0
    if cmd == "policy bundle":
        policy = v_policy(_read_structured_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.policy")
        manifest = v_manifest(_read_structured_file(a.str_req("manifest")), "$.manifest")
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        sigs = [_v_detached_file(_read_json_file(f)) for f in a.str_all("signature")]
        bundle = {"policy": policy, "manifest": manifest, "signatures": sigs}
        _verify_bundle(bundle, root, predecessors())
        o = a.str_req("out")
        _write_out(o, canonicalize(bundle))
        return {"pin": pin_for(bundle), "signatures": len(sigs), "out": o}, 0
    if cmd == "policy verify":
        bundle = v_bundle(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("BUNDLE")), "$.bundle")
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        return _verify_bundle(bundle, root, predecessors(), a.str("at")), 0
    if cmd == "policy publish":
        client, _ = need_client()
        bundle = v_bundle(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("BUNDLE")), "$.bundle")
        return _ok(client.call("POST", "/v1/charters",
                               {"request_id": a.str_req("request-id"), "bundle": bundle})), 0
    if cmd == "policy versions":
        client, _ = need_client()
        return _ok(client.call("GET", "/v1/charters", None,
                               {"after": str(a.int_opt("after", 0)),
                                "limit": str(a.int_opt("limit", 100))})), 0
    if cmd == "policy fetch":
        client, _ = need_client()
        version = _pos_int(a.pos[1] if len(a.pos) > 1 else None, "VERSION")
        body = _ok(client.call("GET", f"/v1/charters/{version}", None))
        bundle = v_bundle(body, "$.bundle")
        loaded = load_tenant(ctx["config_path"])
        preds = [v_bundle(_ok(client.call("GET", f"/v1/charters/{v}", None)), "$.predecessor")
                 for v in range(1, bundle["policy"]["version"])]
        _verify_bundle(bundle, loaded["root"], preds)
        o = a.str_req("out")
        _write_out(o, canonicalize(bundle))
        return {"pin": pin_for(bundle), "out": o}, 0
    if cmd == "policy cite":
        client, _ = need_client()
        version = _pos_int(a.pos[1] if len(a.pos) > 1 else None, "VERSION")
        rule_id = a.pos[2] if len(a.pos) > 2 else _missing("RULE_ID")
        body = _ok(client.call("GET", f"/v1/charters/{version}", None))
        bundle = v_bundle(body, "$.bundle")
        loaded = load_tenant(ctx["config_path"])
        preds = [v_bundle(_ok(client.call("GET", f"/v1/charters/{v}", None)), "$.predecessor")
                 for v in range(1, version)]
        _verify_bundle(bundle, loaded["root"], preds)
        return _cite(bundle, rule_id), 0
    if cmd == "pin sign":
        command = v_pin_command(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.command")
        key_id = a.str_req("key-id")
        det = _sign_detached(a.str_req("key-ref"), key_id, sign_message("pin", command))
        o = a.str_req("out")
        _write_out(o, canonicalize({"command": command, "signature": det}))
        return {"pin": command["target"], "key_id": key_id, "out": o}, 0
    if cmd == "pin assemble":
        command = v_pin_command(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.command")
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        bundle = v_bundle(_read_json_file(a.str_req("bundle")), "$.bundle")
        _verify_bundle(bundle, root, predecessors())
        if digest("policy", bundle["policy"]) != command["authority_policy_hash"]:
            raise CharterError("HASH_MISMATCH", "command authority is not --bundle policy")
        sigs = []
        for f in a.str_all("signature"):
            sf = _read_json_file(f)
            if not json_equal(sf.get("command"), command):
                raise CharterError("SCHEMA", "signature file command differs")
            sigs.append(_v_detached_file(sf.get("signature")))
        if not sigs:
            raise CharterError("QUORUM", "no signature files")
        authority = bundle["policy"]["next_authority"]
        seen = set()
        for s in sigs:
            if s["key_id"] in seen:
                raise CharterError("SIGNATURE_DUPLICATE")
            seen.add(s["key_id"])
            key = next((k for k in authority["keys"] if k["key_id"] == s["key_id"]), None)
            if key is None:
                raise CharterError("KEY_UNKNOWN")
            sig = base64.urlsafe_b64decode(s["signature"] + "=" * (-len(s["signature"]) % 4))
            if not verify_bytes(sign_message("pin", command), sig, bytes.fromhex(key["public_key"])):
                raise CharterError("SIGNATURE_INVALID")
        o = a.str_req("out")
        _write_out(o, canonicalize({"command": command, "signatures": sigs}))
        return {"pin": command["target"], "signatures": len(sigs), "out": o}, 0
    if cmd == "pin activate":
        client, _ = need_client()
        sp = v_signed_pin(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.pin")
        return _ok(client.call("POST", "/v1/deployment/pin", sp)), 0
    if cmd == "gateway status":
        client, _ = need_client()
        deployment = client.call("GET", "/v1/deployment", None)
        ready = client.call("GET", "/v1/readyz", None)
        return {"deployment": deployment["body"] if deployment["status"] < 400 else None,
                "readiness": ready["body"]}, 0
    if cmd == "gateway pause":
        client, _ = need_client()
        body = v_pause_request(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.pause")
        return _ok(client.call("POST", "/v1/deployment/pause", body)), 0
    if cmd == "gateway check":
        client, _ = need_client()
        req = v_call_request(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.request")
        body = _ok(client.call("POST", "/v1/gateway/check", req))
        return body, _check_exit(body)
    if cmd == "gateway call":
        client, _ = need_client()
        req = v_call_request(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.request")
        try:
            body = _ok(client.call("POST", "/v1/gateway/call", req))
            return body, _call_exit(body)
        except CharterError as e:
            if e.code == "AUDIT_UNAVAILABLE" and e.detail == "request timeout":
                return {"error": {"code": "AUDIT_UNAVAILABLE", "retryable": True, "audit_seq": None},
                        "request_id": req["request_id"]}, 8
            raise
    if cmd == "gateway result":
        client, _ = need_client()
        rid = a.pos[1] if len(a.pos) > 1 else _missing("ID")
        if not is_id(rid, "crq"):
            raise CharterError("SCHEMA", "bad request id")
        body = _ok(client.call("GET", f"/v1/gateway/calls/{rid}", None))
        return body, _call_exit(body)
    if cmd == "revoke":
        client, _ = need_client()
        body = v_revoke_request(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.revoke")
        if not a.flags.get("yes") and not sys.stdin.isatty():
            raise CharterError("SCHEMA", "noninteractive revoke requires --yes")
        return _ok(client.call("POST", "/v1/revocations", body)), 0
    if cmd == "revocations list":
        client, _ = need_client()
        return _ok(client.call("GET", "/v1/revocations", None,
                               {"after_epoch": str(a.int_opt("after-epoch", 0)),
                                "limit": str(a.int_opt("limit", 100))})), 0
    if cmd == "dispute record":
        client, _ = need_client()
        req = v_dispute_request(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.request")
        return _ok(client.call("POST", "/v1/disputes", req)), 0
    if cmd == "dispute list":
        client, _ = need_client()
        return _ok(client.call("GET", "/v1/disputes", None,
                               {"after_seq": str(a.int_opt("after-seq", 0)),
                                "limit": str(a.int_opt("limit", 100))})), 0
    if cmd == "fleet heartbeat":
        client, _ = need_client()
        req = v_heartbeat(_read_json_file(a.pos[1] if len(a.pos) > 1 else _missing("FILE")), "$.request")
        return _ok(client.call("POST", "/v1/fleet/heartbeat", req)), 0
    if cmd == "fleet status":
        client, _ = need_client()
        watch_ms = a.int_opt("watch-ms", 0)
        if watch_ms != 0 and (watch_ms < 1000 or watch_ms > 60_000):
            raise CharterError("SCHEMA", "bad --watch-ms")
        body = _ok(client.call("GET", "/v1/fleet", None))
        if watch_ms == 0:
            return body, _fleet_exit(body)
        sys.stdout.write(canonicalize(body) + "\n")
        import time as _t
        while True:
            _t.sleep(watch_ms / 1000.0)
            sys.stdout.write(canonicalize(_ok(client.call("GET", "/v1/fleet", None))) + "\n")
            sys.stdout.flush()
    if cmd == "audit export":
        client, loaded = need_client()
        through = a.int_req("through-seq")
        o = a.str_req("out")
        start_cp = v_checkpoint(_read_json_file(a.str("start-checkpoint")), "$.start") \
            if a.str("start-checkpoint") else None
        inputs = _read_json_file(a.str("inputs")) if a.str("inputs") else []
        entries, controls = [], []
        after = 0 if start_cp is None else start_cp["body"]["through_seq"]
        while True:
            page = _ok(client.call("GET", "/v1/audit", None,
                                   {"after_seq": str(after), "through_seq": str(through), "limit": "100"}))
            entries += page["entries"]
            controls += page["controls"]
            if page["next_after"] is None:
                break
            after = page["next_after"]
        end = v_checkpoint(_ok(client.call("GET", f"/v1/audit/checkpoint?through_seq={through}", None)), "$.end")
        versions = _ok(client.call("GET", "/v1/charters", None, {"after": "0", "limit": "100"}))
        bundles = [v_bundle(_ok(client.call("GET", f"/v1/charters/{v['version']}", None)), "$.bundle")
                   for v in versions["versions"]]
        lines = [canonicalize({"record": "header", "schema": "charter.stream/1",
                               "root": loaded["root"], "start": start_cp, "end": end})]
        lines += [canonicalize({"record": "bundle", "bundle": b}) for b in bundles]
        lines += [canonicalize({"record": "control", "control": c}) for c in controls]
        lines += [canonicalize({"record": "entry", "entry": e}) for e in entries]
        lines += [canonicalize({"record": "input", "input": i}) for i in inputs]
        lines.append(canonicalize({"record": "trailer", "bundles": len(bundles),
                                   "controls": len(controls), "entries": len(entries),
                                   "inputs": len(inputs), "through_seq": through}))
        _write_out(o, "\n".join(lines) + "\n")
        return {"through_seq": through, "entries": len(entries), "out": o}, 0
    if cmd == "audit verify":
        with open(a.pos[1] if len(a.pos) > 1 else _missing("FILE"), encoding="utf-8") as f:
            ev = _evidence_from_ndjson(f.read())
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        ec = a.str("end-checkpoint")
        end_cp = v_checkpoint(_read_json_file(ec), "$.end_checkpoint") if ec else None
        v = _verify_evidence(ev, root, end_cp, bool(a.flags.get("replay")))
        return v, _verify_exit(v)
    if cmd == "metrics":
        client, _ = need_client()
        return _ok(client.call("GET", "/v1/metrics", None)), 0
    if cmd == "config validate":
        loaded = load_tenant(ctx["config_path"])
        return {"valid": True, "manifest_hash": digest("manifest", loaded["manifest"]),
                "instance_count": len(loaded["config"]["instance_inventory"])}, 0
    if cmd == "serve --local":
        # The local engine is the TypeScript implementation; the Python package
        # is the offline verifier/CLI only. Delegating would be a second engine.
        sys.stderr.write("serve --local requires the TypeScript engine: use `charter serve --local`\n")
        raise CharterError("SCHEMA", "python entry cannot host the engine")
    if cmd == "storage verify":
        backup = a.str_req("backup")
        end_cp = v_checkpoint(_read_json_file(a.str_req("end-checkpoint")), "$.end_checkpoint")
        root = v_root_file(_read_json_file(a.str_req("root")), "$.root")
        return _storage_verify(backup, end_cp, root), 0
    raise CharterError("SCHEMA", f"unknown command: {cmd}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    a = _Args(argv)
    if a.flags.get("version"):
        sys.stdout.write(canonicalize({"version": VERSION, "engine": "charter.eval/1",
                                       "api": "charter.http/1"}) + "\n")
        return 0
    if a.flags.get("help") or not a.pos:
        sys.stderr.write(USAGE)
        return 2 if not a.pos and not a.flags.get("help") else 0
    timeout_ms = a.int_opt("timeout-ms", 10_000)
    if timeout_ms < 1 or timeout_ms > 60_000:
        sys.stdout.write(canonicalize({"error": {"code": "SCHEMA", "retryable": False,
                                                 "audit_seq": None}}) + "\n")
        return 2
    config_path = a.str("config") or "./charter.yaml"
    w0 = a.pos[0] if a.pos else ""
    groups = {"policy", "pin", "gateway", "revocations", "dispute", "fleet",
              "audit", "config", "storage"}
    if w0 == "serve":
        cmd = "serve --local" if a.flags.get("local") else "serve"
    elif w0 in groups and len(a.pos) > 1:
        cmd = f"{w0} {a.pos[1]}"
        a.pos.pop(0)
    else:
        cmd = w0
    try:
        body, code = _dispatch(cmd, a, {"config_path": config_path, "timeout_ms": timeout_ms})
        sys.stdout.write(canonicalize(body) + "\n")
        return code
    except CharterError as e:
        sys.stdout.write(canonicalize(api_error(e.code, e.audit_seq)) + "\n")
        return exit_code_for(e.code)
    except Exception:
        sys.stdout.write(canonicalize(api_error("AUDIT_UNAVAILABLE")) + "\n")
        return 7


if __name__ == "__main__":
    sys.exit(main())
