"""Python-side conformance check: run the §11.1 fixed corpus through
latticeagi_charter and emit canonical JSON of every result. The TS harness
compares each field against the corpus oracles."""
import json
import sys
from os.path import dirname, join

sys.path.insert(0, dirname(dirname(__file__)))
import latticeagi_charter as lc  # noqa: E402


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        fx = json.load(f)
    out = {}

    # parsePolicy over canonical bytes must round-trip C1.
    out["parse_policy"] = lc.parse_policy(lc.canonicalize(fx["C1"]), "json")
    out["canonicalize_C1"] = lc.canonicalize(fx["C1"]).decode("utf-8")
    out["digest_policy_C1"] = lc.digest("policy", fx["C1"])
    out["digest_manifest_M1"] = lc.digest("manifest", fx["M1"])
    out["verify_bundle_B1"] = lc.verify_bundle(fx["B1"], fx["ROOT"], [])
    out["compile"] = lc.compile(fx["C1"], fx["M1"])
    out["evaluate_EI1"] = lc.evaluate(fx["EI1"])
    out["cite"] = lc.cite(fx["B1"], fx["RA"])
    out["diff_same"] = lc.diff(fx["C1"], fx["C1"])
    out["sign_policy_fixture0"] = lc.sign("policy", fx["C1"], fx["KA"], "fixture:0")
    out["verify_evidence_EV1"] = lc.verify_evidence(fx["EV1"], fx["ROOT"], fx["CP1"], True)
    # RFC 8032 test vector 1 — empty message.
    sig = lc.sign  # keep lint quiet; direct ed25519 check below
    from latticeagi_charter.ed25519 import public_key_from_seed, sign_bytes
    pub = public_key_from_seed(bytes.fromhex(fx["SEEDS"][0]))
    out["pub0"] = pub.hex()
    out["sig_empty"] = sign_bytes(b"", bytes.fromhex(fx["SEEDS"][0])).hex()

    sys.stdout.write(lc.jcs.canonicalize(out) + "\n")


if __name__ == "__main__":
    main()
