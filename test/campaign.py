"""§11.3 adversarial campaigns — Python side. Deterministic seeded generator;
each case contributes one tagged result line to a rolling SHA-256.
Usage: python3 test/campaign.py <canon|parse|eval> <count> [fixtureJson]"""
import hashlib
import json
import os
import sys
import unicodedata
from os.path import dirname

sys.path.insert(0, dirname(dirname(__file__)))
from latticeagi_charter import CharterError  # noqa: E402
from latticeagi_charter.core import evaluate  # noqa: E402
from latticeagi_charter.jcs import canonicalize  # noqa: E402
from latticeagi_charter.strict_json import parse_json_text  # noqa: E402


class Rng:
    """Identical stream to the TS campaign: sha256('charter.campaign/1\nseed/i/j')."""

    def __init__(self, seed, index):
        self.seed = seed
        self.index = index
        self.block = 0
        self.buf = b""
        self.off = 0

    def byte(self):
        if self.off >= len(self.buf):
            self.buf = hashlib.sha256(
                f"charter.campaign/1\n{self.seed}/{self.index}/{self.block}".encode()).digest()
            self.block += 1
            self.off = 0
        b = self.buf[self.off]
        self.off += 1
        return b

    def int(self, n):
        v = 0
        for _ in range(n):
            v = (v << 8) | self.byte()
        return v

    def pick(self, arr):
        return arr[self.byte() % len(arr)]


KEY_POOL = ["a", "b", "z", "aa", "k1", "x_y", "A", "é", "中", "q9", "k-2", "zz"]
STR_POOL = ["", "a", "hello", 'x"y', "back\\slash", "nl\n", "tab\t", "é", "中文字",
            unicodedata.normalize("NFC", "ś"), "ctrl", "z", "snowman ☃", "0", "-0", "1e3"]


def gen_value(r, depth):
    t = r.byte() % 10
    if depth >= 4:
        l = r.byte() % 4
        if l == 0:
            return r.pick(STR_POOL)
        if l == 1:
            return r.int(4) % 9007199254740991
        if l == 2:
            return r.byte() % 2 == 0
        return None
    if t <= 2:
        n = r.byte() % 5
        o = {}
        used = set()
        for _ in range(n):
            k = r.pick(KEY_POOL) + (str(r.byte() % 8) if r.byte() % 4 == 0 else "")
            if k in used:
                continue
            used.add(k)
            o[k] = gen_value(r, depth + 1)
        return o
    if t <= 4:
        return [gen_value(r, depth + 1) for _ in range(r.byte() % 4)]
    if t <= 6:
        return r.pick(STR_POOL)
    if t <= 8:
        return r.int(5) % 9007199254740991
    return None if r.byte() % 3 == 0 else (r.byte() % 2 == 0)


def _malformed(r):
    i = r.byte() % 28
    fixed = [
        '{"a":1,"a":2}', '[1,2,]', '{"x":01}', '{"x":1e3}', '{"x":-1}',
        '{"x":9007199254740992}', '"lone\\ud800"', '"lone\\udc00"',
        '{"a":"bad\\x"}', '{"a":"rawctrl"}', 'tru', '{"a" 1}',
        '{"a":1} trailing', '\ufeff{"a":1}', '[' + '1,' * 130 + '1]',
        '{' + ",".join(f'"k{j}":0' for j in range(257)) + '}',
        '[' * 17 + ']' * 17,
        unicodedata.normalize("NFD", '{"s":"é"}'),
        unicodedata.normalize("NFD", '{"é":0}'),
        '{"a":}', '', '   ', '"unterminated', '{"a":+1}', '{a:1}',
        '"ok" ', '{"k":[0,{"m":true}]}',
    ]
    if i < len(fixed):
        return fixed[i]
    return canonicalize(gen_value(r, 0))[:-1]


def gen_eval_input(r, fx):
    tools = ["record.get", "record.put", "record.delete", "record.list", "record.export", "unknown.tool"]
    scopes = ["task-a", "task-b", "other"]
    resources = ["records/a", "records/b", "records", "other/x", "records/a/b"]
    deadline = [fx["T30"], fx["T0"], fx["T180"], fx["END"]][r.byte() % 4]
    now = [fx["T0"], fx["T30"], fx["END"]][r.byte() % 3]
    tool = r.pick(tools)
    args = {}
    if tool == "record.put":
        args["value"] = r.pick(STR_POOL)[:16]
    if tool == "record.list":
        args["limit"] = r.byte() % 120 if r.byte() % 3 == 0 else r.byte() % 101
    if tool == "record.export":
        args["destination"] = r.pick(STR_POOL)[:70]
    if r.byte() % 5 == 0:
        args["extra"] = r.byte()
    req = {
        "request_id": "crq_" + "Q" * 21,
        "pin": fx["P2"] if r.byte() % 4 == 0 else fx["P1"],
        "scope": r.pick(scopes), "tool": tool, "resource": r.pick(resources),
        "args": args, "deadline": deadline,
    }
    principal = {
        "principal_id": fx["O"] if r.byte() % 8 == 0 else fx["A"],
        "credential_id": fx["CR"], "instance_id": fx["I"],
        "scopes": ["task-b"] if r.byte() % 4 == 0 else ["task-a"],
    }
    return {
        "policy": fx["C1"], "manifest": fx["M1"], "active_pin": fx["P1"],
        "request": req, "principal": principal, "now": now,
        "policy_revoked": r.byte() % 16 == 0,
        "policy_signatures_valid": r.byte() % 16 != 1,
    }


def main():
    mode, count = sys.argv[1], int(sys.argv[2])
    roll = hashlib.sha256()
    dump = os.environ.get("CHARTER_DUMP") == "1"

    def emit(line):
        roll.update((line + "\n").encode())
        if dump:
            print(line)

    if mode == "canon":
        for i in range(count):
            r = Rng("canon", i)
            try:
                h = hashlib.sha256(canonicalize(gen_value(r, 0)).encode()).hexdigest()
                emit(f"{i}:ok:{h}")
            except CharterError as e:
                emit(f"{i}:err:{e.code}")
    elif mode == "parse":
        for i in range(count):
            r = Rng("parse", i)
            text = _malformed(r)
            try:
                h = hashlib.sha256(canonicalize(parse_json_text(text)).encode()).hexdigest()
                emit(f"{i}:ok:{h}")
            except CharterError as e:
                emit(f"{i}:err:{e.code}")
    elif mode == "eval":
        with open(sys.argv[3] if len(sys.argv) > 3 else "/tmp/charter-fixtures.json") as f:
            fx = json.load(f)
        for i in range(count):
            r = Rng("eval", i)
            try:
                d = evaluate(gen_eval_input(r, fx))
                h = hashlib.sha256(canonicalize(d).encode()).hexdigest()
                emit(f"{i}:ok:{h}")
            except CharterError as e:
                emit(f"{i}:err:{e.code}")
    else:
        sys.stderr.write("usage: campaign.py <canon|parse|eval> <count> [fixtureJson]\n")
        sys.exit(2)
    print(f"{mode} {count} sha256:{roll.hexdigest()}")


if __name__ == "__main__":
    main()
