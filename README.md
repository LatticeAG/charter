# Charter

[![status](https://img.shields.io/badge/status-unwritten%2C%20gated%20behind%20Covenant%20v1-orange)](https://github.com/LatticeAG/charter)
[![protocol](https://img.shields.io/badge/protocol-charter%2F1-blue)](https://github.com/LatticeAG/charter)
[![engine](https://img.shields.io/badge/engine-charter.eval%2F1-blue)](https://github.com/LatticeAG/charter)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![ci](https://img.shields.io/badge/ci-node--test%20%2B%20tsc-brightgreen)](./.github/workflows/ci.yml)

**Governance is written, hashed, and revocable. Rules agents can cite, not vibes.**

Charter is the LatticeAGI governance zone core: a versioned, Ed25519-signed policy
format (`charter.policy/1`), a deterministic evaluator (`charter.eval/1`), a
gateway that admits or denies agent tool calls (`record.get/put/delete/list/export`
over the `RECORDS` binding), an immutable signed audit stream with checkpoints,
advisory disputes, fleet freshness observation, and an offline evidence verifier.

> Status: **Unwritten — gated behind Covenant v1.** This repository is the
> MIT-licensed core implementation of the charter/1 contract. It is not a live
> product claim, and it does not authorize deployment or a LIVE badge.

## What's in the box

| Surface | Status |
|---|---|
| Strict JSON parser (charter/1 scalar grammar) + RFC 8785 canonicalizer | Implemented |
| YAML 1.2 JSON-subset parser (policy/config source) | Implemented |
| Policy compiler + deterministic evaluator | Implemented |
| Bundle signing/verification, pin commands, citations, policy diff | Implemented |
| Tenant engine: publication, pin CAS, pause, revocations, fleet, audit, checkpoints | Implemented (local SQLite profile) |
| Gateway admission: durable marker, at-most-one initiation, NOT_SENT/INDETERMINATE honesty | Implemented |
| `charter` CLI (all §4 verbs) + `serve --local` loopback emulator | Implemented |
| Offline evidence export/verify (`charter.stream/1`, `charter.proof-link/1`) | Implemented |
| Python verifier `python -m latticeagi_charter` | Implemented |
| Cloudflare Worker/`CharterTenantDO` hosted deploy | Stub — `NotImplemented` (hosted surface) |
| Production `RECORDS` adapter (real upstream) | Stub — `NotImplemented` (requires certified upstream) |
| Hosted registry operations | Stub — `NotImplemented` (paid/hosted surface) |

## Install / run

Requires Node.js ≥ 22.18 (native type stripping, `node:sqlite`, `node:test`).

```sh
npm install        # dev deps only (typescript, @types/node)
npm test           # full conformance + unit suite
npm run typecheck
./bin/charter --help
```

Python verifier (no third-party deps):

```sh
cd python && python3 -m latticeagi_charter --help
```

## Quick start (local emulator)

```sh
# 1. Write a config (see examples/charter.local.yaml) and provision env secrets:
export CHARTER_CLIENT_CREDENTIAL=<base64url-32-byte-bearer>
export CHARTER_AUTH_RECORDS=<base64url J(auth-file)>
export CHARTER_AUDIT_SEED=<base64url-32-byte-ed25519-seed>
export CHARTER_RESPONSE_KEYS=<base64url J(encryption-keys)>

# 2. Boot the loopback emulator
./bin/charter serve --local --config ./charter.yaml --json

# 3. Lint, sign, bundle, publish, pin, call
./bin/charter policy lint policy.yaml --manifest manifest.json --root trust.json
./bin/charter policy sign policy.yaml --manifest manifest.json --key-id cky_... --key-ref env:POLICY_SEED_A --out sig-a.json
./bin/charter policy bundle policy.yaml --manifest manifest.json --signature sig-a.json --signature sig-b.json --root trust.json --out bundle.json
./bin/charter policy publish bundle.json --request-id crq_... --json
./bin/charter pin sign pin-command.json --key-id cky_... --key-ref env:POLICY_SEED_A --out pin-sig-a.json
./bin/charter pin assemble pin-command.json --signature pin-sig-a.json --signature pin-sig-b.json --root trust.json --bundle bundle.json --out signed-pin.json
./bin/charter pin activate signed-pin.json --json
./bin/charter gateway check request.json --json
./bin/charter gateway call request.json --json
./bin/charter audit export --through-seq 5 --out evidence.jsonl
./bin/charter audit verify evidence.jsonl --root trust.json --replay --json
```

## Threat model and honesty contract

Charter admits at most one upstream initiation per request ID, never re-sends a
committed call, reports `INDETERMINATE` rather than guessing, never fabricates a
rule for a default deny (`default-deny/1` invariant is cited instead), and treats
`/check` as permanently non-authoritative (`enforcement:false`). Revocation is
prospective: it blocks later admissions at that logical gateway and never rewrites
history. See `docs/` and the conformance suite (`test/vectors.test.ts`, 66
spec-pinned vectors) for the exact contract.

## Layout

```
src/json        strict parser + J canonicalizer
src/yaml        YAML 1.2 JSON-subset parser
src/crypto      LAGI-CHARTER digests, Ed25519 strict verify
src/schema      closed-schema validators (all wire types)
src/core        compile / evaluate / cite / diff / verifyBundle / verifyEvidence
src/engine      tenant engine: storage, audit, admission, fleet, encryption
src/http        loopback server implementing the 22-route surface
src/adapter     RECORDS binding + fixture adapter (test only)
src/cli         charter CLI
src/hosted      hosted/deploy stubs (NotImplemented)
python/         latticeagi_charter pure-function verifier + module CLI
fixtures/       executable conformance corpus (public RFC 8032 test material)
test/           node:test suite (66 vectors + unit coverage)
```

## License

MIT — see [LICENSE](./LICENSE).
