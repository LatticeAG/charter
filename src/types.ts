/** charter/1 wire types — normative schemas from CHARTER §§1.3–1.5, 5, 9. */
import type { ErrorCode } from "./errors.ts";

export type Int = number;
export type Hash = string;
export type Public = string;
export type Signature = string;
export type Time = string;
export type Label = string;
export type ToolName = string;
export type Resource = string;
export type ID<P extends string> = `${P}_${string}`;
export type TenantId = ID<"cte">;
export type CharterId = ID<"cch">;
export type GatewayId = ID<"cgw">;
export type InstanceId = ID<"cin">;
export type PrincipalId = ID<"cpr">;
export type KeyId = ID<"cky">;
export type CredentialId = ID<"ccr">;
export type RequestId = ID<"crq">;
export type RuleId = ID<"crl">;
export type DisputeId = ID<"cds">;
export type LogId = ID<"clg">;
export type Scalar = string | Int | boolean;
export type Json = null | Scalar | Json[] | { [key: string]: Json };

export type Key = { key_id: KeyId; public_key: Public };
export type Authority = { threshold: Int; keys: Key[] };
export type Detached = { key_id: KeyId; signature: Signature };
export type Source = { repository: string; pull_request: Int; commit: string };
export type Selector =
  | { match: "exact" | "segment_prefix"; value: Resource }
  | { match: "all" };
export type Predicate =
  | { arg: Label; op: "eq"; value: Scalar }
  | { arg: Label; op: "int_lte"; value: Int };
export type Rule = {
  id: RuleId; text: string; principals: (PrincipalId | "*")[]; tools: ToolName[];
  scopes: (Label | "*")[]; resources: Selector[]; when: Predicate[];
};
export type Field =
  | { name: Label; kind: "string"; max_bytes: Int }
  | { name: Label; kind: "integer"; min: Int; max: Int }
  | { name: Label; kind: "boolean" };
export type Tool = {
  tool: ToolName; binding: "RECORDS";
  operation: "get" | "put" | "delete" | "list" | "export"; args: Field[];
};
export type Manifest = {
  schema: "charter.manifest/1"; gateway_id: GatewayId; engine: "charter.eval/1";
  resource_grammar: "segments/1"; adapter_build_hash: Hash; tools: Tool[];
};
export type Policy = {
  schema: "charter.policy/1"; tenant_id: TenantId; charter_id: CharterId;
  version: Int; previous_hash: Hash | null; engine: "charter.eval/1";
  manifest_hash: Hash; issued_at: Time; not_before: Time; not_after: Time;
  source: Source; description: string; next_authority: Authority;
  hard_denies: Rule[]; scope_rules: Rule[];
};
export type Bundle = { policy: Policy; manifest: Manifest; signatures: Detached[] };
export type Pin = {
  charter_id: CharterId; version: Int; policy_hash: Hash; manifest_hash: Hash;
  engine: "charter.eval/1";
};
export type Citation = {
  schema: "charter.citation/1"; pin: Pin; rule_id: RuleId; pointer: string;
  clause_hash: Hash; rule: Rule;
};

export type PinCommand = {
  schema: "charter.pin/1"; tenant_id: TenantId; gateway_id: GatewayId;
  request_id: RequestId; expected_revision: Int; expected_revocation_epoch: Int;
  authority_policy_hash: Hash; target: Pin; expires_at: Time;
};
export type SignedPin = { command: PinCommand; signatures: Detached[] };
export type PauseRequest = { request_id: RequestId; expected_revision: Int; reason: string };
export type RevokeTarget =
  | { kind: "policy"; policy_hash: Hash }
  | { kind: "credential"; credential_id: CredentialId }
  | { kind: "policy_key"; key_id: KeyId };
export type RevokeRequest = {
  request_id: RequestId; expected_revocation_epoch: Int; target: RevokeTarget;
  reason: string;
};
export type Revocation = RevokeRequest & {
  epoch: Int; actor_id: PrincipalId; effective_seq: Int; recorded_at: Time;
};
export type Deployment = {
  gateway_id: GatewayId; revision: Int; revocation_epoch: Int;
  state: "UNPINNED" | "ACTIVE" | "PAUSED"; pin: Pin | null;
  installed_manifest_hash: Hash; in_flight: Int;
};
export type Principal = {
  principal_id: PrincipalId; credential_id: CredentialId;
  instance_id: InstanceId; scopes: Label[];
};
export type CallRequest = {
  request_id: RequestId; pin: Pin; scope: Label; tool: ToolName;
  resource: Resource; args: { [field: string]: Scalar }; deadline: Time;
};
export type DecisionReason =
  | "ALLOW_SCOPE" | "HARD_DENY" | "NO_SCOPE" | "PIN_MISMATCH"
  | "MANIFEST_MISMATCH" | "POLICY_REVOKED" | "POLICY_KEY_REVOKED"
  | "POLICY_NOT_YET_VALID" | "POLICY_EXPIRED" | "DEADLINE" | "PRINCIPAL_SCOPE"
  | "UNKNOWN_TOOL";
export type Decision = { verdict: "ALLOW" | "DENY"; reason: DecisionReason; rule_ids: RuleId[] };
export type EvalInput = {
  policy: Policy; manifest: Manifest; active_pin: Pin; request: CallRequest;
  principal: Principal; now: Time; policy_revoked: boolean;
  policy_signatures_valid: boolean;
};
export type CallState = "DENIED" | "COMMITTED" | "SUCCEEDED" | "FAILED" | "INDETERMINATE" | "NOT_SENT";
export type CallResult = {
  request_id: RequestId; state: CallState; decision: Decision; input_hash: Hash;
  output: Json; output_available: boolean; output_hash: Hash | null; audit_seqs: Int[];
};
export type CheckResult = { decision: Decision; input_hash: Hash; enforcement: false; audit_seq: Int };
export type ControlResult = { deployment: Deployment; audit_seq: Int };
export type RevokeResult = { revocation: Revocation; deployment: Deployment };

export type Heartbeat = {
  request_id: RequestId; instance_id: InstanceId; counter: Int;
  observed_pin: Pin | null; manifest_hash: Hash;
};
export type InstanceState = "MISSING" | "MATCHED" | "MISMATCH";
export type InstanceView = {
  instance_id: InstanceId; counter: Int; received_at: Time | null;
  expires_at: Time | null; observed_pin: Pin | null; manifest_hash: Hash | null;
  state: InstanceState;
};
export type Fleet = {
  as_of: Time; desired_pin: Pin | null;
  status: "EMPTY" | "HEALTHY" | "SPLIT" | "MISSING"; instances: InstanceView[];
};
export type HeartbeatResult = { counter: Int; expires_at: Time; state: InstanceState; audit_seq: Int };
export type DisputeRequest = {
  request_id: RequestId; dispute_id: DisputeId; pin: Pin; cited_seq: Int;
  category: "POLICY_TEXT" | "SCOPE_MATCH" | "EXECUTION" | "VERSION_SPLIT";
  statement: string; evidence_hashes: Hash[];
};
export type Dispute = DisputeRequest & {
  actor_id: PrincipalId; recorded_at: Time; status: "RECORDED_ADVISORY"; receipt_seq: Int;
};
export type DecisionData = {
  request_id: RequestId; input_hash: Hash; evaluated_at: Time; decision: Decision;
  revision: Int; revocation_epoch: Int; instance_counter: Int;
};
export type AuditEvent =
  | { type: "PolicyPublished"; value: { pin: Pin; source: Source } }
  | { type: "PinActivated"; value: { revision: Int; revocation_epoch: Int; previous_pin: Pin | null; pin: Pin; control_hash: Hash; in_flight: Int } }
  | { type: "GatewayPaused"; value: { revision: Int; control_hash: Hash; in_flight: Int } }
  | { type: "TargetRevoked"; value: { epoch: Int; target: RevokeTarget; control_hash: Hash; in_flight: Int } }
  | { type: "CheckEvaluated" | "CallDenied" | "CallCommitted"; value: DecisionData }
  | { type: "CallFinished"; value: { request_id: RequestId; state: "SUCCEEDED" | "FAILED" | "INDETERMINATE" | "NOT_SENT"; output_hash: Hash | null } }
  | { type: "InstanceObserved"; value: { heartbeat: Heartbeat; expires_at: Time } }
  | { type: "DisputeRecorded"; value: { dispute_id: DisputeId; cited_seq: Int; category: DisputeRequest["category"]; statement_hash: Hash } }
  | { type: "CommandRejected"; value: { operation: string; request_hash: Hash; code: ErrorCode } }
  | { type: "StorageMigrated"; value: { from_version: Int; to_version: Int; migration_hash: Hash } };
export type AuditBody = {
  schema: "charter.audit/1"; tenant_id: TenantId; log_id: LogId; seq: Int;
  prev_hash: Hash; time: Time; actor_id: PrincipalId; policy_pin: Pin | null;
  event: AuditEvent;
};
export type AuditEntry = { body: AuditBody; hash: Hash; key_id: KeyId; signature: Signature };
export type CheckpointBody = {
  schema: "charter.checkpoint/1"; tenant_id: TenantId; log_id: LogId;
  through_seq: Int; head_hash: Hash; time: Time;
};
export type Checkpoint = { body: CheckpointBody; key_id: KeyId; signature: Signature };
export type ControlArtifact =
  | { kind: "pin"; value: SignedPin }
  | { kind: "pause"; value: PauseRequest }
  | { kind: "revoke"; value: RevokeRequest };
export type AuditPage = { entries: AuditEntry[]; controls: ControlArtifact[]; through_seq: Int; next_after: Int | null };
export type Evidence = {
  schema: "charter.evidence/1"; root: RootFile; bundles: Bundle[];
  start: Checkpoint | null; entries: AuditEntry[]; controls: ControlArtifact[];
  end: Checkpoint; inputs: { request: CallRequest; principal: Principal }[];
};
export type Verification = {
  integrity: "VALID" | "INVALID" | "INCOMPLETE";
  replay: "MATCH" | "MISMATCH" | "NOT_REQUESTED" | "INPUTS_MISSING" | "CONTEXT_MISSING";
  through_seq: Int; checkpoint_match: boolean; truth: "NOT_ATTESTED";
};

export type Warning = "NO_ALLOW_RULES" | "SINGLE_SIGNER" | "EXPIRY_WITHIN_24H";
export type Validated = { valid: true; pin: Pin; signatures: Int; required: Int; warnings: Warning[] };
export type Linted = { valid: true; policy_hash: Hash; manifest_hash: Hash; warnings: Warning[] };
export type Versions = { versions: Pin[]; head_version: Int; next_after: Int | null };
export type Published = { pin: Pin; head_version: Int; audit_seq: Int };
export type Ready = { ready: true; deployment: Deployment };
export type Revocations = { epoch: Int; revocations: Revocation[]; next_after: Int | null };
export type Disputes = { disputes: Dispute[]; next_after: Int | null };

export type AuditKey = Key & { from_seq: Int; through_seq: Int | null };
export type RootFile = {
  schema: "charter.root/1"; tenant_id: TenantId; charter_id: CharterId;
  gateway_id: GatewayId; log_id: LogId; bootstrap: Authority; audit_keys: AuditKey[];
};
export type AuthRecord = {
  credential_id: CredentialId; token_hash: Hash; tenant_id: TenantId;
  principal_id: PrincipalId;
  role: "reader" | "publisher" | "operator" | "agent" | "instance";
  scopes: Label[]; instance_id: InstanceId | null; expires_at: Time;
};
export type AuthFile = { schema: "charter.auth/1"; records: AuthRecord[] };
export type EncryptionKeys = { active_key_id: Label; keys: { key_id: Label; key_base64url: string }[] };
export type Config = {
  schema: "charter.config/1"; environment: "local" | "production"; endpoint: string;
  tenant_id: TenantId; gateway_id: GatewayId; instance_id: InstanceId;
  system_principal_id: PrincipalId; root_file: string; manifest_file: string;
  instance_inventory: InstanceId[]; client_credential_ref: string;
  auth_records_ref: string; audit_seed_ref: string; audit_key_id: KeyId;
  response_keys_ref: string; storage_soft_limit_bytes: Int; max_in_flight: Int;
  metrics_enabled: boolean;
};

export type AdapterRequest = {
  request_id: RequestId; principal_id: PrincipalId; scope: Label; pin: Pin;
  input_hash: Hash; operation: Tool["operation"]; resource: Resource;
  args: { [field: string]: Scalar }; deadline: Time;
};
export type AdapterResponse =
  | { status: "ok" | "error"; output: Json }
  | { status: "unknown" };

export type MetricSnapshot = {
  window_seconds: 60; calls: Int; allows: Int; denies: Int; indeterminate: Int;
  not_sent: Int; audit_failures: Int; pin_revision: Int; revocation_epoch: Int;
  instances_matched: Int; instances_missing: Int; instances_mismatch: Int;
};
export type Diagnostic = {
  time: Time; level: "INFO" | "WARN" | "ERROR";
  component: "worker" | "tenant" | "adapter" | "verifier";
  code: ErrorCode | DecisionReason; request_id: RequestId | null;
  audit_seq: Int | null;
  duration_bucket: "lt1ms" | "lt10ms" | "lt100ms" | "lt1s" | "gte1s";
};

export type ExportHeader = { record: "header"; schema: "charter.stream/1"; root: RootFile; start: Checkpoint | null; end: Checkpoint };
export type ExportBundle = { record: "bundle"; bundle: Bundle };
export type ExportControl = { record: "control"; control: ControlArtifact };
export type ExportEntry = { record: "entry"; entry: AuditEntry };
export type ExportInput = { record: "input"; input: { request: CallRequest; principal: Principal } };
export type ExportTrailer = { record: "trailer"; bundles: Int; controls: Int; entries: Int; inputs: Int; through_seq: Int };
export type ProofLink = {
  schema: "charter.proof-link/1"; tenant_id: TenantId; log_id: LogId; seq: Int;
  audit_hash: Hash; policy_pin: Pin | null; input_hash: Hash | null;
  parent_hashes: Hash[]; evidence_profile: "charter.stream/1";
  execution_truth: "NOT_ATTESTED";
};

export type Compiled = { policy_hash: Hash; manifest_hash: Hash; engine: "charter.eval/1" };
export type Diff = { old_hash: Hash; new_hash: Hash; changes: { pointer: string; before: Json; after: Json }[] };

export const ENGINE = "charter.eval/1" as const;
export const API = "charter.http/1" as const;
/** Default-deny citation invariant — never a fabricated rule. */
export const DEFAULT_DENY_INVARIANT = "default-deny/1" as const;
