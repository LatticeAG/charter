/** charter/1 error taxonomy, HTTP status mapping, retryability, CLI exit codes. */

export const ERROR_CODES = [
  "PARSE", "SCHEMA", "LIMIT", "AUTH_REQUIRED", "FORBIDDEN", "NOT_FOUND",
  "UNSUPPORTED_VERSION", "UNSUPPORTED_COMPOSITION", "HASH_MISMATCH",
  "SIGNATURE_INVALID", "SIGNATURE_DUPLICATE", "KEY_UNKNOWN", "QUORUM",
  "VERSION_CONFLICT", "REVISION_CONFLICT", "REVOCATION_CONFLICT",
  "ALREADY_REVOKED", "PIN_NOT_HEAD", "PIN_EXPIRED", "POLICY_INELIGIBLE",
  "IDEMPOTENCY_CONFLICT", "REQUEST_ID_REUSED", "COUNTER_CONFLICT",
  "STATE_TRANSITION", "UNPINNED", "PAUSED", "POLICY_INACTIVE",
  "MANIFEST_UNAVAILABLE", "INSTANCE_STALE", "INSTANCE_MISMATCH",
  "CLOCK_UNSAFE", "AUDIT_UNAVAILABLE", "STORAGE_FULL", "BUSY",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

const STATUS: Record<ErrorCode, number> = {
  PARSE: 400, SCHEMA: 400,
  AUTH_REQUIRED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  VERSION_CONFLICT: 409, REVISION_CONFLICT: 409, REVOCATION_CONFLICT: 409,
  ALREADY_REVOKED: 409, PIN_NOT_HEAD: 409, IDEMPOTENCY_CONFLICT: 409,
  REQUEST_ID_REUSED: 409, COUNTER_CONFLICT: 409, STATE_TRANSITION: 409,
  LIMIT: 413,
  UNSUPPORTED_VERSION: 422, UNSUPPORTED_COMPOSITION: 422, HASH_MISMATCH: 422,
  SIGNATURE_INVALID: 422, SIGNATURE_DUPLICATE: 422, KEY_UNKNOWN: 422,
  QUORUM: 422, PIN_EXPIRED: 422, POLICY_INELIGIBLE: 422,
  BUSY: 429,
  UNPINNED: 503, PAUSED: 503, POLICY_INACTIVE: 503, MANIFEST_UNAVAILABLE: 503,
  INSTANCE_STALE: 503, INSTANCE_MISMATCH: 503, CLOCK_UNSAFE: 503,
  AUDIT_UNAVAILABLE: 503, STORAGE_FULL: 503,
};

const RETRYABLE = new Set<ErrorCode>([
  "BUSY", "INSTANCE_STALE", "INSTANCE_MISMATCH", "AUDIT_UNAVAILABLE",
]);

/** CLI exit code per the §4 contract. */
const EXIT: Record<ErrorCode, number> = {
  PARSE: 2, SCHEMA: 2, LIMIT: 2, NOT_FOUND: 2, UNSUPPORTED_VERSION: 2,
  UNSUPPORTED_COMPOSITION: 2, PIN_EXPIRED: 2, POLICY_INELIGIBLE: 2,
  HASH_MISMATCH: 4, SIGNATURE_INVALID: 4, SIGNATURE_DUPLICATE: 4,
  KEY_UNKNOWN: 4, QUORUM: 4,
  AUTH_REQUIRED: 5, FORBIDDEN: 5,
  VERSION_CONFLICT: 6, REVISION_CONFLICT: 6, REVOCATION_CONFLICT: 6,
  ALREADY_REVOKED: 6, PIN_NOT_HEAD: 6, IDEMPOTENCY_CONFLICT: 6,
  REQUEST_ID_REUSED: 6, COUNTER_CONFLICT: 6, STATE_TRANSITION: 6,
  UNPINNED: 7, PAUSED: 7, POLICY_INACTIVE: 7, MANIFEST_UNAVAILABLE: 7,
  INSTANCE_STALE: 7, INSTANCE_MISMATCH: 7, CLOCK_UNSAFE: 7,
  AUDIT_UNAVAILABLE: 7, STORAGE_FULL: 7, BUSY: 7,
};

export function statusFor(code: ErrorCode): number {
  return STATUS[code];
}

export function retryable(code: ErrorCode): boolean {
  return RETRYABLE.has(code);
}

export function exitCodeFor(code: ErrorCode): number {
  return EXIT[code];
}

export type ApiError = { error: { code: ErrorCode; retryable: boolean; audit_seq: number | null } };

export function apiError(code: ErrorCode, auditSeq: number | null = null): ApiError {
  return { error: { code, retryable: retryable(code), audit_seq: auditSeq } };
}

/** Thrown by parsers/validators/engine; carries the wire code and optional audit seq. */
export class CharterError extends Error {
  readonly code: ErrorCode;
  readonly auditSeq: number | null;
  constructor(code: ErrorCode, detail?: string, auditSeq: number | null = null) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "CharterError";
    this.code = code;
    this.auditSeq = auditSeq;
  }
}

export function toApiError(e: unknown): ApiError & { status: number } {
  if (e instanceof CharterError) {
    return { status: statusFor(e.code), ...apiError(e.code, e.auditSeq) };
  }
  return { status: 503, ...apiError("AUDIT_UNAVAILABLE") };
}
