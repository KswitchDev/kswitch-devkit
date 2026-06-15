/**
 * KSwitch TypeScript SDK — DenyReason (EP-050 W4 parity with server).
 *
 * Wire parity: matches `app/enforcement/reason_class.py::DenyReason` (server)
 * and `sdks/python/kswitch/deny_reason.py` (Python SDK).  Five canonical
 * values — adding one requires a coordinated server-SDK rollout.
 *
 * Forward compatibility: `parseDenyReason(...)` falls back to `UNKNOWN` when
 * the server emits a value this SDK does not yet recognise; no throw.
 */

export const DenyReason = {
  POLICY: "POLICY",
  GOVERNANCE: "GOVERNANCE",
  UNAVAILABLE: "UNAVAILABLE",
  VALIDATION: "VALIDATION",
  UNKNOWN: "UNKNOWN",
} as const;

export type DenyReason = typeof DenyReason[keyof typeof DenyReason];

const KNOWN: readonly string[] = Object.values(DenyReason);

/**
 * Parse any value into a DenyReason.  Unknown inputs return `DenyReason.UNKNOWN`.
 */
export function parseDenyReason(raw: unknown): DenyReason {
  if (typeof raw !== "string") {
    return DenyReason.UNKNOWN;
  }
  const upper = raw.toUpperCase();
  if ((KNOWN as readonly string[]).includes(upper)) {
    return upper as DenyReason;
  }
  return DenyReason.UNKNOWN;
}
