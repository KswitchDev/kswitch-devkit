/**
 * OBO and local Envoy policy evidence contract helpers.
 *
 * This module captures the portable wire shape used by KSwitch OBO flows:
 * actor-chain headers, scoped resource access, Envoy ext_authz evidence,
 * OPA/Cedar local PDP decisions, KSwitch enforcement references, and
 * proof-level sender constraints.
 */

import * as crypto from "node:crypto";

export const OBO_ACTOR_CHAIN_HEADER = "X-OBO-Actor-Chain";
export const OBO_REQUESTED_SCOPE_HEADER = "X-OBO-Requested-Scope";
export const OBO_SENDER_CONSTRAINT_HEADER = "X-OBO-Sender-Constraint";
export const KSWITCH_ENFORCEMENT_DECISION_HEADER =
  "X-KSwitch-Enforcement-Decision";
export const KSWITCH_ENFORCEMENT_ID_HEADER = "X-KSwitch-Enforcement-Id";
export const KSWITCH_POLICY_DECISION_HEADER = "X-KSwitch-Policy-Decision";
export const KSWITCH_POLICY_EVIDENCE_HEADER = "X-KSwitch-Policy-Evidence";
export const KSWITCH_POLICY_BUNDLE_HEADER = "X-KSwitch-Policy-Bundle";

export const EXPECTED_POLICY_PEP = "envoy_ext_authz";
export const EXPECTED_POLICY_TRANSPORT = "envoy_http_ext_authz";
export const EXPECTED_POLICY_ENFORCEMENT_POINT = "local_envoy_sidecar";
export const EXPECTED_POLICY_PDP_MODE = "opa_and_cedar_must_allow";

export interface PolicyEngineEvidence {
  allow: boolean;
  engine: string;
  policyId?: string;
  denyReasons: string[];
  raw: Record<string, unknown>;
}

export interface PolicyEvidence {
  allow: boolean;
  pep: string;
  pepTransport?: string;
  enforcementPoint?: string;
  pdpMode?: string;
  resourceId: string;
  requiredScope: string;
  requestedScope?: string;
  bundleVersion?: string;
  bundleSha256?: string;
  opa: PolicyEngineEvidence;
  cedar: PolicyEngineEvidence;
  raw: Record<string, unknown>;
}

export interface BuildActorChainOptions {
  humanSubject: string;
  agentSpiffeId: string;
  mcpSpiffeId: string;
  brokerSpiffeId?: string;
  humanSub?: string;
  humanEmail?: string;
  prompt?: string;
}

export interface BuildSenderConstraintOptions {
  agentSpiffeId: string;
  executorSpiffeId: string;
  resourceAudience: string;
  brokerSpiffeId?: string;
  agentJwtSvid?: string;
  executorJwtSvid?: string;
}

export interface BuildOBOHeadersOptions {
  actorChain: Record<string, unknown>;
  requestedScope: string;
  senderConstraint?: Record<string, unknown>;
  kswitchDecision?: Record<string, unknown>;
  kswitchEnforcementId?: string;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!isRecord(value)) return value;
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    ordered[key] = stableValue(value[key]);
  }
  return ordered;
}

function stableJson(value: Record<string, unknown>): string {
  return JSON.stringify(stableValue(value));
}

export function encodeJsonHeader(payload: Record<string, unknown>): string {
  const encoded = Buffer.from(stableJson(payload), "utf8").toString("base64url");
  return encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
}

export function decodeJsonHeader(value?: string | null): Record<string, unknown> {
  if (!value) return {};
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const decoded = JSON.parse(Buffer.from(padded, "base64url").toString("utf8"));
    return isRecord(decoded) ? decoded : {};
  } catch {
    return {};
  }
}

export function sha256B64Url(value: string): string {
  return crypto.createHash("sha256").update(value).digest().toString("base64url");
}

export function getHeader(
  headers: Record<string, unknown>,
  name: string,
): string {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) return String(value);
  }
  return "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function policyEngineEvidenceFrom(
  payload?: unknown,
): PolicyEngineEvidence {
  const raw = isRecord(payload) ? payload : {};
  const deny = raw["deny_reasons"] ?? raw["deny"] ?? [];
  return {
    allow: Boolean(raw["allow"]),
    engine: String(raw["engine"] ?? ""),
    policyId: raw["policy_id"] == null ? undefined : String(raw["policy_id"]),
    denyReasons: Array.isArray(deny) ? deny.map(String) : [],
    raw,
  };
}

export function policyEvidenceFrom(payload?: unknown): PolicyEvidence {
  const raw = isRecord(payload) ? payload : {};
  return {
    allow: Boolean(raw["allow"]),
    pep: String(raw["pep"] ?? ""),
    pepTransport:
      raw["pep_transport"] == null ? undefined : String(raw["pep_transport"]),
    enforcementPoint:
      raw["enforcement_point"] == null
        ? undefined
        : String(raw["enforcement_point"]),
    pdpMode: raw["pdp_mode"] == null ? undefined : String(raw["pdp_mode"]),
    resourceId: String(raw["resource_id"] ?? ""),
    requiredScope: String(raw["required_scope"] ?? ""),
    requestedScope:
      raw["requested_scope"] == null ? undefined : String(raw["requested_scope"]),
    bundleVersion:
      raw["bundle_version"] == null ? undefined : String(raw["bundle_version"]),
    bundleSha256:
      raw["bundle_sha256"] == null ? undefined : String(raw["bundle_sha256"]),
    opa: policyEngineEvidenceFrom(raw["opa"]),
    cedar: policyEngineEvidenceFrom(raw["cedar"]),
    raw,
  };
}

export function policyEvidenceAllows(
  evidence: PolicyEvidence,
  opts: { resourceId?: string; requiredScope?: string } = {},
): boolean {
  if (!evidence.allow || evidence.pep !== EXPECTED_POLICY_PEP) return false;
  if (opts.resourceId != null && evidence.resourceId !== opts.resourceId) {
    return false;
  }
  if (
    opts.requiredScope != null &&
    evidence.requiredScope !== opts.requiredScope
  ) {
    return false;
  }
  return evidence.opa.allow && evidence.cedar.allow;
}

export function policyEvidenceFromHeaders(
  headers: Record<string, unknown>,
): PolicyEvidence {
  return policyEvidenceFrom(
    decodeJsonHeader(getHeader(headers, KSWITCH_POLICY_EVIDENCE_HEADER)),
  );
}

export function actorChainFromHeaders(
  headers: Record<string, unknown>,
): Record<string, unknown> {
  return decodeJsonHeader(getHeader(headers, OBO_ACTOR_CHAIN_HEADER));
}

export function senderConstraintFromHeaders(
  headers: Record<string, unknown>,
): Record<string, unknown> {
  return decodeJsonHeader(getHeader(headers, OBO_SENDER_CONSTRAINT_HEADER));
}

export function kswitchDecisionFromHeaders(
  headers: Record<string, unknown>,
): Record<string, unknown> {
  return decodeJsonHeader(getHeader(headers, KSWITCH_ENFORCEMENT_DECISION_HEADER));
}

export function buildActorChain(
  opts: BuildActorChainOptions,
): Record<string, unknown> {
  const actors: Record<string, unknown>[] = [
    { role: "agent", spiffe_id: opts.agentSpiffeId },
    { role: "mcp", spiffe_id: opts.mcpSpiffeId },
  ];
  if (opts.brokerSpiffeId) {
    actors.push({ role: "broker", spiffe_id: opts.brokerSpiffeId });
  }
  const chain: Record<string, unknown> = {
    sub: opts.humanSub ?? "",
    human_subject: opts.humanSubject,
    human: {
      sub: opts.humanSub ?? "",
      subject: opts.humanSubject,
      email: opts.humanEmail ?? "",
      prompt: opts.prompt ?? "",
    },
    actor: {
      role: "agent",
      spiffe_id: opts.agentSpiffeId,
      action: "interpreted human prompt",
    },
    executor: {
      role: "mcp",
      spiffe_id: opts.mcpSpiffeId,
      action: "executed resource call",
    },
    actors,
    standards: {
      obo: "RFC 8693 token exchange",
      workload_identity: "SPIFFE/SPIRE JWT-SVID",
      wimse_profile:
        "WIMSE workload identity and authorization-evidence profile candidate",
    },
  };
  if (opts.brokerSpiffeId) {
    chain["broker"] = {
      role: "obo-broker",
      spiffe_id: opts.brokerSpiffeId,
      action: "validated actor/executor and exchanged token",
    };
  }
  return chain;
}

export function buildSenderConstraint(
  opts: BuildSenderConstraintOptions,
): Record<string, unknown> {
  const constraint: Record<string, unknown> = {
    type: "svid-bound-proof",
    confirmation_method: "jwt-svid-sha256",
    actor_spiffe_id: opts.agentSpiffeId,
    executor_spiffe_id: opts.executorSpiffeId,
    broker_spiffe_id: opts.brokerSpiffeId ?? "",
    resource_audience: opts.resourceAudience,
  };
  if (opts.agentJwtSvid) {
    constraint["agent_svid_sha256"] = sha256B64Url(opts.agentJwtSvid);
  }
  if (opts.executorJwtSvid) {
    constraint["mcp_svid_sha256"] = sha256B64Url(opts.executorJwtSvid);
  }
  return constraint;
}

export function buildOBOHeaders(opts: BuildOBOHeadersOptions): Record<string, string> {
  const headers: Record<string, string> = {
    [OBO_ACTOR_CHAIN_HEADER]: encodeJsonHeader(opts.actorChain),
    [OBO_REQUESTED_SCOPE_HEADER]: opts.requestedScope,
  };
  if (opts.senderConstraint) {
    headers[OBO_SENDER_CONSTRAINT_HEADER] = encodeJsonHeader(
      opts.senderConstraint,
    );
  }
  if (opts.kswitchDecision) {
    headers[KSWITCH_ENFORCEMENT_DECISION_HEADER] = encodeJsonHeader(
      opts.kswitchDecision,
    );
  }
  if (opts.kswitchEnforcementId) {
    headers[KSWITCH_ENFORCEMENT_ID_HEADER] = opts.kswitchEnforcementId;
  }
  return headers;
}
