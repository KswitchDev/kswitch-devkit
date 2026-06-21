# KSwitch SDK Governed Invocation Model

**Version:** v2 | **Applies to:** Python SDK, TypeScript SDK, Go SDK

This document defines the supported SDK invocation model for production code:
which paths run the full governance pipeline, which paths are test/migration
exceptions, and how KSwitch repository CI reviews unsafe SDK-internal usage.

---

## Governed Invocation Model

The governed invocation path is the only supported production path across all three SDKs.

```
developer
  → governed runtime/invoke API
  → interceptor
  → local PDP (in-process Cedar evaluation)
  → [optional server escalation for conditional decisions]
  → tool execution
  → output filtering
  → audit emit
```

This pipeline is the supported production path. Bypassing it means:
- No enforcement (allow/deny) — tool runs regardless of policy
- No output filtering — PII/PHI/MNPI returned unmasked
- No obligation blocking — credential risk / anomaly obligations not enforced
- No audit trail — decisions not logged to JSONL or forwarded to central audit

---

## Supported Public APIs per SDK

### Python
```python
# PRIMARY — governed runtime (registers tools, enforces on every invoke)
runtime = KSwitchRuntime(agent_id, mcp_server_id, client=client)
runtime.register("tool_name", tool_fn)
result = runtime.invoke("tool_name", **kwargs)

# ALSO SUPPORTED — direct interceptor (for advanced composition)
interceptor = KSwitchInterceptor(client)
result = interceptor.check_and_invoke(
    agent_id=..., mcp_server_id=..., tool_name=..., tool_fn=..., tool_args={}
)
```

### TypeScript
```typescript
// PRIMARY — interceptor with optional local PDP
const interceptor = new KSwitchInterceptor(client, { localPDP: new LocalPDPEvaluator() });
const result = await interceptor.checkAndInvoke({ agentId, mcpServerId, toolName, toolFn });
```

### Go
```go
// PRIMARY — interceptor with local PDP
evaluator := localpdp.NewLocalPDPEvaluator()
interceptor := kswitch.NewInterceptor(client, kswitch.WithLocalPDP(evaluator))
result, err := interceptor.CheckAndInvoke(ctx, &kswitch.CheckAndInvokeRequest{
    AgentID: agentID, MCPServerID: mcpServerID, ToolName: toolName, ToolFn: toolFn,
})
```

---

## Non-Compliant Paths

The following paths are **non-compliant** and must NOT be used in production code:

| Path | SDK | Why it's unsafe |
|------|-----|----------------|
| `client.enforcement.enforce_mcp_call()` | Python | Returns decision only; no output filtering, no obligation blocking, no local PDP |
| `client.enforcement.enforceMCPCall()` | TypeScript | Same as above |
| `client.Enforcement.EnforceMCPCall()` | Go | Same as above |
| `tool._unsafe_raw_call()` | Python | Bypasses all enforcement, filtering, and audit |
| `tool._fn(...)` | Python | Direct raw callable — no governance |
| `enforcePreInvokeObligations()` standalone | TypeScript | Partial pipeline — no output filtering |
| `applyOutputPolicy()` standalone | TypeScript | Partial pipeline — no enforcement |
| `deriveOutputPolicy()` standalone | TypeScript | Internal helper — not a public API |

KSwitch repository CI flags these patterns. Consumers embedding the SDK should
add the same checks to their own release pipeline when they need hard assurance
that application code uses governed invocation.

---

## Escape Hatch Policy

Sometimes unsafe paths are necessary for:
- Unit tests that need to isolate a specific component
- Migration code transitioning from old patterns
- Internal tooling with explicit awareness of the trade-off

### Required marker

To use an unsafe path intentionally, annotate the call site with:

```python
# kswitch: allow-unsafe
decision = client.enforcement.enforce_mcp_call(...)
```

```typescript
// kswitch: allow-unsafe
const decision = await client.enforcement.enforceMCPCall(request);
```

```go
// kswitch: allow-unsafe
decision, err := client.Enforcement.EnforceMCPCall(ctx, req)
```

The marker must appear on the **same line** or the **immediately preceding line**.

### Rules for approved escape hatches

1. **Must have business justification** — add a comment explaining why
2. **Must not appear in production invocation paths** — tests and tooling only
3. **Must be reviewed in code review** — the marker makes them easy to spot
4. **CI reports them** — approved usages are listed in CI output but do not fail the build

### What CI does with the marker

- Without marker → CI **fails** the build
- With marker → CI **logs** the approved usage but does not fail

The marker is CI review metadata only. It does not disable runtime enforcement,
grant permission, or make an unsafe invocation production-compliant.

---

## CI Rules

Add to your CI pipeline:

```bash
# All bypass checks (Python + TypeScript + Go + startup refusal)
make check-bypass

# Individual language checks
make check-bypass-python    # sdks/python/
make check-bypass-ts        # sdks/typescript/
make check-bypass-go        # sdks/go/

# Verify bundle/signature startup refusal is present in all SDKs
make verify-startup-refusal

# Test the checker scripts themselves
make test-bypass-checks
```

The `make ci` target runs all of the above automatically.

### What each checker detects

#### Python (`scripts/check_bypass_python.py`)
- `enforce_mcp_call()` invocation
- `_unsafe_raw_call()` invocation
- `._fn(...)` direct callable access on GovernedTool

#### TypeScript (`scripts/check_bypass_ts.py`)
- `enforceMCPCall()` invocation
- Direct import of `enforcePreInvokeObligations`, `applyOutputPolicy`, `deriveOutputPolicy`
- `Unsafe...()` or `Raw...()` function calls

#### Go (`scripts/check_bypass_go.py`)
- `Enforcement.EnforceMCPCall()` invocation
- `Unsafe...()` or `Raw...()` function calls

### Actionable CI output

```
[kswitch bypass] FAIL — 1 UNAPPROVED bypass violation(s):

  ✗ sdks/python/myservice/tool_handler.py:42:8  [HIGH]  direct_enforce_mcp_call
    Direct enforce_mcp_call() invocation — use KSwitchInterceptor.check_and_invoke() ...
    → Add '# kswitch: allow-unsafe' on this line or the line above to approve.

To fix: use KSwitchRuntime.invoke() or KSwitchInterceptor.check_and_invoke().
```

---

## Startup Refusal Requirements

Each SDK must **fail fast** on invalid bundle state. This is enforced by
`verify-startup-refusal` in CI.

| SDK | Required behavior |
|-----|------------------|
| Python | `BundleNotAvailableError` raised if bundle missing/corrupt/signature-invalid |
| TypeScript | `BundleNotAvailableError` thrown under same conditions |
| Go | `ErrBundleNotAvailable` returned under same conditions |

### Production signature enforcement

All SDKs accept unsigned bundles in **development mode** only.

In production (`KSWITCH_ENV=production`), unsigned bundles are **rejected**.

```bash
# Production deployment — enforce signed bundles
export KSWITCH_ENV=production

# Development — unsigned bundles accepted (default)
export KSWITCH_ENV=development  # or unset
```

---

## Production Profile Checklist

Before production deployment, verify:

- [ ] `KSWITCH_ENV=production` is set — enables hard-fail on unsigned bundles
- [ ] `KSWITCH_AUDIT_FORWARDING_ENABLED=true` — enables central audit forwarding
- [ ] `KSWITCH_STATE_DIR` points to a writable persistent directory
- [ ] Local bundle is present at `$KSWITCH_STATE_DIR/bundle/current.bundle`
- [ ] Bundle has a valid `sha256:` signature
- [ ] Revocation sync is enabled (`KSWITCH_REVOCATION_SYNC_ENABLED=true`)
- [ ] `KSWITCH_REVOCATION_STALE_MODE=deny` or `conditional` for critical agents
- [ ] No `# kswitch: allow-unsafe` markers in production code paths

---

## Example: Correct Governed Usage

### Python
```python
from kswitch import KSwitchClient, KSwitchRuntime, KSwitchEnforcementError

client = KSwitchClient(base_url="https://kswitch.bank.internal", token=token)

runtime = KSwitchRuntime(
    agent_id="agent:fraud-detector@bank.internal",
    mcp_server_id="mcp:payments@bank.internal",
    client=client,
)
runtime.register("initiate_payment", payment_tool.initiate_payment)
runtime.register("read_balance", payment_tool.read_balance)

try:
    result = runtime.invoke("initiate_payment", amount=500, currency="USD")
except KSwitchEnforcementError as e:
    print(f"Denied: {e}")
```

### TypeScript
```typescript
import { KSwitchClient, KSwitchInterceptor, LocalPDPEvaluator } from "@kswitch/sdk";

const client = new KSwitchClient({ baseUrl: "https://kswitch.bank.internal", token });
const interceptor = new KSwitchInterceptor(client, {
  localPDP: new LocalPDPEvaluator(),
});

const result = await interceptor.checkAndInvoke({
  agentId: "agent:fraud-detector@bank.internal",
  mcpServerId: "mcp:payments@bank.internal",
  toolName: "initiate_payment",
  toolFn: () => paymentTool.initiatePayment({ amount: 500, currency: "USD" }),
});
```

### Go
```go
evaluator := localpdp.NewLocalPDPEvaluator()
interceptor := kswitch.NewInterceptor(client, kswitch.WithLocalPDP(evaluator))

result, err := interceptor.CheckAndInvoke(ctx, &kswitch.CheckAndInvokeRequest{
    AgentID:     "agent:fraud-detector@bank.internal",
    MCPServerID: "mcp:payments@bank.internal",
    ToolName:    "initiate_payment",
    ToolFn: func() (any, error) {
        return paymentTool.InitiatePayment(ctx, 500, "USD")
    },
})
```

---

## What Is NOT in Scope

This document covers SDK-layer bypass hardening only.

Not in scope:
- Gateway / network-layer enforcement
- Execution token / cryptographic proof
- Runtime attestation protocols

Those may be added in a future hardening layer.
