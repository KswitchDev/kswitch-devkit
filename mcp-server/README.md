# KSwitch.ai MCP Server

Trust enforcement for autonomous systems. This MCP server connects any MCP-compatible AI coding tool to the KSwitch Agent Trust Control Plane, giving your AI agents governed access to registration, compliance, enforcement, identity, kill switch, policy, and audit capabilities.

## Installation

```bash
pip install kswitch-mcp
```

Or install from the DevKit source tree:

```bash
cd mcp-server
pip install -e .
```

From the local DevKit runtime directory:

```bash
cd devkit
make mcp-install
```

## Quick Start

1. Install the package
2. Set your environment variables (see below)
3. Add the MCP server to your tool's configuration
4. Start using KSwitch tools in your AI coding environment

## Package Entry Points

The package installs four local commands:

| Command | Purpose |
|---------|---------|
| `kswitch-mcp` | Governance tools for registration, compliance, enforcement, identity, kill switch, policy, and audit |
| `kswitch-proxy` | Transparent governing proxy in front of upstream MCP servers |
| `kswitch-brain-mcp` | AI Brain MCP bridge for startup context and bounded recall |
| `kswitch-service-mcp` | Fail-closed governed service MCP for fetch, search, and policy checks |

The DevKit repo includes ready-to-edit config snippets under `configs/`.
Install the package, copy the snippet for your tool, then set the local
DevKit URL and authentication values.

## Configuration by Tool

### Claude Code

Add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_CLIENT_ID": "kswitch-m2m",
        "KSWITCH_CLIENT_SECRET": "your-secret"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

### Windsurf

Add to `mcp_config.json`:

```json
{
  "mcpServers": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

### OpenCode

Add to `.opencode/config`:

```json
{
  "mcp": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

### OpenClaw

Add to `openclaw.json`:

```json
{
  "mcpServers": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

### Cline (VS Code)

Add to VS Code settings:

```json
{
  "cline.mcp.servers": {
    "kswitch": {
      "command": "kswitch-mcp",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token"
      }
    }
  }
}
```

See the `configs/` directory for complete example configuration files.

## AI Brain MCP

KSwitch work should start with the AI Brain bootstrap before broad repo reading,
planning, code changes, review, or handoff. From the repository root:

```bash
python3 scripts/kswitch_brain_bootstrap.py --runtime codex --task "<task>" --format markdown
```

For MCP-native clients, `kswitch-brain-mcp` exposes the local Brain bridge. The
packaged command form is:

```json
{
  "mcpServers": {
    "kswitch-brain": {
      "command": "kswitch-brain-mcp",
      "env": {
        "KSWITCH_DEV_MEMORY_URL": "http://127.0.0.1:8765",
        "KSWITCH_DEV_MEMORY_ACCESS_KEY": "dev-local-memory-key"
      }
    }
  }
}
```

Source-tree development can use
[`configs/brain-local-python.json`](configs/brain-local-python.json), which
runs `python3 -m kswitch_brain_mcp.server` with `PYTHONPATH` set. The Brain MCP
bridge is included for local development, but the managed Brain runtime is not
part of the free DevKit stack.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KSWITCH_URL` | No | `https://localhost:5001` | KSwitch control plane URL |
| `KSWITCH_TOKEN` | No* | `""` | Direct bearer token for authentication |
| `KSWITCH_CLIENT_ID` | No* | `""` | Keycloak M2M client ID |
| `KSWITCH_CLIENT_SECRET` | No* | `""` | Keycloak M2M client secret |
| `KSWITCH_KEYCLOAK_URL` | No | `""` | Keycloak server URL for M2M auth |
| `KSWITCH_KEYCLOAK_REALM` | No | `kswitch` | Keycloak realm name |
| `KSWITCH_VERIFY_SSL` | No | `true` | Enable SSL verification |
| `KSWITCH_CA_FILE` | No | `""` | Path to custom CA certificate |

*Authentication: Provide either `KSWITCH_TOKEN` (direct) or `KSWITCH_CLIENT_ID` + `KSWITCH_CLIENT_SECRET` + `KSWITCH_KEYCLOAK_URL` (M2M). The server auto-detects mkcert CA certificates for local development.

## Tool Reference

### Governance (6 tools)

| Tool | Description |
|------|-------------|
| `register_agent` | Register a new agent or MCP server |
| `list_agents` | List registered agents with filtering |
| `get_agent` | Get full details for a specific agent |
| `approve_agent` | Approve a pending agent |
| `suspend_agent` | Suspend an active agent |
| `get_dashboard` | Get system overview statistics |

### Compliance (5 tools)

| Tool | Description |
|------|-------------|
| `evaluate_toxic_combos` | Check agent for toxic skill/permission combinations |
| `evaluate_all_toxic_combos` | Fleet-wide toxic combo evaluation |
| `analyze_boundaries` | Boundary crossing analysis (tier/division/data) |
| `assess_risk` | Comprehensive risk score (0-1000) |
| `get_compliance_dashboard` | Compliance overview |

### Enforcement (2 tools)

| Tool | Description |
|------|-------------|
| `enforce_mcp_call` | Runtime trust decision for MCP tool calls |
| `evaluate_authzen` | AuthZen PDP evaluation (OpenID standard) |

### Identity (4 tools)

| Tool | Description |
|------|-------------|
| `create_spiffe_identity` | Issue SPIFFE workload identity |
| `get_identity` | Get SPIFFE and service identity details |
| `rotate_identity` | Rotate SPIFFE SVID |
| `list_expiring_identities` | Find expiring identities |

### Kill Switch (3 tools)

| Tool | Description |
|------|-------------|
| `kill_switch` | Targeted kill switch on specific agents |
| `get_kill_switch_history` | Kill switch activation history |
| `get_blast_radius` | Impact analysis before kill |

### Policy (3 tools)

| Tool | Description |
|------|-------------|
| `list_policies` | List governance policies |
| `evaluate_policy` | Evaluate policies for a record |
| `get_policy` | Get policy details with Cedar + Rego text |

### Audit (3 tools)

| Tool | Description |
|------|-------------|
| `get_system_status` | System health + dashboard + event stats |
| `get_audit_trail` | Agent audit history |
| `detect_anomalies` | Anomaly detection across events |

## Examples

### Register an agent and check compliance

```
> Register a new fraud detection agent in tier_3

I'll register the agent using the register_agent tool...

> Now evaluate it for toxic combinations

Running evaluate_toxic_combos...
```

### Runtime enforcement

```
> Check if agent:data-pipeline@analytics can invoke tools/call on mcp:database-writer

Using enforce_mcp_call to get the trust decision...
Decision: deny
Reason: tier_3 agent cannot invoke tier_1 MCP server tools
```

### Pre-kill-switch analysis

```
> What would happen if we killed agent:trading-bot-v2@finops?

Running get_blast_radius...
- 3 connected MCP servers would lose access
- 2 delegation chains would break
- Estimated disruption: 5 downstream agents affected
```

## Architecture

```
Your AI Tool (Claude Code, Cursor, etc.)
    |
    | stdio (MCP protocol)
    |
kswitch-mcp (this server)
    |
    | HTTPS + Bearer/M2M auth
    |
KSwitch Control Plane API
```

The MCP server acts as a thin, stateless bridge between your AI coding tool and the KSwitch control plane. All state lives in KSwitch.

## KSwitch Governing Proxy (kswitch-proxy)

KSwitch supports two integration models. **Model A** (above) installs `kswitch-mcp` as an additional MCP server alongside your existing ones. AI tools gain 26 governance tools they can call explicitly, such as registering agents, evaluating policies, and triggering kill switches. **Model B** (`kswitch-proxy`) replaces direct MCP connections with a governing gateway: `kswitch-proxy` sits _in front of_ all your other MCP servers (postgres-mcp, filesystem-mcp, etc.), enforcement-checks every tool call against the KSwitch control plane before forwarding it, and optionally inspects each response for injection or policy violations. Model B requires no changes to how you call upstream tools. It is transparent to the AI tool.

### Install

```bash
pip install kswitch-mcp
```

Both `kswitch-mcp` and `kswitch-proxy` are installed by the same package.

### Quick start

```bash
export KSWITCH_URL=https://localhost:5001
export KSWITCH_TOKEN=your-bearer-token
export KSWITCH_PROXY_AGENT_ID=my-cursor-session
export KSWITCH_PROXY_UPSTREAMS='[
  {"id": "postgres-mcp", "command": "npx", "args": ["-y", "@mcp/postgres", "postgres://localhost/mydb"]},
  {"id": "files-mcp",    "command": "npx", "args": ["-y", "@mcp/filesystem", "/home/user/projects"]}
]'
kswitch-proxy
```

The proxy connects to each upstream on startup, discovers their tools, registers them in KSwitch, and re-exposes them under `{upstream_id}__{tool_name}` (or plain `{tool_name}` when there is only one upstream). Every call is enforcement-checked; blocked calls return a `[KSwitch] Blocked by governance policy: <reason>` message instead of the upstream result.

### Configuration for Claude Code

Add to `.claude/settings.json` (see `configs/proxy-claude-code.json` for a complete example):

```json
{
  "mcpServers": {
    "kswitch-proxy": {
      "command": "kswitch-proxy",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token",
        "KSWITCH_PROXY_AGENT_ID": "claude-code-session",
        "KSWITCH_PROXY_UPSTREAMS": "[{\"id\": \"postgres-mcp\", \"command\": \"npx\", \"args\": [\"-y\", \"@mcp/postgres\", \"postgres://localhost/mydb\"]}]"
      }
    }
  }
}
```

### Configuration for Cursor

Add to `.cursor/mcp.json` (see `configs/proxy-cursor.json` for a complete example):

```json
{
  "mcpServers": {
    "kswitch-proxy": {
      "command": "kswitch-proxy",
      "env": {
        "KSWITCH_URL": "https://localhost:5001",
        "KSWITCH_TOKEN": "your-bearer-token",
        "KSWITCH_PROXY_AGENT_ID": "cursor-session",
        "KSWITCH_PROXY_UPSTREAMS": "[{\"id\": \"postgres-mcp\", \"command\": \"npx\", \"args\": [\"-y\", \"@mcp/postgres\", \"postgres://localhost/mydb\"]}]"
      }
    }
  }
}
```

### Proxy environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KSWITCH_PROXY_UPSTREAMS` | `[]` | JSON array of upstream MCP configs (see above) |
| `KSWITCH_URL` | `https://localhost:5001` | KSwitch control plane URL |
| `KSWITCH_TOKEN` | `""` | Bearer token for KSwitch API |
| `KSWITCH_CA_FILE` | `""` | Path to internal CA bundle for KSwitch HTTPS |
| `KSWITCH_BUNDLE_PUBKEY_FILE` | `~/.kswitch/bundle-signing-pubkey.pem` | Optional override for the pinned policy-bundle public key |
| `KSWITCH_PROXY_AGENT_ID` | `kswitch-proxy-session` | Agent ID sent in enforcement calls |
| `KSWITCH_VERIFY_SSL` | `true` | SSL verification for KSwitch API calls |
| `KSWITCH_LOCAL_INSPECTION_MODE` | `enforce` | `enforce` \| `shadow` \| `disabled`; PIJ scan behaviour |

Each upstream config object supports:
- `id` (required): unique ID used for tool name prefixing and KSwitch registration
- `command` + `args`: stdio upstream (e.g. `npx -y @mcp/postgres ...`)
- `url`: SSE/HTTP upstream (e.g. `http://localhost:8080/mcp`)
- `env`: optional environment overrides for stdio upstreams

### 7-step enforcement pipeline

Every tool call passes through seven steps before reaching (or being blocked from) the upstream MCP server:

```
Tool call received
  └─[Step 0] Reachability tick: async 30 s probe to /api/v1/health/live
  └─[Step 1] L2a floor rules: synchronous, no network, cannot be disabled
               LU-001: tool name > 128 chars → BLOCK
               LU-002: shell metacharacters in name (; | & ` $ ()) → BLOCK
               LU-003: path traversal in server ID (../ %2e%2e \0) → BLOCK
  └─[Step 2] L1 PIJ request scan: 20 regex patterns applied to JSON-serialised args
               enforce mode (default): match → BLOCK + audit log
               shadow mode: match → LOG, continue
               disabled: skip
  └─[Step 3] L2b bundle rules: LU rules from Ed25519-signed offline bundle
  └─[Step 4] Remote enforcement: POST /api/v1/enforce/mcp-call (Cedar + OPA)
               unreachable → FAIL OPEN, logged
  └─[Step 5] Upstream tool call forwarded
  └─[Step 6] Remote response inspection (control plane)
  └─[Step 7] L1 PIJ response scan: same 20 patterns applied to upstream reply
               match in enforce mode → response SUPPRESSED
```

### PIJ pattern catalogue (20 patterns)

All 20 patterns in `kswitch_mcp/data/pij-signatures.json` are applied at Steps 2 and 7:

| ID | Label | Severity |
|----|-------|----------|
| PIJ-001 | Ignore previous instructions | critical |
| PIJ-002 | System override | critical |
| PIJ-003 | New objective injection | critical |
| PIJ-004 | Role confusion: you are now | high |
| PIJ-005 | Disregard safety guidelines | critical |
| PIJ-006 | Jailbreak DAN-style | high |
| PIJ-007 | Exfil URL pattern | high |
| PIJ-008 | Prompt delimiter injection | high |
| PIJ-009 | Assistant role impersonation | high |
| PIJ-010 | Forget everything | critical |
| PIJ-011 | Hidden instruction (Unicode zero-width) | critical |
| PIJ-012 | Base64 encoded instruction block | medium |
| PIJ-013 | Credential harvest | critical |
| PIJ-014 | Sudo / privilege escalation language | high |
| PIJ-015 | Transfer funds instruction | critical |
| PIJ-016 | Alt instruction via markdown comment | medium |
| PIJ-017 | Direct address to model by name | medium |
| PIJ-018 | Naïve context terminator (control chars + JSON-escaped forms) | high |
| PIJ-019 | YAML/JSON front-matter injection | medium |
| PIJ-020 | Repeated delimiter flooding | medium |

The catalogue is in `kswitch_mcp/data/pij-signatures.json` (byte-identical to the canonical source in `schema/pij-signatures.json`). Drift between the two files is detected by `make check-pij-drift` in CI.

### Containment guarantee

| Threat | Layer | Offline? |
|--------|-------|----------|
| Shell injection via tool name | L2a LU-002 | Yes |
| Path traversal in MCP server ID | L2a LU-003 | Yes |
| Prompt injection in tool arguments | L1 request scan | Yes |
| Prompt injection in upstream response | L1 response scan | Yes |
| Org policy violation | L2b bundle rules | Yes (once bundle pulled) |
| Tier / scope violation | Remote enforcement | No (fails open, logged) |
| Toxic skill combination | Remote enforcement | No (fails open, logged) |
| Tampered bundle | Ed25519 verification | Yes |

### Bundle signing

Policy bundles are Ed25519-signed by the control plane and verified before loading. A bundle that fails verification is rejected; the previous valid bundle remains in use.

- **Control plane:** set `KSWITCH_BUNDLE_SIGNING_KEY` to a base64-encoded PEM private key.
- **Developer machine:** run `kswitch policy pull`. The CLI fetches `GET /api/v1/keys/bundle-signing`, pins the public key PEM at `~/.kswitch/bundle-signing-pubkey.pem`, then downloads and verifies the bundle.
- **Managed override:** set `KSWITCH_BUNDLE_PUBKEY_FILE=/path/to/org-bundle-signing-pubkey.pem`.
- **Dev mode:** no usable public key present → verification skipped, warning logged. A packaged placeholder PEM is treated as absent.

Pull the bundle: `kswitch policy pull`  
Check bundle status: `kswitch policy status`

### TLS / internal CA bootstrap

For local mkcert development, `kswitch-mcp` and `kswitch-proxy` auto-detect common mkcert roots. For enterprise/internal CA deployments, install the CA bundle from your platform team and export:

```bash
export KSWITCH_CA_FILE=$HOME/.kswitch/ca/acme-root-ca.pem
export KSWITCH_VERIFY_SSL=true
```

Avoid `KSWITCH_VERIFY_SSL=false` outside disposable local development.

### Local audit log

Every enforcement decision is written append-only to `~/.kswitch/local-audit.jsonl` (10 MB rotation, thread-safe). Events are synced to the control plane via `POST /api/v1/audit/local-sync`.

```bash
kswitch audit local    # list unsynced entries
kswitch audit sync     # push all pending entries to control plane
```

## License

Apache 2.0. See [LICENSE](LICENSE).
