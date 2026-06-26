# SDK Authentication Model

KSwitch ships workload identity support so service workloads can authenticate
without distributing long-lived shared application secrets.

Public SDK examples should lead with workload-bound identity for
service-to-service calls. OAuth2 client credentials remain available as a
compatibility bridge for environments that cannot issue workload-bound tokens
yet.

## Preferred Order

1. **Human/local development:** OAuth2 PKCE using the DevKit CLI.
2. **Service-to-service:** workload identity using SPIFFE JWT-SVID or WIMSE.
3. **Transport identity:** mTLS where deployment policy binds clients by
   certificate identity.
4. **Fallback:** OAuth2 client credentials when the deployment cannot issue
   workload identity.

## Why Workload Identity

Workload identity gives KSwitch a concrete, cryptographically bound service
identity without asking developers to distribute long-lived shared secrets:

- The workload obtains a short-lived identity document from the local trust
  fabric.
- The private key stays with the workload identity provider.
- Rotation is automatic.
- Revocation and trust-domain policy can be centralized.
- The SDK sends a bearer JWT-SVID or WIMSE-derived assertion to KSwitch.

## DevKit Default

DevKit should run SPIRE locally and make this path easy:

```text
agent process
  -> SPIRE Workload API
  -> JWT-SVID / WIMSE assertion
  -> KSwitch API Authorization: Bearer <assertion>
```

Human examples may still use PKCE tokens. Static bearer tokens are acceptable for
copy-paste local examples when clearly labelled as local/dev only.

## Client Credentials Fallback

Client credentials remain in each SDK for existing Keycloak, Logto, Entra,
Okta, or other OAuth2 client-credentials deployments. The docs should frame them
like this:

```text
Use this only when your deployment cannot issue SPIFFE/WIMSE or another
workload-bound token.
```

Required handling:

- Never hard-code the secret in examples.
- Read from an environment variable or secret manager.
- Scope the client narrowly.
- Rotate regularly.
- Prefer short access-token lifetimes.

## Current SDK Gap

The SDKs already contain SPIFFE/WIMSE helper code in the language packages, but
the public `KSwitchClient` auth examples still need a first-class token provider
or refresh hook in each SDK so JWT-SVID/WIMSE tokens can be refreshed
automatically.
