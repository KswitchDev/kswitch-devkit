# SDK Authentication Model

KSwitch SDK examples should not present `client_id` + `client_secret` as the
preferred service-to-service posture.

Client credentials work, but they create a shared secret that must be provisioned,
stored, rotated, revoked, and protected in every workload environment. That is a
reasonable compatibility option for legacy IdPs. It is not the identity model
KSwitch should lead with.

## Preferred Order

1. **Human/local development:** OAuth2 PKCE using the Developer Edition CLI.
2. **Service-to-service:** workload identity using SPIFFE JWT-SVID or WIMSE.
3. **Transport identity:** mTLS where deployment policy binds clients by
   certificate identity.
4. **Fallback:** OAuth2 client credentials when the deployment cannot issue
   workload identity.

## Why Workload Identity

Workload identity gives the platform a concrete identity binding without asking
developers to distribute long-lived shared secrets:

- The workload obtains a short-lived identity document from the local trust
  fabric.
- The private key stays with the workload identity provider.
- Rotation is automatic.
- Revocation and trust-domain policy can be centralized.
- The SDK sends a bearer JWT-SVID or WIMSE-derived assertion to KSwitch.

## Developer Edition Default

Developer Edition can run SPIRE locally with `make up-with-identity` and make
this path easy:

```text
agent process
  -> SPIRE Workload API
  -> JWT-SVID / WIMSE assertion
  -> KSwitch API Authorization: Bearer <assertion>
```

Human examples may still use PKCE tokens. Static bearer tokens are acceptable for
copy-paste local examples when clearly labelled as local/dev only.

## Client Credentials Fallback

Client credentials may remain in each SDK because customers will have existing
Keycloak, Logto, Entra, or Okta client-credentials flows. The docs should frame
them like this:

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
the public `KSwitchClient` auth examples still lead with static bearer tokens
and client credentials. Before the docs promise one-line workload auth, add a
first-class token provider or refresh hook in each SDK so JWT-SVID/WIMSE tokens
can be refreshed automatically.
