# EP-227 Image SBOM Engineering Summary

Status: BLOCKED_KSWITCH_IMAGE_UNAVAILABLE.

Generated with Syft from registry sources on 2026-06-21:

- `sbom-postgres-18.syft.json`
- `sbom-keycloak-25.0.syft.json`
- `sbom-valkey-8.syft.json`
- `sbom-falkordb-latest.syft.json`
- `sbom-opa-1.15.1-envoy-static.syft.json`
- `sbom-spire-server-1.11.0.syft.json`
- `sbom-spire-agent-1.11.0.syft.json`

The KSwitch application image reference
`ghcr.io/maxcope-alt/kswitch:v1.39.0-pg` denied unauthenticated registry access
during evidence generation. Public Developer Edition release remains blocked
until KSwitch publishes an accessible Developer Edition image reference and
attaches the matching SBOM, vulnerability scan, secret scan, licence inventory,
and provenance evidence.
