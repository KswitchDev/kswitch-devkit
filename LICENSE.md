# KSwitch DevKit Licence Map

This repository is mixed-licence. Do not assume that the licence for one
directory applies to the whole repository.

## Apache-2.0 SDK And Client Surfaces

The following paths are licensed under the Apache License, Version 2.0, unless a
file in that path says otherwise:

- `python/`
- `typescript/`
- `go/`
- `mcp-server/`
- SDK-only examples and documentation that do not require the local DevKit
  runtime

The canonical Apache-2.0 notice is in
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

## KSwitch DevKit Surfaces

The following paths are source-available under the KSwitch DevKit
Licence:

- `devkit/`
- DevKit compose files, runtime configuration, seed material,
  entitlement overlays, local lifecycle scripts, dashboards, policy bundles, and
  generated DevKit release artefacts
- DevKit documentation and examples that require the local runtime

The KSwitch DevKit Licence is in
[`LICENSES/KSWITCH-DEVKIT-LICENSE.md`](LICENSES/KSWITCH-DEVKIT-LICENSE.md).

DevKit is not open source. It is free only for permitted
non-commercial local development, testing, education, demos, SDK integration,
and non-commercial evaluation. Commercial evaluation and commercial,
production, customer-facing, internal business, managed-service, hosted,
resale, or revenue-generating use are outside DevKit and require a scoped
KSwitch POC engagement or separate written agreement before use. See
[`COMMERCIAL-USE.md`](COMMERCIAL-USE.md).

## Trademarks

KSwitch names, logos, marks, product names, screenshots, badges, and trade dress
are not licensed except for nominative use needed to identify the origin of this
software. See [`TRADEMARKS.md`](TRADEMARKS.md).

## Third-Party Material

Third-party dependencies, generated files, and image layers remain under their
own licences. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and
[`DEPENDENCY-LICENSE-POLICY.md`](DEPENDENCY-LICENSE-POLICY.md).
