# KSwitch.io Website Handoff - Developer Edition Terms

Date: 2026-06-26

Source repo: `KswitchDev/kswitch-devkit`

Branch: `codex/developer-edition-noncommercial-terms`

Commit / PR: see the pushed branch and draft PR for the final head SHA.

## What Changed In The DevKit Repo

- Added top-level mixed-licence map: `LICENSE.md`.
- Added Developer Edition non-commercial terms:
  `LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md`.
- Added commercial-use, trademark, privacy, security, contribution,
  dependency-licence, third-party notice, and release legal checklist files.
- Added explicit DevKit assent gate:
  `KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1`.
- Added CI legal-boundary validation:
  `scripts/validate_legal_boundary.py`.
- Aligned Python SDK metadata from MIT to Apache-2.0.

## Website Routes To Add Or Fix

1. Keep the live DevKit page:
   `https://kswitch.io/pages/devkit.html`.
2. Add a redirect or real page for the old footer link:
   `https://hub.kswitch.io/pages/developer-edition`.
3. Fix marketing-site footer links that point to `/pages/developer-edition` so
   they point to `/pages/devkit.html` or a new Developer Edition legal landing
   page.
4. Do not use `.html` links for routes that are not deployed by the static host.

## Required DevKit Page Copy

Add this near the top of the DevKit page:

```html
<div class="endpoint-card">
  <h4><span class="method-badge method-patch">LICENCE</span> Source-available, non-commercial</h4>
  <p>KSwitch Developer Edition is source-available for permitted non-commercial local development, testing, education, demos, SDK integration, and non-commercial evaluation. It is not open source. Commercial, production, customer-facing, internal business, managed-service, hosted, resale, or revenue-generating use requires a separate written KSwitch agreement.</p>
  <p>See the Developer Edition Licence in the <a href="https://github.com/KswitchDev/kswitch-devkit/blob/main/LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md">DevKit repo</a> and the commercial-use summary in <a href="https://github.com/KswitchDev/kswitch-devkit/blob/main/COMMERCIAL-USE.md">COMMERCIAL-USE.md</a>.</p>
</div>
```

Update the "Bring Up Developer Edition" block:

```html
<pre>git clone https://github.com/KswitchDev/kswitch-devkit.git
cd kswitch-devkit/devkit
cp .env.example .env

# Set KEYCLOAK_ADMIN_PASSWORD in .env to a strong local password.
# Read the Developer Edition Licence and set:
# KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1
make up</pre>
```

Update the "Developer Edition Boundary" intro:

```html
<p>Developer Edition is useful on purpose, but it is source-available, non-commercial, and local-only. It is not open source and it is not licensed for commercial, production, customer-facing, internal business, managed-service, hosted, resale, or revenue-generating use. The official unmodified artefacts enforce these caps:</p>
```

Update the boundary close:

```html
<p>Production deployment rights, commercial use, cloud packages, HA, SIEM integration, fleet operations, enterprise SSO packaging, support, and enterprise enforcement add-ons sit outside Developer Edition and require a separate written KSwitch agreement.</p>
```

## Pricing Page Copy

Developer Edition card:

```html
<p class="text-muted text-small">Source-available for permitted non-commercial local development only</p>
```

FAQ:

```html
<p class="text-muted text-small">Developer Edition is source-available under the KSwitch Developer Edition Licence for permitted non-commercial local development, testing, education, demos, SDK integration, and non-commercial evaluation. It is not open source. Commercial, production, customer-facing, internal business, managed-service, hosted, resale, or revenue-generating use requires a separate written KSwitch agreement.</p>
```

## Legal Links To Expose

Add footer or page links to:

- `https://github.com/KswitchDev/kswitch-devkit/blob/main/LICENSE.md`
- `https://github.com/KswitchDev/kswitch-devkit/blob/main/LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md`
- `https://github.com/KswitchDev/kswitch-devkit/blob/main/COMMERCIAL-USE.md`
- `https://github.com/KswitchDev/kswitch-devkit/blob/main/TRADEMARKS.md`
- `https://github.com/KswitchDev/kswitch-devkit/blob/main/PRIVACY.md`
- `https://github.com/KswitchDev/kswitch-devkit/blob/main/SECURITY.md`

## Deployment Verification

After updating `.io`, verify:

```sh
curl -fsSL https://kswitch.io/pages/devkit.html | grep -i "source-available"
curl -fsSL https://kswitch.io/pages/devkit.html | grep -i "not open source"
curl -fsSL https://kswitch.io/pages/devkit.html | grep -i "Commercial"
curl -fsSL -I https://hub.kswitch.io/pages/developer-edition
```
