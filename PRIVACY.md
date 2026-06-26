# Privacy

KSwitch DevKit is designed for local development.

## Telemetry

Developer Edition does not send product telemetry to KSwitch by default.

If a future release adds telemetry, it must be opt-in, documented, minimised,
and free of customer data, personal data, secrets, tokens, private URLs, policy
payloads, production logs, and sensitive environment details.

## Local Data

The local runtime may store local development data in Docker volumes and files
under `devkit/state/`, `devkit/backups/`, and related local runtime paths. Do
not use Developer Edition with customer, regulated, confidential, or production
data.

## Public Issues

Do not include secrets, tokens, customer data, private URLs, production logs,
personal data, or sensitive environment details in public GitHub issues.

