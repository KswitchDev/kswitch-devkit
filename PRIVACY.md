# Privacy and Telemetry

Default posture: telemetry is off by default.

Developer Edition must not collect personal data, customer data, sensitive
payloads, secrets, tokens, policy contents, or internal hostnames by default.

Any future telemetry must be opt-in, documented, minimised, and reviewed before
release. The review must describe:

- data fields collected;
- purpose;
- retention;
- destination;
- opt-in and opt-out controls;
- whether a privacy notice update is required.

Public issue and pull request templates warn contributors not to submit secrets,
personal data, customer data, or proprietary third-party code.
