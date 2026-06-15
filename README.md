# KSwitch SDKs

Official SDK packages for the KSwitch Agent Trust Control Plane.

This repository is intentionally narrow. It contains only SDK source, SDK examples, SDK schemas, and SDK hardening notes. Marketing-site assets, platform services, and unrelated product documentation stay out of this repo so the Developer Hub can link here cleanly.

## Packages

| Language | Path | Package |
| --- | --- | --- |
| Python | `python/` | `kswitch-sdk` |
| TypeScript | `typescript/` | `@kswitch/sdk` |
| Go | `go/` | `github.com/KswitchDev/kswitch-sdks/go` |

The current SDK release train is recorded in [`SDK_VERSION`](SDK_VERSION).

## Developer Hub

- [Python SDK docs](https://kswitch.io/sdk/python.html)
- [TypeScript SDK docs](https://kswitch.io/sdk/typescript.html)
- [Go SDK docs](https://kswitch.io/sdk/go.html)

## Local Checks

Python:

```sh
cd python
python -m pip install -e ".[dev]"
pytest tests -q
```

TypeScript:

```sh
cd typescript
npm ci
npm test
```

Go:

```sh
cd go
go test ./...
```

## Licenses

Each SDK package carries its own license file:

- `python/LICENSE`
- `typescript/LICENSE`
- `go/LICENSE`
