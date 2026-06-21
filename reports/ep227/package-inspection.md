# EP-227 Package Inspection

Status: ENGINEERING SOURCE INSPECTION COMPLETE - final artefact inspection is
completed at release-tag time and approval is tracked in
`RELEASE-LEGAL-CHECKLIST.md`.

Source inspection scope:

| Package | Boundary |
| --- | --- |
| Python | `python/kswitch/`, `python/examples/`, `python/pyproject.toml`, `python/LICENSE` |
| TypeScript | `typescript/src/`, `typescript/examples/`, `typescript/package.json`, `typescript/LICENSE` |
| Go | `go/kswitch/`, `go/examples/`, `go/go.mod`, `go/LICENSE` |

Engineering source review result:

- SDK package trees do not include `devkit/`.
- SDK package trees do not include Developer Edition entitlement overlays.
- SDK package trees do not include image manifests, Docker compose files, or
  public devkit configuration.
- SDK package trees do include SDK-side local developer helpers for local PDP,
  bundle/context cache, revocation, WIMSE/SPIFFE, audit, and execution-token
  flows; those files are classified in `sdk-ip-boundary.csv`.

Final artefact inspection must record reproducible evidence for the Python
sdist/wheel, npm tarball, Go module contents, generated clients, examples, and
release archive before publication.
