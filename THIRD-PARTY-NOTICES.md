# Third-Party Notices

This repository includes SDK packages, local runtime configuration, examples,
and generated artefacts that depend on third-party software.

The current public source tree keeps package-level licence files in:

- `python/LICENSE`
- `typescript/LICENSE`
- `go/LICENSE`
- `mcp-server/LICENSE`

Package managers and container images include additional transitive
dependencies. Before any public release, refresh dependency notices for:

- Python dependencies from `python/pyproject.toml`, `python/requirements-locked.txt`,
  `mcp-server/pyproject.toml`, and `mcp-server/requirements-locked.txt`;
- TypeScript dependencies from `typescript/package-lock.json`;
- Go modules from `go/go.mod` and `go/go.sum`;
- Docker/OCI image layers referenced by `devkit/docker-compose.yml` and
  `devkit/image-digests.lock`;
- documentation assets, fonts, examples, schemas, dashboards, and generated
  OpenAPI artefacts.

Do not ship a public release until required notices are present and reviewed.

