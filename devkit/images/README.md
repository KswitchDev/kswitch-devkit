# Developer Edition Images

These Dockerfiles build the public images used by the free local Developer
Edition stack.

The runtime image is a derivative image, not a source image. It must be built in
CI with access to the private platform image, then published to the public
`ghcr.io/kswitchdev` namespace.

Security posture:

- The final runtime image starts from a fresh Python base, not from the full
  platform image, so deleted private files are not retained in lower layers.
- Only runtime directories needed by the local devkit are copied.
- Customer bundles, Helm, Kubernetes, Terraform, release scripts, and docs are
  not copied into the final image.
- The Developer Edition entitlement loader is baked into the image.
- `app/` and `fleet/` Python source files are compiled to legacy `.pyc` files
  and the `.py` sources are removed.

This raises the reverse-engineering bar, but it is not DRM. Anyone who can pull
a public container can inspect its filesystem and bytecode. Do not put secrets,
customer-specific artefacts, enterprise deployment material, or unreleased
commercial modules into this image.
