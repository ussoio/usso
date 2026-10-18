# USSO core and overlay contract

- `main` and `pure` represent the same stable, provider-neutral core. Keep their
  accepted core content synchronized. Neither contains product-specific
  provisioning, branding, URLs, credentials or integration implementations.
- `ice` is the same core plus reviewed ICE-only tools and integrations. Keep
  shared fixes in the core and product customization in an explicit overlay.
- Develop on feature branches. Merge only after relevant tests, lint, formatting,
  type and build checks pass. Never treat work in progress as a stable release.
- Inventory maintained repositories, local work and deployments before declaring
  synchronization complete. Preserve local changes and never overwrite them.
- Deployments select trusted modules through `USSO_EXTENSION_MODULES`; each module
  exports `install(app)` and uses the existing registration hooks. The default
  core starts with no product overlay.
- Never commit environment files, credential backups, private agent settings or
  generated output. Keep public configuration examples free of deployment values.
- Publishing or deploying a service requires explicit authorization. Verify the
  real deployed artifact and affected flow before declaring a release complete.

Source: user clarifications on 2026-10-18.
