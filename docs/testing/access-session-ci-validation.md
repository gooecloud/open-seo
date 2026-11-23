# Access-session CI validation

This temporary pull request exists only to trigger the repository's normal CI
workflow against the exact long-lived access-session implementation commit.

- Validation base: `5756715ec310d106dcf48c7226635acb1b47d968`
- Source branch: `feat/seo-long-lived-access-session`
- No application source, deployment configuration, secrets, or Cloudflare
  resources are changed by this validation branch.
- This documentation-only change is excluded by the PR Preview workflow's
  path filters; it must not deploy a Worker or create Cloudflare resources.

Expected CI checks on the PR:
- `pnpm run ci:check`
- `pnpm run test:ci`
- Worker build
- Website protection tests, type checks, and build
- Docker image build

This is CI validation only. It does not prove Cloudflare Access path behavior,
real browser login, persistent-cookie behavior, D1 session persistence, or
administrator revocation. Those require a separately provisioned isolated
Preview environment and real end-to-end tests.
