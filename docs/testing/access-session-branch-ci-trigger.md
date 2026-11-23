# Access-session validation notes

This file records the CI trigger for the long-lived access-session branch.

The source changes are validated by the repository pull-request CI workflow.
This documentation-only commit is intended to produce a pull_request
synchronize event on PR #1. The PR Preview workflow ignores Markdown and docs,
so it must not deploy a Worker or modify Cloudflare resources.

A successful CI run is not equivalent to Cloudflare Access or browser end-to-end
validation. Those checks require the separately provisioned isolated preview.
