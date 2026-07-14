# Shared DTC Development Authentication

The deployable authentication infrastructure is maintained with the rest of the
AWS sandbox infrastructure:

- [`../aws-infra/sandbox/auth/template.yaml`](../aws-infra/sandbox/auth/template.yaml)
- [`../aws-infra/sandbox/auth/README.md`](../aws-infra/sandbox/auth/README.md)

It provides Cognito password login and optional Google Workspace login at
`auth.dtcdev.click`, with a separate OAuth client for every protected service.

