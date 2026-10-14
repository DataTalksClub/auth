# DataTalksClub shared authentication

Application-level policy and deployment verification for the shared Cognito
browser login at `https://auth.dtcdev.click`.

This repository owns:

- the federated-domain guard Lambda code;
- the public client/callback contract for protected services;
- unit and contract tests;
- live post-deployment verification;
- CI/CD for deploying the policy code through GitHub Actions OIDC.

AWS resources remain declarative in
[`DataTalksClub/aws-infra`](https://github.com/DataTalksClub/aws-infra/tree/main/sandbox/auth):
the Cognito pool and clients, custom domain, certificate, DNS, Lambda resource,
and GitHub/CloudFormation IAM roles.

## Policy

- Google is the only supported identity provider. Every app client offers
  Google sign-in only; username/password authentication is not reachable.
- Google identities must have a verified `@datatalks.club` email address.
- The restriction is enforced on both first federated signup and every later
  Google authentication. A Google `hd` hint is not an authorization boundary.
- Other Cognito trigger types pass through unchanged.

Each relying service performs authorization-code + S256 PKCE, validates the ID
token and nonce, and creates its own secure server-side session.

CLI device login for those services is `dtc_device_login` (Python) and
`dtc_device_login/login.mjs` (Node). Cognito does not issue an RFC 8628 device
grant, so each app still approves the code in its own signed-in browser session
and mints its own credential. The start, prompt, and poll loop lives here, and
every app uses it. The default routes are `POST /api/auth/device` and
`POST /api/auth/device/token`. Poll errors are `authorization_pending`,
`slow_down`, `access_denied`, and `expired_token`. A 200 response with no
`error` is that app's credential, which the caller stores.

## Development

```bash
uv run --with pytest python -m pytest
uv run --with boto3 python scripts/verify_deployment.py --live
```

The live verifier checks the deployed Cognito clients, direct Google redirects,
both allow/deny branches of the Lambda policy, and absence of disposable test
users. It does not sign in to a real Google account.

## Deployment

Pushes to `main` run tests and deploy `src/index.py` to the existing
`DomainGuardFunction` in the `dtcdev-shared-auth` stack. GitHub authenticates to
AWS with OIDC; no long-lived AWS key or Google OAuth secret is stored here.

Infrastructure changes continue through the `aws-infra` shared-auth workflow.
That workflow also reapplies the latest policy code from this repository after
CloudFormation completes, preventing the inline bootstrap implementation from
replacing the maintained runtime code.

Google OAuth credential rotation is performed in Google Cloud and AWS Secrets
Manager. GitHub stores neither the client ID nor the client secret; the
CloudFormation service role resolves them entirely within AWS.

See [Google authentication setup](docs/google-auth-setup.md) for the complete
initial setup, rotation, deployment, and verification procedure.
