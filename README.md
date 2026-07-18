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
