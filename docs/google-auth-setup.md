# Google authentication setup

This guide connects one Google OAuth web client to the shared Cognito user pool
at `auth.dtcdev.click`. Cognito then serves Google login to Dapier, DataOps,
System Design Studio, AI Engineering Gym, and Datamailer. Do not create a
separate Google OAuth client for each service: Google returns to Cognito first,
and Cognito returns to the selected service client afterward.

## Before you start

You need:

- permission to manage a Google Cloud project associated with the
  `datatalks.club` Google Workspace organization;
- permission to update `dtcdev-shared-auth/google-oauth` in AWS Secrets Manager;
- permission to run that repository's shared-auth deployment workflow;
- access to one `@datatalks.club` Google account for the allowed test and one
  non-domain Google account for the rejection test.

Never paste the OAuth client secret into chat, an issue, a command argument that
will be logged, or a tracked file.

## 1. Configure the Google Auth Platform audience

1. Open the Google Cloud console and select the project that will own the OAuth
   client.
2. Open **Google Auth Platform → Branding** and configure:
   - app name: `DataTalksClub Development Auth`;
   - a monitored `@datatalks.club` user-support email;
   - developer contact information;
   - `dtcdev.click` as an authorized domain if the console requests it.
3. Open **Google Auth Platform → Audience**.
4. Select **Internal** when the project belongs to the `datatalks.club` Google
   Workspace organization. This is preferred because Google then limits the app
   to organization members before Cognito's own domain guard runs.
5. If **Internal** is unavailable, select **External**. While the app remains in
   Testing, add every allowed `@datatalks.club` account under **Test users**.
   Publish or verify the app before expecting other users to sign in.

The AWS domain-guard Lambda remains mandatory even with an Internal audience.
It validates the mapped, verified email during first federation and every later
Google authentication rather than trusting a browser-supplied domain hint.

## 2. Create the OAuth web client

Open **Google Auth Platform → Clients**, select **Create client**, and use:

| Field | Value |
|---|---|
| Application type | Web application |
| Name | `DTC Development Cognito` |
| Authorized JavaScript origin | `https://auth.dtcdev.click` |
| Authorized redirect URI | `https://auth.dtcdev.click/oauth2/idpresponse` |

The redirect URI must match exactly, including HTTPS and the
`/oauth2/idpresponse` path. This is Cognito's identity-provider response
endpoint, not any individual service callback.

After selecting **Create**, securely capture the client ID and client secret.
The client ID is not confidential; the client secret is.

## 3. Store the credentials for deployment

Open AWS Secrets Manager in `us-east-1` and create a secret named:

```text
dtcdev-shared-auth/google-oauth
```

Choose **Other type of secret** and store two key/value pairs:

| Key | Value |
|---|---|
| `client_id` | The Google OAuth client ID |
| `client_secret` | The matching Google OAuth client secret |

GitHub stores neither value. The GitHub deployment role can inspect only the
secret's version metadata; the CloudFormation service role resolves the actual
values within AWS and supplies them directly to Cognito.

## 4. Deploy the Cognito provider

Run **Deploy shared authentication** in `DataTalksClub/aws-infra`:

```bash
gh workflow run deploy-shared-auth.yml --repo DataTalksClub/aws-infra
```

The workflow uses GitHub OIDC to assume the least-privilege AWS deployment
role, reads the current non-secret version ID, updates the
`dtcdev-shared-auth` stack in `us-east-1`, and verifies the Google provider.
Only CloudFormation's AWS service role can read the credential value.

After it succeeds, this repository's **CI and deploy auth policy** workflow
deploys and verifies the domain-guard Lambda independently. It does not need or
read the Google OAuth client secret.

## 5. Verify the deployment

The automated verifier requires AWS access but no user credentials:

```bash
uv run --with boto3 python scripts/verify_deployment.py --live
```

It checks that all five Cognito application clients enable `Google` as their
only identity provider, their callback/logout registrations match
`config/clients.json`, the Google provider maps the `email` and `email_verified`
claims the guard reads, each Google authorization request reaches
`accounts.google.com`, the deployed guard allows a verified `@datatalks.club`
address and rejects both another domain and a missing `email_verified`, and no
disposable Codex test users remain.

Then use private browser windows for the two human checks:

1. Sign in with a real `@datatalks.club` Google account and confirm the service
   returns to its authenticated page.
2. Sign out from both the service and Google/Cognito, open a fresh private
   window, and attempt sign-in with a non-domain Google account. Confirm it is
   rejected.

Repeat the allowed login once for each service because each has its own Cognito
client and callback:

- `https://dapier.dtcdev.click/auth/login`
- `https://ops.dtcdev.click/login`
- `https://sds.dtcdev.click/login`
- `https://gym.dtcdev.click/login`
- `https://datamailer.dtcdev.click/admin/login/`

Do not record passwords, authorization codes, cookies, ID tokens, or the OAuth
client secret in screenshots or issue comments.

## Rotate a Google OAuth client secret

Create a replacement **Web application** client using the same origin and
redirect URI. Google client secrets should be treated as passwords; do not try
to recover or reuse a value that may have been exposed.

Use this order to avoid unnecessary downtime:

1. Create the replacement Google OAuth client.
2. Create a new version of `dtcdev-shared-auth/google-oauth` in AWS Secrets
   Manager with the replacement `client_id` and `client_secret` values.
3. Run the `aws-infra` shared-auth deployment workflow; it passes the new
   version ID so Cognito refreshes both values.
4. Complete an allowed Google sign-in.
5. delete the old OAuth client in Google Cloud;
6. rerun the automated verifier and the non-domain rejection test.

## Troubleshooting

- `redirect_uri_mismatch`: compare the Google client redirect character for
  character with `https://auth.dtcdev.click/oauth2/idpresponse`.
- Google says access is limited to test users: add the account under Audience →
  Test users, publish the External app, or use an Internal Workspace project.
- Cognito returns to an invalid callback: compare the service with
  `config/clients.json` and the Cognito app-client callback list.
- A non-domain account signs in: stop testing, disable Google on the Cognito
  clients, and inspect the deployed PreSignUp and PreAuthentication Lambda
  triggers before restoring access.

## Primary documentation

- [Google: manage OAuth clients](https://support.google.com/cloud/answer/15549257)
- [Google: OAuth web-server applications](https://developers.google.com/identity/protocols/oauth2/web-server)
- [AWS: add Google as a Cognito social provider](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-social-idp.html)
- [AWS: federation endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html)
