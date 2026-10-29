# Ruff B905 deployment failure verification

Verified on 2026-10-29 for Hub intake
`48fa4691-7be7-469b-89e0-a8438549a29f`.

## Cause and prevention

Commit `c181286` introduced `zip(callbacks, logouts)` without an explicit
`strict` argument in `tests/test_clients.py`. It reached main without the local
Ruff check; the post-push CI lint gate caught B905 and blocked deployment in
[run 40261580910](https://github.com/DataTalksClub/auth/actions/runs/40261580910).

Commit `b5947e4` added `strict=True`, following the existing equal-length
assertion. Commit `e741073` added `make check`, which runs the same Ruff and
pytest commands as CI. Run it before pushing; `make test-node` runs the remaining
CI test command. This is a manual local gate, not an installed Git hook.

## Evidence

- Fresh fetch confirmed `origin/main` at
  `f4c4d6d89a4002395e53a465a0d5c85a163771a2`, containing both fixes.
- Local `make check`: Ruff clean and 32 pytest tests passed.
- Local `make test-node`: 3 tests passed.
- Independent read-only review found no code issues: strict zip follows the
  equal-length assertion, and the Makefile gate matches the Python CI commands.
- GitHub API inspection confirmed [run 40284391472](https://github.com/DataTalksClub/auth/actions/runs/40284391472)
  succeeded on prevention commit `e741073cf1004a2318d3bcf9a62c69541f4c552a`,
  including the test job, Deploy policy Lambda, and Verify live deployment.
- GitHub API inspection also confirmed [run 40470229131](https://github.com/DataTalksClub/auth/actions/runs/40470229131)
  succeeded on `f4c4d6d89a4002395e53a465a0d5c85a163771a2`, including those
  deployment and live verification steps.

Deployment evidence comes from the workflow's OIDC-authenticated verifier;
this verification session did not access AWS credentials or invoke AWS APIs.
