# Ruff B905 deployment failure verification

Verified on 2026-11-02 for Hub intake
`48fa4691-7be7-469b-89e0-a8438549a29f`.

## Cause and prevention

Commit `c181286` introduced `zip(callbacks, logouts)` without an explicit
`strict` argument in `tests/test_clients.py`. It was pushed directly to `main`
without a local Ruff check; at the time, the repository had no local hook or
agent `make check` gate. Ruff ran only after the push, so CI caught B905 after
the commit was already on `main` and blocked deployment in
[run 40261580910](https://github.com/DataTalksClub/auth/actions/runs/40261580910).

Commit `b5947e4` added `strict=True`, following the existing equal-length
assertion. Commit `e741073` added `make check`, which runs the same Ruff and
pytest commands as CI. Run it before pushing; `make test-node` runs the remaining
CI test command. This is a manual local gate, not an installed Git hook.

## Evidence

- `origin/main` at `9be3bf5be087ec08328dd8a23a726474d0505724` contains both
  the strict zip fix and the `make check` prevention target.
- Local re-verification: `make check` passed (Ruff clean; 32 pytest tests
  passed), and `make test-node` passed (3 tests).
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
