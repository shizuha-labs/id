# Identity complete-suite gate

`ci/run_identity_test_gate.py` discovers every identity test. The exact-ID
ratchet in `ci/identity_test_baseline.json` is now empty: any failure or error
fails CI. An empty baseline is a valid debt-free state, not permission to skip
execution. Duplicate, malformed, and out-of-scope baseline entries are rejected.
If an explicitly recorded historical failure becomes green, the gate also
requires removing that entry rather than silently leaving stale exceptions.

The former 17 exceptions were repaired at their test boundaries:

- Reuse the migration-seeded QA group and verify actual RS256 platform tokens.
- Exercise the authenticated scoped fleet-provisioning route and configured social
  registration adapter; assert approved agent and pending human states.
- Approve the admin deletion fixture through the audited lifecycle, retaining
  the pending-delete rejection and regular/staff authorization controls.
- Supply an authoritative membership projection for successful token-counter
  fixtures. The independent projection suite still requires typed 503 responses
  on unavailable authority and verifies a later healthy refresh succeeds.
- Use current auth-prefixed admin routes and signature-verified platform token
  claims when checking grants, revocation, and admin/token report consistency.

`identity.tests.test_identity_full_gate_contract` exercises clean success,
failures and errors with an empty baseline, exact known failures, newly passing
entries, and malformed baseline inputs. Application authorization and signing
behavior are unchanged by this test cleanup.
