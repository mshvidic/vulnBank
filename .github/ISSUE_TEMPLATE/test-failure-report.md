---
name: Automated Test Failure Report
about: Automatically created when security regression tests fail.
title: "[Security Regression] Automated Test Suite Failure Detected"
labels: ["bug", "automated-test", "security"]
assignees: []
---

### 🚨 Automated Test Failure Notice

The automated security regression test suite (`access-control.spec.ts`) detected failing test cases during the latest CI/CD run. This indicates that one or more access control vulnerabilities (IDs #8 through #13) are still present in the application.

* **Workflow Run:** ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
* **Commit:** ${{ github.sha }}
* **Triggered by:** ${{ github.actor }}

#### Next Steps:
1. Review the failing test logs in the workflow link above.
2. Fix the corresponding flaw in `server/index.js`.
3. Re-run the tests locally using `npx playwright test access-control.spec.ts` until all security assertions turn green.