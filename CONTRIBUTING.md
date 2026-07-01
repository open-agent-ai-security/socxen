<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Contributing to socxen

Thanks for helping improve socxen. Contributions are welcome via pull request.
socxen is a small, safety-sensitive project — an agentic SOC-analyst skill whose
whole value is a disciplined investigation and a **human-gated** dismiss/close.
So the bar for changes that touch the governance surface is high, and a couple of
conventions below exist specifically to keep that gate real.

## License

socxen is licensed under the [Apache License, Version 2.0](LICENSE). By
contributing, you agree that your contributions are licensed under the same terms.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA — a lightweight way to certify you wrote the contribution, or
otherwise have the right to submit it under the project's license.

Add a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git adds it for you with `-s`:

```
git commit -s -m "Your commit message"
```

The name and email must be a real identity. Sign-off is **required**; we don't
gate it in CI yet, so a maintainer may ask you to amend an unsigned commit before
merge.

<details><summary>Full DCO text</summary>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this license
document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications, whether
    created in whole or in part by me, under the same open source license
    (unless I am permitted to submit under a different license), as indicated in
    the file; or

(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public and
    that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may be
    redistributed consistent with this project or the open source license(s)
    involved.
```
</details>

## Branching

Branch from and target **`dev`**, not `main`.

`main` is the **live install channel**: a fresh
`claude plugin marketplace add open-agent-ai-security/socxen && claude plugin install socxen@socxen`
pulls `main` at HEAD, so anything merged to `main` reaches installers immediately.
`main` therefore receives only deliberate, re-verified releases — everyday work
lands on `dev` first.

When you open a PR, GitHub pre-selects the base as the repository default; confirm
it's **`dev`** unless you are specifically cutting a release.

The invariant we hold: **`main` is always an ancestor of `dev`** — `dev` is `main`
plus the unreleased work, never a divergent history.

- **Feature work → `dev`: squash-merge.** Short-lived branches, deleted on merge.
- **Release `dev → main`: merge commit, never squash** (`gh pr merge <n> --merge`).
  A squash discards the shared-parent link and drifts the branches apart. Author
  the version bump + `CHANGELOG` on `dev` first, promote with a merge commit, then
  **fast-forward `dev` back up** so `main` stays an ancestor:
  ```
  git fetch origin && git checkout dev && git merge --ff-only origin/main && git push origin dev
  ```

We deliberately keep the release machinery light for now: **no tag-driven release
automation, no scheduled branch-drift check, no `dependabot`** — those arrive when
socxen has a real tagged-release cadence. Until then the two rules above are the
whole model.

## Making a change

- **One logical change per PR.** Easier to review, easier to revert.
- **Run the tests before you push:**
  ```
  uv run --with pytest pytest -q tests/
  ```
  These are deterministic, no-credential invariant checks; CI runs them on every
  PR and **must be green** to merge.
- **Governance-sensitive changes get extra scrutiny.** If you touch
  `skills/soc-investigate/settings.snippet.json`, `reference/containment-tools.md`,
  `reference/tool-map.md`, or the Governance section of `SKILL.md`, keep the
  permission tiers and the containment deny-list in sync — the invariant tests
  enforce this (dismiss/close stays in `ask`, containment stays denied and matches
  the doc). Call out the governance impact in your PR description.
- **Version bumps go in three places together:** `.claude-plugin/plugin.json`,
  the plugin entry in `.claude-plugin/marketplace.json`, **and** the
  `version-vX.Y.Z` pill in `README.md`. An invariant test fails if the README pill
  drifts from `plugin.json`, so bump all three in the same commit.
- **Evals:** if you change a fixture or the harness (`evals/`), include a recorded
  run and confirm the HARD safety gates pass. A backend/fixture is not mergeable
  without at least one grounded run.

## Reporting security issues & conduct

- Security vulnerabilities: **do not** open a public issue — see [SECURITY.md](SECURITY.md).
- Conduct: this project follows [our Code of Conduct](CODE_OF_CONDUCT.md).
