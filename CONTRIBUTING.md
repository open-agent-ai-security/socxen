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

A scheduled CI check (`.github/workflows/branch-drift.yml`) asserts the invariant
daily and fails the day the histories diverge — catching a missed fast-forward or
an accidental squash promotion before it accumulates.

### If the histories have already diverged

Don't squash-paper-over it — reconcile so the invariant holds again. Rebuild on a
**temporary branch** off `origin/main` (never `reset --hard` `dev` in place, or
you lose the commit hashes you still need):

```
git checkout -b dev-rebuild origin/main
git cherry-pick --signoff <the unreleased commits>   # the new work only
git diff origin/dev dev-rebuild                       # MUST be empty (byte-identical)
git push --force-with-lease origin dev-rebuild:dev
```

We deliberately keep the rest of the release machinery light for now: **no
tag-driven release automation, no `dependabot`** — those arrive when socxen has a
real tagged-release cadence. Until then the rules above are the whole model.

## Releasing and rolling back

*(Maintainers.)* socxen cuts releases as `dev → main` merge commits — no tags, no
release artifacts. Because fresh installs pull `main@HEAD`, **`main` is the live
release channel**: whatever lands there reaches new installers immediately.

**Cutting a release**

1. Land all changes on `dev`. Run `python3 scripts/bump_version.py X.Y.Z` (bumps
   `plugin.json`, the marketplace entry, the README pill, and regenerates the AI
   BOM), date the `CHANGELOG.md` entry by hand, commit to `dev`.
2. Open the release PR `dev → main`; promote with a **merge commit** (never
   squash), then fast-forward `dev` back up (see Branching above).
3. Run the **post-release install smoke**: `scripts/release/plugin-smoke.sh`.
   It exercises both real Claude Code journeys in throwaway scratch
   `$CLAUDE_CONFIG_DIR`s — a **clean install** of the new release and an
   **upgrade** from the prior release — and asserts the resulting version,
   never touching your live install. It is deliberately *not* in CI: the
   `claude` CLI doesn't run in GitHub Actions, so this stays a maintainer-run
   check.

**Rolling back a bad release**

1. **Stop the bleed first.** Revert the offending change on `main` with a *new
   forward commit* (`git revert`), then fast-forward `dev`. Installs track
   `main@HEAD`, so the revert reaches new installers as soon as it lands.
2. **Cut a patch release** with the real fix when ready, via the normal flow.
3. **Never force-push `main` or `dev`** to "undo" a release — rewriting history
   breaks every clone and the `main`-ancestor-of-`dev` invariant. Forward revert
   plus a patch release is the only safe path.
4. Record the incident and the fix in `CHANGELOG.md`.

## Making a change

- **One logical change per PR.** Easier to review, easier to revert.
- **Run the tests before you push:**
  ```
  uv run --with pytest --with jsonschema --with observra --with typing_extensions pytest -q tests/
  ```
  These are deterministic, no-credential invariant checks; CI runs them on every
  PR and **must be green** to merge.
- **Governance-sensitive changes get extra scrutiny.** If you touch
  `skills/soc-investigate/settings.snippet.json`, `reference/containment-tools.md`,
  `reference/tool-map.md`, or the Governance section of `SKILL.md`, keep the
  permission tiers and the containment deny-list in sync — the invariant tests
  enforce this (dismiss/close stays in `ask`, containment stays denied and matches
  the doc). Call out the governance impact in your PR description.
- **Version bumps:** run **`uv run scripts/bump_version.py X.Y.Z`** — it updates
  `.claude-plugin/plugin.json`, the plugin entry in `.claude-plugin/marketplace.json`,
  and the `version-vX.Y.Z` pill in `README.md`, then regenerates the AI BOM, and
  verifies they all agree. (If you edit by hand instead, all four must match or CI
  fails — an invariant test guards the pill↔plugin link, and `gen_aibom.py --check`
  guards the BOM against any version / connector-dep / MCP / governance drift.)
- **Evals:** if you change a fixture or the harness (`evals/`), include a recorded
  run and confirm the HARD safety gates pass. A backend/fixture is not mergeable
  without at least one grounded run.

## Reporting security issues & conduct

- Security vulnerabilities: **do not** open a public issue — see [SECURITY.md](SECURITY.md).
- Conduct: this project follows [our Code of Conduct](CODE_OF_CONDUCT.md).
