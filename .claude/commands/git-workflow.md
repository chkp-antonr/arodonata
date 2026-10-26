---
name: "Git Workflow"
description: "Git workflow for arodonata v2 (chkpar remote, master_v2 default branch): pr/daily, pr nomerge, merge, cleanup, release"
category: "Workflow"
tags: ["workflow", "git", "pr", "merge", "release"]
---

# Git Workflow Command (`/git-workflow`)

Git workflow for `chkp-antonr/arodonata` (`chkpar` remote, default branch `master_v2`). Arguments: `$ARGUMENTS`

## Execution Routing

Based on the invocation argument (`$ARGUMENTS`), execute the corresponding flow:

- **`pr` / `daily`** → Commit staged changes (if any) on the topic branch, push to `chkpar`, create a PR against `master_v2`, wait for CI checks (if configured), squash-merge (`--squash --delete-branch`), fast-forward local `master_v2`, and delete the local topic branch. No version bump.
- **`pr nomerge`** → Same as `pr`, but stop once the PR is open and report its URL and CI status without merging.
- **`merge`** → Locate the open PR for the current topic branch, squash-merge (`--squash --delete-branch`), sync local `master_v2` (`--ff-only`), verify content parity, and delete the local topic branch.
- **`cleanup`** → Fetch `chkpar --prune`, sync `master_v2`, and delete merged/squash-merged local topic branches.
- **`release [patch|minor|major]`** → Version bump, `v<version>` release tag through a release PR targeting `master_v2`, PyPI publish via `sops` (`UV_PUBLISH_TOKEN`), and GitHub Release creation. Without an explicit increment, show the dry-run proposal and stop for confirmation.
- **No argument** → Display this reference or ask which flow to run.

## Commit Discipline for `/git-workflow pr`

Invoking `/git-workflow pr` explicitly is the go-ahead to commit staged changes, push, open a PR, and squash-merge into `master_v2`:

- **Staged changes only**: Only commit what is already staged (`git diff --cached`). Never run `git add -A` or `git commit -a` automatically inside this flow unless all changes were already staged. If nothing is staged and commits already exist on the topic branch ahead of `master_v2`, skip the commit step and proceed directly to pushing and opening the PR.
- **Conventional Commits**: Derive the commit message and PR title from the actual diff (`feat`, `fix`, `docs`, `chore`, `refactor`, `perf`, `test`, `ci`, `build`).
- **Multiple branch commits → 1 commit in `master_v2`**: A topic branch may accumulate multiple commits during development; `--squash` condenses the entire PR into a single clean commit on `master_v2`.

---

## 1. Mandatory Preflight: GitHub Account & Proxy Check

Two `gh` accounts exist on this machine (`chkp-antonr` and `arazumov_chkpsw`). `chkp-antonr` owns `chkp-antonr/arodonata`. Always verify the active account before running any `gh` command:

```bash
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
# Must show: chkp-antonr
# If not:
gh auth switch --hostname github.com --user chkp-antonr
```

---

## 2. Repository Constraints

- **Default branch**: `master_v2` (both locally in `arodonata_v2` and on `chkpar`). Legacy v1 lives in `master_v1` (`../arodonata`).
- **Remote**: `chkpar` → `git@github-chkpar.com:chkp-antonr/arodonata.git` (SSH host alias).
- **Never commit or push directly to `master_v2`**: Every change goes through a topic branch (`feat/<topic>`, `fix/<topic>`, `chore/<topic>`, `docs/<topic>`) and a Pull Request.
- **Squash-merge only**: Always merge PRs with `gh pr merge --squash --delete-branch` to keep `master_v2` linear.
- **GitHub CLI guardrail**: Never pass escaped `\n` inside quoted `--body` strings; use `--body-file` or a heredoc.

---

## 3. Workflow Procedures

### A. PR & Squash-Merge Flow (`/git-workflow pr` or `/git-workflow daily`)

```bash
# 1. Verify active branch is a topic branch (NEVER master_v2)
TOPIC_BRANCH=$(git branch --show-current)
if [ "$TOPIC_BRANCH" = "master_v2" ]; then
  echo "ERROR: Switch to a topic branch (e.g. git checkout -b feat/<topic>) before running /git-workflow pr"
  exit 1
fi

# 2. If there are staged changes, commit them (skip if working tree is clean and commits are already made)
git diff --cached --stat
# Only if staged changes exist:
git commit -m "<type>(<scope>): <description>"

# 3. Push topic branch to chkpar
git push -u chkpar "$TOPIC_BRANCH"

# 4. Ensure chkp-antonr account is active and create PR against master_v2
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
gh pr create --repo chkp-antonr/arodonata \
  --base master_v2 \
  --head "$TOPIC_BRANCH" \
  --title "<type>(<scope>): <description>" \
  --body "<summary of changes and verification>"

# 5. Stop here if invoked as `/git-workflow pr nomerge`
# Otherwise, check CI status (if checks exist on the repo):
gh pr checks --repo chkp-antonr/arodonata --watch --fail-fast || true

# 6. Squash-merge PR into master_v2 and delete remote topic branch
PR_NUMBER=$(gh pr view --repo chkp-antonr/arodonata --json number --jq '.number')
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata

# 7. Return to master_v2 and fast-forward sync
git checkout master_v2
git pull chkpar master_v2 --ff-only

# 8. Verify content parity and delete local topic branch
git diff master_v2 "$TOPIC_BRANCH" --stat   # must output nothing
git branch -D "$TOPIC_BRANCH"
```

---

### B. Merge Existing PR Flow (`/git-workflow merge`)

Use when a PR is already open (e.g. after `/git-workflow pr nomerge` or manual review) and ready to squash-merge into `master_v2`:

```bash
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"

TOPIC_BRANCH=$(git branch --show-current)
PR_NUMBER=$(gh pr list --repo chkp-antonr/arodonata --head "$TOPIC_BRANCH" --json number --jq '.[0].number')

# 1. Squash-merge and delete remote branch
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata

# 2. Switch to master_v2 and pull squashed commit
git checkout master_v2
git pull chkpar master_v2 --ff-only

# 3. Verify content parity and delete local topic branch
git diff master_v2 "$TOPIC_BRANCH" --stat   # must output nothing
git branch -D "$TOPIC_BRANCH"
```

---

### C. Cleanup Flow (`/git-workflow cleanup`)

Prune remote-tracking branches, sync `master_v2`, and clean up any leftover local topic branches whose contents are already in `master_v2`:

```bash
git fetch chkpar --prune
git checkout master_v2
git pull chkpar master_v2 --ff-only

# Delete standard merged branches:
git branch --merged master_v2 | grep -v "master_v2\|\*" | xargs -r git branch -d

# For squash-merged branches not detected by --merged, verify empty diff against master_v2 first:
for b in $(git for-each-ref --format='%(refname:short)' refs/heads/ | grep -v '^master_v2$'); do
  if [ -z "$(git diff master_v2 "$b" --stat)" ]; then
    git branch -D "$b"
  else
    echo "Keeping unmerged branch: $b"
  fi
done
```

---

### D. Release Flow (`/git-workflow release [patch|minor|major]`)

`cz bump` (`update_changelog_on_bump = true`) replaces `## [Unreleased]` with `## v<B> (<date>)` and auto-generated commit bullets. Always save any hand-written `## [Unreleased]` notes before running `cz bump` and merge them into the `## v<B> (<date>)` section afterwards.

```bash
# 1. Preconditions: clean tree on master_v2 synced with chkpar/master_v2
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
git checkout master_v2 && git fetch chkpar && git pull chkpar master_v2 --ff-only
git status --short

# 2. Preview version bump (stop and ask user if increment was not specified)
uv run cz bump --dry-run --yes [--increment PATCH|MINOR|MAJOR]

# 3. Create release branch, preserve hand-written [Unreleased] notes, bump version, update lockfile, run quality gates
git checkout -b release/v<B>
uv run cz bump --yes [--increment PATCH|MINOR|MAJOR]
# Restore/merge hand-written notes into CHANGELOG.md under ## v<B> (<date>) and format markdown:
npx markdownlint-cli "CHANGELOG.md" --fix
uv lock
git add CHANGELOG.md pyproject.toml src/arodonata/__init__.py uv.lock && git commit --amend --no-edit
git tag -d v<B>   # remove local pre-squash tag; tag will be placed on master_v2 after squash-merge

# 4. Push release branch, create PR, squash-merge into master_v2
git push -u chkpar release/v<B>
gh pr create --repo chkp-antonr/arodonata \
  --base master_v2 \
  --head release/v<B> \
  --title "chore(release): bump version to v<B>" \
  --body "<release notes from CHANGELOG.md>"
PR_NUMBER=$(gh pr view --repo chkp-antonr/arodonata --json number --jq '.number')
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata

# 5. Sync master_v2, tag the squashed commit on master_v2, push tag, delete local release branch
git checkout master_v2 && git pull chkpar master_v2 --ff-only
git tag -a v<B> -m "Release v<B>" "$(git rev-parse HEAD)"
git push chkpar v<B>
git diff master_v2 release/v<B> --stat   # must output nothing
git branch -D release/v<B>

# 6. Build distributions, publish to PyPI via sops prod (UV_PUBLISH_TOKEN), and create GitHub Release
rm -rf dist/
uv build
sops exec-env "$HOME/c/sops/prod.env.enc" -- uv publish
gh release create "v<B>" dist/* \
  --repo chkp-antonr/arodonata \
  --title "v<B>" \
  --notes "<release notes from CHANGELOG.md>"
```
