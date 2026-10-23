---
name: "Git Workflow"
description: "Git workflow for arodonata_v2 (chkpar remote): pr/daily, pr nomerge, merge, cleanup, release"
category: "Workflow"
tags: ["workflow", "git", "pr", "merge", "release"]
---

# Git Workflow Command (`/git-workflow`)

Git workflow for `chkp-antonr/arodonata_v2` (`chkpar` remote, default branch `master`). Arguments: `$ARGUMENTS`

## Execution Routing

Based on the invocation argument (`$ARGUMENTS`), execute the corresponding flow:

- **`pr` / `daily`** → Commit staged changes (if any) on the topic branch, push to `chkpar`, create a PR against `master`, wait for CI checks (if configured), squash-merge (`--squash --delete-branch`), fast-forward local `master`, and delete the local topic branch. No version bump.
- **`pr nomerge`** → Same as `pr`, but stop once the PR is open and report its URL and CI status without merging.
- **`merge`** → Locate the open PR for the current topic branch, squash-merge (`--squash --delete-branch`), sync local `master` (`--ff-only`), verify content parity, and delete the local topic branch.
- **`cleanup`** → Fetch `chkpar --prune`, sync `master`, and delete merged/squash-merged local topic branches.
- **`release [patch|minor|major]`** → Version bump and `v<version>` release tag through a release PR targeting `master`. Without an explicit increment, show the dry-run proposal and stop for confirmation.
- **No argument** → Display this reference or ask which flow to run.

## Commit Discipline for `/git-workflow pr`

Invoking `/git-workflow pr` explicitly is the go-ahead to commit staged changes, push, open a PR, and squash-merge into `master`:

- **Staged changes only**: Only commit what is already staged (`git diff --cached`). Never run `git add -A` or `git commit -a` automatically inside this flow unless all changes were already staged. If nothing is staged and commits already exist on the topic branch ahead of `master`, skip the commit step and proceed directly to pushing and opening the PR.
- **Conventional Commits**: Derive the commit message and PR title from the actual diff (`feat`, `fix`, `docs`, `chore`, `refactor`, `perf`, `test`, `ci`, `build`).
- **Multiple branch commits → 1 commit in `master`**: A topic branch may accumulate multiple commits during development; `--squash` condenses the entire PR into a single clean commit on `master`.

---

## 1. Mandatory Preflight: GitHub Account & Proxy Check

Two `gh` accounts exist on this machine (`chkp-antonr` and `arazumov_chkpsw`). `chkp-antonr` owns `chkp-antonr/arodonata_v2`. Always verify the active account before running any `gh` command:

```bash
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
# Must show: chkp-antonr
# If not:
gh auth switch --hostname github.com --user chkp-antonr
```

---

## 2. Repository Constraints

- **Default branch**: `master` (both locally and on `chkpar`).
- **Remote**: `chkpar` → `git@github-chkpar.com:chkp-antonr/arodonata_v2.git` (SSH host alias).
- **Never commit or push directly to `master`**: Every change goes through a topic branch (`feat/<topic>`, `fix/<topic>`, `chore/<topic>`, `docs/<topic>`) and a Pull Request.
- **Squash-merge only**: Always merge PRs with `gh pr merge --squash --delete-branch` to keep `master` linear.
- **GitHub CLI guardrail**: Never pass escaped `\n` inside quoted `--body` strings; use `--body-file` or a heredoc.

---

## 3. Workflow Procedures

### A. PR & Squash-Merge Flow (`/git-workflow pr` or `/git-workflow daily`)

```bash
# 1. Verify active branch is a topic branch (NEVER master)
TOPIC_BRANCH=$(git branch --show-current)
if [ "$TOPIC_BRANCH" = "master" ]; then
  echo "ERROR: Switch to a topic branch (e.g. git checkout -b feat/<topic>) before running /git-workflow pr"
  exit 1
fi

# 2. If there are staged changes, commit them (skip if working tree is clean and commits are already made)
git diff --cached --stat
# Only if staged changes exist:
git commit -m "<type>(<scope>): <description>"

# 3. Push topic branch to chkpar
git push -u chkpar "$TOPIC_BRANCH"

# 4. Ensure chkp-antonr account is active and create PR against master
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
gh pr create --repo chkp-antonr/arodonata_v2 \
  --base master \
  --head "$TOPIC_BRANCH" \
  --title "<type>(<scope>): <description>" \
  --body "<summary of changes and verification>"

# 5. Stop here if invoked as `/git-workflow pr nomerge`
# Otherwise, check CI status (if checks exist on the repo):
gh pr checks --repo chkp-antonr/arodonata_v2 --watch --fail-fast || true

# 6. Squash-merge PR into master and delete remote topic branch
PR_NUMBER=$(gh pr view --repo chkp-antonr/arodonata_v2 --json number --jq '.number')
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata_v2

# 7. Return to master and fast-forward sync
git checkout master
git pull chkpar master --ff-only

# 8. Verify content parity and delete local topic branch
git diff master "$TOPIC_BRANCH" --stat   # must output nothing
git branch -D "$TOPIC_BRANCH"
```

---

### B. Merge Existing PR Flow (`/git-workflow merge`)

Use when a PR is already open (e.g. after `/git-workflow pr nomerge` or manual review) and ready to squash-merge into `master`:

```bash
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"

TOPIC_BRANCH=$(git branch --show-current)
PR_NUMBER=$(gh pr list --repo chkp-antonr/arodonata_v2 --head "$TOPIC_BRANCH" --json number --jq '.[0].number')

# 1. Squash-merge and delete remote branch
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata_v2

# 2. Switch to master and pull squashed commit
git checkout master
git pull chkpar master --ff-only

# 3. Verify content parity and delete local topic branch
git diff master "$TOPIC_BRANCH" --stat   # must output nothing
git branch -D "$TOPIC_BRANCH"
```

---

### C. Cleanup Flow (`/git-workflow cleanup`)

Prune remote-tracking branches, sync `master`, and clean up any leftover local topic branches whose contents are already in `master`:

```bash
git fetch chkpar --prune
git checkout master
git pull chkpar master --ff-only

# Delete standard merged branches:
git branch --merged master | grep -v "master\|\*" | xargs -r git branch -d

# For squash-merged branches not detected by --merged, verify empty diff against master first:
for b in $(git for-each-ref --format='%(refname:short)' refs/heads/ | grep -v '^master$'); do
  if [ -z "$(git diff master "$b" --stat)" ]; then
    git branch -D "$b"
  else
    echo "Keeping unmerged branch: $b"
  fi
done
```

---

### D. Release Flow (`/git-workflow release [patch|minor|major]`)

```bash
# 1. Preconditions: clean tree on master synced with chkpar/master
unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY
gh auth status | grep -B1 "Active account: true"
git checkout master && git fetch chkpar && git pull chkpar master --ff-only
git status --short

# 2. Preview version bump (stop and ask user if increment was not specified)
uv run cz bump --dry-run --yes [--increment PATCH|MINOR|MAJOR]

# 3. Create release branch, bump version, update lockfile, run quality gates
git checkout -b release/v<B>
uv run cz bump --yes [--increment PATCH|MINOR|MAJOR]
uv lock --offline
git add CHANGELOG.md pyproject.toml uv.lock && git commit --amend --no-edit
git tag -d v<B>   # remove local pre-squash tag; tag will be placed on master after squash-merge

# 4. Push release branch, create PR, squash-merge into master
git push -u chkpar release/v<B>
gh pr create --repo chkp-antonr/arodonata_v2 \
  --base master \
  --head release/v<B> \
  --title "chore(release): bump version to v<B>" \
  --body "<release notes from CHANGELOG.md>"
PR_NUMBER=$(gh pr view --repo chkp-antonr/arodonata_v2 --json number --jq '.number')
gh pr merge "$PR_NUMBER" --squash --delete-branch --repo chkp-antonr/arodonata_v2

# 5. Sync master, tag the squashed commit on master, push tag, delete local release branch
git checkout master && git pull chkpar master --ff-only
git tag -a v<B> -m "Release v<B>" "$(git rev-parse HEAD)"
git push chkpar v<B>
git diff master release/v<B> --stat   # must output nothing
git branch -D release/v<B>
```
