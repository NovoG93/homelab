# Git Hooks

Local git hooks for kustomize validation and commit message conventions.

## Hooks

- **pre-commit** — Runs `kustomize build` on directories with staged kustomization files. Requires `kustomize` on PATH; skips gracefully if not installed.
- **commit-msg** — Enforces [conventional commit](https://www.conventionalcommits.org/) format: `type(scope): description`.

## Setup

Hooks auto-activate on clone via `post-checkout`. If you need to fix permissions manually:

```bash
bash .githook/setup.bash
```

**Prerequisite**: `core.hooksPath` must be set to `.githook`:
```bash
git config --local core.hooksPath .githook
```

## Disable

```bash
git config --local --unset core.hooksPath
```

## Bypass

```bash
git commit --no-verify
```
