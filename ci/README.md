# CI definitions

`github-actions.yml.example` is the intended GitHub Actions workflow. It is
deliberately **not** under `.github/workflows/` because the token used to push
this repository does not have the `workflow` scope; GitHub rejects any push
that adds workflow files with such a token.

To enable CI, a maintainer whose credentials carry the `workflow` scope must:

```sh
mkdir -p .github/workflows
cp ci/github-actions.yml.example .github/workflows/ci.yml
git add .github/workflows/ci.yml && git commit -m "ci: enable GitHub Actions workflow"
```

The example workflow runs ruff, mypy (strict), the always-runnable unit suite,
and the env-gated integration suite against real PostgreSQL 16 and Redis 7
service containers.
