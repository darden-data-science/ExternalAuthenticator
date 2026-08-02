# Contributing

## Local setup

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -e .[dev]
```

If you prefer a different Python version, use any interpreter supported by the package metadata.

## Run checks

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

Build the source and wheel distributions:

```bash
uv build
```

If you are working in a restricted environment that already has `setuptools` and `wheel`
available, `uv build --no-build-isolation` is a reasonable fallback.

## Before opening a pull request

- Keep behavior-preserving refactors separate from documentation-only changes when possible.
- Update the README when you change the external login contract or the supported configuration.
- Add or update tests for any authentication flow change.
- Include the commands you used for verification in the pull request description.

## Testing convention, and its limits

These tests stub `jupyterhub`, `tornado`, and `traitlets` into `sys.modules` so they run with no
real dependencies installed. That is fast and deterministic, and it suits this package because
most of the authenticator's logic is pure Python.

It has a real cost, and 1.0.1 is the proof: the cookie-clearing bug fixed in that release was
invisible to this suite for years, because `RequestStub` modelled `request.host` with a value that
had no port — the convenient case rather than the awkward one. A stub only tests what it models.

Two rules follow:

1. When adding an attribute to a stub, model the awkward case. `RequestStub` now takes an explicit
   `port` for exactly this reason.
2. For anything involving the real wire contract, use the end-to-end rig in the SingleAuthServer
   repo (`dev/`) instead. It runs a real JupyterHub and a real auth server against each other, and
   it is what caught the 1.0.1 bug. Point it at a local checkout of this package by flipping the
   commented `[tool.uv.sources]` entry in `dev/pyproject.toml`.

The sibling `NullAuthenticator` and `DictionaryAuthenticator` repos deliberately went the other
way and test against a real JupyterHub, because their defining behaviour lives in traitlets and
JupyterHub's allow gate rather than in their own code.

## Downstream impact

The Darden JupyterHub hub image installs this package **from this default branch, unpinned**
(`images/hub/Dockerfile` in `darden-data-science/jupyterhub-config-darden`). Merging to `main`
lands in the next hub image build, so merging is a deploy decision. Docker layer-caches that
`pip install`, so `ENV cacheBuster` in the hub Dockerfile must be bumped or the rebuild silently
keeps the old version.
