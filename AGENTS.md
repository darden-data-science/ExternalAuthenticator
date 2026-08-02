<!-- last-verified: 2026-08-02 against 5f92cf1 (main) -->

# ExternalAuthenticator

**LIVE. v1.0.1. This repo is the packaging reference for the other Python repos in this system** —
PEP 621 `pyproject.toml` with a dynamic version, a 7-line
`setup.py` shim, GitHub Actions CI, and a `sys.modules`-stubbed unittest suite.

Note the default branch here is **`main`**. Every sibling repo uses `master`.

## Where this fits

A JupyterHub `Authenticator` that delegates login to a separate trusted service, so no hub carries
SAML machinery. Every live cohort uses it (`authType: external`).

**My half of Contract A:** `login_url()` sends users to
`<base_url>/hub/external-login?redirect-to=<external_login_url>`. My `ExternalLoginHandler` finds
no `auth-token` cookie, reconstructs `base_return_url` = `proto://host + base_url +
/hub/external-login`, signs it under the name **`signed-return-url`**, and redirects to the login
service with `return-url=<that, plus next= and signed-return-url=>`. When the user comes back,
`authenticate()` reads the **`auth-token`** cookie, **clears it immediately**, JSON-decodes
`{"username", "return_url"}`, and rejects unless `return_url` equals my own reconstructed URL —
that check is what stops a cookie minted for one hub being replayed at another. Replay is
separately blocked by `token_history` in JupyterHub `auth_state`.

**Trust model:** shared Tornado `cookie_secret` with the login service. No bearer tokens. I mint
`signed-return-url` but never verify it — validating it is the login service's contractual
obligation.

**Who consumes me:** pip-installed from **this GitHub default branch, unpinned**, by
`images/hub/Dockerfile:8` in `darden-data-science/jupyterhub-config-darden`. Configured by
`config_files/integration/jupyterhub/values.yaml.gotmpl:42-55`.

**Full system map:** `/Users/Michael/Documents/Git Projects/Darden Jupyterhub/docs/SYSTEM-MAP.md`
(repo `darden-data-science/jupyterhub-config-darden`, private).

## Layout

```
ExternalAuthenticator/ExternalAuthenticator.py   191 lines — everything
ExternalAuthenticator/_version.py                the single source of truth for the version
pyproject.toml                                   PEP 621, authoritative
setup.py                                         7-line shim, kept for editable installs
tests/test_external_authenticator.py             9 tests
examples/jupyterhub_config.example.py            the current, correct config example
.github/workflows/ci.yml                         py3.10-3.13
```

Config surface: `login_service`, `auth_token_valid_time` (Int, 300s), `external_login_url`.
Entry point `external_authenticator`; the deployment uses the dotted path
`ExternalAuthenticator.ExternalAuthenticator` instead.

## Commands

```bash
pip install -e ".[dev]"
```

```bash
python -m unittest discover -s tests -v
```

```bash
python -m build
```

## Testing convention — and where it fell short

`tests/test_external_authenticator.py:146` (`load_package()`) injects fake `traitlets`,
`jupyterhub`, `jupyterhub.auth`, `jupyterhub.handlers`, `jupyterhub.utils`, `tornado`,
`tornado.httputil`, and `tornado.web` into `sys.modules` before importing the package. Tests then
run with **no real JupyterHub installed** — fast, no dependency hell, works on any Python.

Two caveats if you extend it: there is no `tests/__init__.py`, and the `sys.modules` stubbing
would leak across a shared pytest session, so this suite wants to stay on stdlib `unittest`.

**A stub only tests what it models.** The v1.0.1 cookie bug survived for years because
`RequestStub` set `request.host` to a value with no port — the convenient case. It now takes an
explicit `port`, and the rule is: model the awkward case. For anything touching the real wire
contract, use the end-to-end rig in `../Single Auth Server/dev/` instead; flip the commented
`[tool.uv.sources]` entry in its `pyproject.toml` to point at this checkout.

`../NullAuthenticator` and `../DictionaryAuthenticator` deliberately went the other way and test
against a real JupyterHub, because their behaviour lives in traitlets and JupyterHub's allow gate
rather than in their own code. Copy the stubbing pattern only when a package's logic is genuinely
independent of its dependencies.

Still not covered: `ExternalLoginHandler` (neither `get` nor `redirect_to_login_server`).

## Fixed in v1.0.1 (2026-08-02)

- **The cookie clear was a no-op on any non-default port.** `authenticate()` cleared `auth-token`
  with `domain=handler.request.host`, which carries the port. A port in a cookie `Domain` is
  invalid per RFC 6265, so the whole `Set-Cookie` was discarded and the cookie survived — after
  which replay protection rejects it, trapping the user in exactly the loop the clear exists to
  prevent. Now uses `request.host_name`. Production never saw it because port 443 is implicit and
  the two values are identical there; four commits between 2021 and 2024 circled this line without
  finding it. Caught by the end-to-end rig, not by this repo's tests — see below.
- `setuptools>=69` → `>=77`. The bare SPDX `license` string is rejected by 69–76 with an opaque
  "invalid project.license" error, so the build was broken on those versions.
- **CI never ran on the default branch.** The push trigger listed `master`; the default branch is
  `main`.
- `requires-python` `>=3.8` → `>=3.10`, matching the CI matrix and the sibling repos. Version
  classifiers and `Framework :: Jupyter` added.

## Known issues

- `login_url()` is overridden without `auto_login = True`, so users see an intermediate
  "Sign in with…" page rather than being bounced straight to the IdP. Probably intentional; worth
  deciding explicitly.
- The cookie clear matches the login service's **default** `Domain` (the return URL's hostname).
  If SingleAuthServer's `auth_token_cookie_domain` is ever configured to something else, the clear
  will not match and a stale cookie can linger for `auth_token_valid_time`.
- `ExternalLoginHandler` is still untested — neither `get` nor `redirect_to_login_server`. The
  end-to-end rig exercises both; the unit suite does not.

## Cross-repo impact

- The hub image installs from this branch **unpinned**. Merging to `main` changes the next hub
  image build. Docker layer-caches that `RUN pip install`, so `ENV cacheBuster` in
  `images/hub/Dockerfile` must be bumped for the change to actually land.
- **[J]** `config_files/integration/jupyterhub/values.yaml.gotmpl:47` still sets
  `ExternalAuthenticator.unique_id`, a trait v1.0.0 removed. Harmless traitlets warning today, but
  it should be deleted.

## Untracked cruft in the working tree

All gitignored, none committed, but present: `jupyterhub.sqlite` (100 KB, 2020),
`jupyterhub_config.py` (37 KB, 2020 — **stale and misleading**; it references the removed
`unique_id` trait and puts `external_login_url` on `c.Authenticator` instead of
`c.ExternalAuthenticator`. `examples/jupyterhub_config.example.py` supersedes it), `.venv/`,
`.egg-info/` (its PKG-INFO still says 0.0.1.dev0), and `__pycache__` holding both cpython-38 and
cpython-314 bytecode.
