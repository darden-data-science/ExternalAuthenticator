# ExternalAuthenticator

ExternalAuthenticator is a custom JupyterHub authenticator for deployments that rely on a separate, trusted login service. Instead of collecting credentials inside JupyterHub, the hub redirects users to an external service, then validates a short-lived signed cookie when the user returns.

This repository is a good fit when:

- You already have an internal authentication service.
- That service can share the JupyterHub Tornado `cookie_secret`.
- You want multiple JupyterHub deployments to rely on the same login entry point.

## How it works

1. A user hits the JupyterHub login flow.
2. ExternalAuthenticator redirects the browser to the configured external login URL and passes a signed return URL back to the hub.
3. The external service authenticates the user, sets an `auth-token` secure cookie that JupyterHub can verify, and redirects the browser back to the hub.
4. ExternalAuthenticator validates the cookie, checks that the embedded `return_url` matches the current hub, and logs the user in.
5. If auth state persistence is enabled, the authenticator records previously seen tokens to help detect replay attempts.

## Requirements

- Python 3.10 or newer
- JupyterHub 4.x or 5.x
- A trusted external login service that can use the same Tornado `cookie_secret` as the hub
- HTTPS everywhere, especially if the external service and JupyterHub live on different hosts

Replay protection depends on persisted auth state. To enable it, set:

- `c.Authenticator.enable_auth_state = True`
- `JUPYTERHUB_CRYPT_KEY` in the hub environment

Without persisted auth state, the authenticator can still log users in, but it cannot retain token history between requests and hub restarts.

## Installation

Install from a local checkout:

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install .
```

Install from a checkout for local development:

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -e .[dev]
```

## JupyterHub configuration

Set the authenticator by its entry point name and point it at your external login service:

```python
c.JupyterHub.authenticator_class = "external_authenticator"

# Strongly recommended so replay protection can persist token history.
c.Authenticator.enable_auth_state = True

c.ExternalAuthenticator.external_login_url = "https://login.example.com/start"
c.ExternalAuthenticator.auth_token_valid_time = 300
```

You also need a `JUPYTERHUB_CRYPT_KEY` when `enable_auth_state` is on:

```bash
export JUPYTERHUB_CRYPT_KEY=$(openssl rand -hex 32)
```

A ready-to-copy example lives in [examples/jupyterhub_config.example.py](examples/jupyterhub_config.example.py).

## External service contract

The external login service is expected to:

1. Accept the `return-url` query parameter from JupyterHub.
2. Authenticate the user by whatever means are appropriate for your environment.
3. Set a Tornado secure cookie named `auth-token` that JupyterHub can validate with the shared `cookie_secret`.
4. Redirect the browser back to the provided `return-url`.

The cookie payload must be JSON-encoded and include:

```json
{
  "username": "alice",
  "return_url": "https://hub.example.com/jupyter/hub/external-login"
}
```

Important notes:

- `return_url` must exactly match the hub return URL or the login is rejected.
- The cookie lifetime should not exceed `c.ExternalAuthenticator.auth_token_valid_time`.
- The cookie must be scoped so the JupyterHub host can read it.
- Sharing `cookie_secret` means the external service is fully trusted by the hub. Treat it accordingly.

## Security notes

- Use TLS for both the external service and JupyterHub.
- Keep `auth_token_valid_time` short.
- Enable auth state persistence if you want replay detection to survive beyond a single request.
- Rotate shared secrets carefully and coordinate changes across every service that participates in the login flow.

## Development

The project uses a lightweight `uv` workflow:

```bash
uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -e .[dev]
python -m unittest discover -s tests -v
uv build
```

Additional contributor guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
