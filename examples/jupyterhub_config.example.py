"""Example JupyterHub configuration for ExternalAuthenticator."""

c.JupyterHub.authenticator_class = "external_authenticator"

# Persist auth state so replay protection can retain token history.
c.Authenticator.enable_auth_state = True

# The external service must share the same Tornado cookie_secret.
c.ExternalAuthenticator.external_login_url = "https://login.example.com/start"

# Keep the external auth token short-lived.
c.ExternalAuthenticator.auth_token_valid_time = 300
