"""Focused tests for the authenticator without requiring a full JupyterHub install.

These tests intentionally provide small in-memory stand-ins for the parts of
JupyterHub, Tornado, and traitlets that the package imports. The repository is
small and the authenticator logic is mostly pure Python, so a lightweight test
double approach gives us good behavioral coverage without needing to install and
boot a full JupyterHub application in CI.

The module is documented more heavily than a typical test file because most of
the complexity lives in the scaffolding rather than in the assertions
themselves. Future maintainers should be able to understand:

- which external interfaces the authenticator relies on,
- why we stub those interfaces instead of importing real dependencies, and
- what each test is proving about the login flow.
"""

import importlib
import json
import sys
import types
import unittest
from urllib.parse import parse_qs, urlencode, urlparse


class DummyLog:
    """Capture the last log message emitted by the authenticator.

    The production authenticator logs extensively during successful and failed
    authentication attempts. The current tests do not assert on log output, but
    the object still needs to quack like a logger so the authenticator can run
    without pulling in Python's logging configuration machinery.
    """

    # Accepts *args/**kwargs so it tolerates BOTH logging styles: eager
    # ("...%r" % x) as used through most of this package, and lazy
    # ("...%r", x) which is the correct form because it skips formatting
    # entirely when the level is disabled. A single-argument stub silently
    # forces every call site to the eager style.

    def debug(self, message, *args, **kwargs):
        self.last_message = message

    def info(self, message, *args, **kwargs):
        self.last_message = message

    def warning(self, message, *args, **kwargs):
        self.last_message = message


class DummyUser:
    """Minimal async user object that exposes stored auth state."""

    def __init__(self, auth_state):
        self._auth_state = auth_state

    async def get_auth_state(self):
        return self._auth_state


class RequestStub:
    """Small request object with just the attributes the authenticator reads.

    `host` and `host_name` are separate on purpose. Tornado's `host` includes
    the port when it is non-default; `host_name` never does. This stub used to
    model only `host`, with a value that had no port — which is exactly why it
    could not catch the cookie-clearing bug fixed in 1.0.1. Any new attribute
    added here should model the awkward case, not the convenient one.
    """

    def __init__(self, host="hub.example.com", port=None):
        self.protocol = "https"
        self.host_name = host
        self.host = f"{host}:{port}" if port else host
        self.path = "/hub/login"


class HandlerStub:
    """Emulate the narrow slice of handler behavior used during authentication.

    JupyterHub passes a Tornado handler into `Authenticator.authenticate`. The
    authenticator reads plain cookies, validates secure cookies, and clears the
    auth token once it has been consumed. This stub tracks all of those
    interactions so tests can verify the expected side effects.
    """

    def __init__(self, *, cookie=None, secure_cookie=None, valid_tokens=None,
                 request=None):
        self.base_url = "/jupyter"
        self.request = request or RequestStub()
        self.cookies = {}
        self.secure_values = {}
        self.valid_tokens = set(valid_tokens or [])
        self.cleared = []

        if cookie is not None:
            self.cookies["auth-token"] = cookie
            self.valid_tokens.add(cookie)

        if secure_cookie is not None:
            self.secure_values["auth-token"] = secure_cookie

    def get_cookie(self, name):
        """Return the raw browser cookie value for replay-tracking checks."""

        return self.cookies.get(name)

    def get_signed_cookie(self, name, max_age_days=None, value=None):
        """Mimic Tornado secure-cookie validation.

        When `value` is provided, the authenticator is asking Tornado to verify
        whether a previously seen token is still valid. Otherwise it is asking
        for the current signed cookie payload to deserialize into JSON.
        """

        if value is not None:
            return value if value in self.valid_tokens else None
        return self.secure_values.get(name)

    def clear_cookie(self, name, path=None, domain=None):
        """Record cookie clearing so tests can assert the defensive cleanup."""

        self.cleared.append((name, path, domain))


class LegacyHandlerStub:
    """Simulate older Tornado releases that only expose `get_secure_cookie`.

    The production code prefers `get_signed_cookie` to avoid deprecation
    warnings on newer Tornado releases, but still falls back to the legacy name
    for compatibility with older deployments.
    """

    def __init__(self, *, cookie=None, secure_cookie=None, valid_tokens=None,
                 request=None):
        self.base_url = "/jupyter"
        self.request = request or RequestStub()
        self.cookies = {}
        self.secure_values = {}
        self.valid_tokens = set(valid_tokens or [])
        self.cleared = []

        if cookie is not None:
            self.cookies["auth-token"] = cookie
            self.valid_tokens.add(cookie)

        if secure_cookie is not None:
            self.secure_values["auth-token"] = secure_cookie

    def get_cookie(self, name):
        return self.cookies.get(name)

    def get_secure_cookie(self, name, max_age_days=None, value=None):
        if value is not None:
            return value if value in self.valid_tokens else None
        return self.secure_values.get(name)

    def clear_cookie(self, name, path=None, domain=None):
        self.cleared.append((name, path, domain))


def load_package():
    """Import the authenticator module against a fully stubbed dependency graph.

    The package imports JupyterHub, Tornado, and traitlets at module import
    time. Rather than requiring those packages in the test environment, we
    preload small substitute modules in `sys.modules` and then import the real
    package under test. This keeps the tests fast and deterministic while still
    exercising the authenticator's own code exactly as packaged.
    """

    class FakeTrait:
        """Descriptor that behaves enough like a traitlets config attribute.

        We only need a tiny subset of traitlets behavior:

        - a default value,
        - instance storage,
        - a `tag()` method that records metadata such as `config=True`.

        That is sufficient to verify the package marks `auth_token_valid_time`
        as configurable.
        """

        def __init__(self, default_value=None, metadata=None):
            self.default_value = default_value
            self.metadata = metadata or {}
            self.name = None

        def __set_name__(self, owner, name):
            self.name = name

        def __get__(self, instance, owner):
            if instance is None:
                return self
            return instance.__dict__.get(self.name, self.default_value)

        def __set__(self, instance, value):
            instance.__dict__[self.name] = value

        def tag(self, **kwargs):
            self.metadata.update(kwargs)
            return self

    def make_trait(default_value=None, **kwargs):
        """Build a fake trait and preserve whether it was marked configurable."""

        metadata = {}
        if kwargs.get("config"):
            metadata["config"] = True
        return FakeTrait(default_value=default_value, metadata=metadata)

    def url_path_join(*pieces):
        """Simplified version of JupyterHub's path join helper."""

        filtered = [piece for piece in pieces if piece]
        if not filtered:
            return ""

        result = filtered[0].rstrip("/")
        for piece in filtered[1:]:
            result = f"{result}/{piece.strip('/')}"
        return result

    def url_concat(url, params):
        """Append query parameters in the same style Tornado uses."""

        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{urlencode(params)}"

    class HTTPError(Exception):
        """Drop-in replacement for `tornado.web.HTTPError` in tests."""

        def __init__(self, status_code, log_message=None):
            super().__init__(log_message or str(status_code))
            self.status_code = status_code
            self.log_message = log_message

    class Authenticator:
        """Small test double for the JupyterHub authenticator base class.

        The production class provides many features, but the package under test
        only relies on parent/user lookup, logging, and username normalization.
        This substitute focuses on those behaviors and intentionally leaves out
        unrelated framework details.
        """

        def __init__(self, **kwargs):
            self.parent = kwargs.pop("parent", types.SimpleNamespace(users={}))
            self.log = kwargs.pop("log", DummyLog())
            for key, value in kwargs.items():
                setattr(self, key, value)

        def normalize_username(self, username):
            return username.lower()

    traitlets_module = types.ModuleType("traitlets")
    traitlets_module.Int = lambda default_value=0, **kwargs: make_trait(default_value, **kwargs)
    traitlets_module.Unicode = lambda default_value="", **kwargs: make_trait(default_value, **kwargs)

    jupyterhub_module = types.ModuleType("jupyterhub")
    jupyterhub_auth_module = types.ModuleType("jupyterhub.auth")
    jupyterhub_auth_module.Authenticator = Authenticator
    jupyterhub_handlers_module = types.ModuleType("jupyterhub.handlers")
    jupyterhub_handlers_module.BaseHandler = type("BaseHandler", (), {})
    jupyterhub_utils_module = types.ModuleType("jupyterhub.utils")
    jupyterhub_utils_module.url_path_join = url_path_join

    tornado_module = types.ModuleType("tornado")
    tornado_httputil_module = types.ModuleType("tornado.httputil")
    tornado_httputil_module.url_concat = url_concat
    tornado_web_module = types.ModuleType("tornado.web")
    tornado_web_module.HTTPError = HTTPError

    # Preload the fake dependency tree so importing the package under test uses
    # these stand-ins instead of requiring the real third-party packages.
    sys.modules["traitlets"] = traitlets_module
    sys.modules["jupyterhub"] = jupyterhub_module
    sys.modules["jupyterhub.auth"] = jupyterhub_auth_module
    sys.modules["jupyterhub.handlers"] = jupyterhub_handlers_module
    sys.modules["jupyterhub.utils"] = jupyterhub_utils_module
    sys.modules["tornado"] = tornado_module
    sys.modules["tornado.httputil"] = tornado_httputil_module
    sys.modules["tornado.web"] = tornado_web_module

    for module_name in list(sys.modules):
        if module_name == "ExternalAuthenticator" or module_name.startswith("ExternalAuthenticator."):
            sys.modules.pop(module_name)

    return importlib.import_module("ExternalAuthenticator.ExternalAuthenticator")


class ExternalAuthenticatorTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the authenticator's control flow at the package boundary."""

    @classmethod
    def setUpClass(cls):
        """Import the module once after the fake dependency graph is installed."""

        cls.module = load_package()

    def test_login_url_targets_external_handler(self):
        """The login URL should always bounce users through `/external-login`."""

        authenticator = self.module.ExternalAuthenticator(
            external_login_url="https://login.example.com/sso"
        )

        login_url = authenticator.login_url("/jupyter/")
        parsed = urlparse(login_url)

        self.assertEqual(parsed.path, "/jupyter/external-login")
        self.assertEqual(
            parse_qs(parsed.query),
            {"redirect-to": ["https://login.example.com/sso"]},
        )

    def test_cookie_helper_prefers_new_tornado_name(self):
        """Prefer `get_signed_cookie` when the handler exposes the new API."""

        handler = HandlerStub(secure_cookie=b"payload")

        cookie = self.module.get_signed_cookie(
            handler,
            "auth-token",
            max_age_days=1,
        )

        self.assertEqual(cookie, b"payload")

    def test_cookie_helper_falls_back_to_legacy_name(self):
        """Fall back to `get_secure_cookie` for older Tornado releases."""

        handler = LegacyHandlerStub(secure_cookie=b"payload")

        cookie = self.module.get_signed_cookie(
            handler,
            "auth-token",
            max_age_days=1,
        )

        self.assertEqual(cookie, b"payload")

    async def test_authenticate_records_token_history(self):
        """A successful login records the token and clears the browser cookie.

        This covers the happy path for the authenticator:

        - a valid signed cookie is present,
        - the embedded return URL matches the current hub instance,
        - auth state is preserved and updated with the newly consumed token.
        """

        authenticator = self.module.ExternalAuthenticator(
            parent=types.SimpleNamespace(
                users={
                    "alice": DummyUser(
                        {"external_auth_state": {"token_history": {}}}
                    )
                }
            ),
            log=DummyLog(),
        )
        handler = HandlerStub(
            cookie="token-123",
            secure_cookie=json.dumps(
                {
                    "username": "Alice",
                    "return_url": "https://hub.example.com/jupyter/hub/external-login",
                }
            ).encode("utf-8"),
        )

        authentication = await authenticator.authenticate(handler, data=None)

        self.assertEqual(authentication["name"], "alice")
        self.assertEqual(
            authentication["auth_state"]["external_auth_state"]["token_history"],
            {"token-123": ""},
        )
        self.assertEqual(
            handler.cleared,
            [("auth-token", "/hub/login", "hub.example.com")],
        )

    async def test_authenticate_rejects_replay_attack(self):
        """A previously seen token must not be accepted again."""

        authenticator = self.module.ExternalAuthenticator(
            parent=types.SimpleNamespace(
                users={
                    "alice": DummyUser(
                        {"external_auth_state": {"token_history": {"token-123": ""}}}
                    )
                }
            ),
            log=DummyLog(),
        )
        handler = HandlerStub(
            cookie="token-123",
            secure_cookie=json.dumps(
                {
                    "username": "Alice",
                    "return_url": "https://hub.example.com/jupyter/hub/external-login",
                }
            ).encode("utf-8"),
        )

        authentication = await authenticator.authenticate(handler, data=None)

        self.assertIsNone(authentication)

    async def test_authenticate_rejects_mismatched_return_url(self):
        """Tokens minted for another hub URL must be rejected."""

        authenticator = self.module.ExternalAuthenticator(log=DummyLog())
        handler = HandlerStub(
            cookie="token-123",
            secure_cookie=json.dumps(
                {
                    "username": "Alice",
                    "return_url": "https://different.example.com/hub/external-login",
                }
            ).encode("utf-8"),
        )

        authentication = await authenticator.authenticate(handler, data=None)

        self.assertIsNone(authentication)

    async def test_cookie_is_cleared_with_a_port_free_domain(self):
        """Regression test for the 1.0.1 cookie-clearing fix.

        A cookie `Domain` attribute must not contain a port (RFC 6265). When it
        does, the whole Set-Cookie is discarded and the clear silently does
        nothing, leaving a stale auth-token that replay protection then rejects
        — trapping the user in exactly the loop this clear exists to prevent.

        The bug was invisible for years because production runs on port 443,
        where Tornado's `host` and `host_name` are identical. It only appears on
        a non-default port, which is what this test forces.
        """

        handler = HandlerStub(
            cookie="raw-token",
            secure_cookie=json.dumps(
                {
                    "username": "alice",
                    "return_url": "https://hub.example.com:8081/jupyter/hub/external-login",
                }
            ).encode("utf-8"),
            request=RequestStub(host="hub.example.com", port=8081),
        )
        handler.parent = None
        authenticator = self.module.ExternalAuthenticator(log=DummyLog())
        authenticator.parent = types.SimpleNamespace(users={})

        await authenticator.authenticate(handler)

        self.assertEqual(len(handler.cleared), 1)
        _name, _path, domain = handler.cleared[0]
        self.assertEqual(domain, "hub.example.com")
        self.assertNotIn(":", domain, "a port in a cookie Domain voids the clear")

    def test_remove_expired_tokens_prunes_invalid_entries(self):
        """Only still-valid tokens should remain in replay-protection history."""

        authenticator = self.module.ExternalAuthenticator(log=DummyLog())
        handler = HandlerStub(valid_tokens={"fresh-token"})

        remaining_tokens = authenticator.remove_expired_tokens(
            {"fresh-token": "", "stale-token": ""},
            handler,
        )

        self.assertEqual(remaining_tokens, {"fresh-token": ""})

    def test_auth_token_valid_time_is_configurable(self):
        """The timeout trait should be exposed as a JupyterHub config option."""

        trait = self.module.ExternalAuthenticator.auth_token_valid_time
        self.assertEqual(trait.default_value, 300)
        self.assertTrue(trait.metadata.get("config"))
