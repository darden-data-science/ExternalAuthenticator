import importlib
import json
import sys
import types
import unittest
from urllib.parse import parse_qs, urlencode, urlparse


class DummyLog:
    def debug(self, message):
        self.last_message = message

    def info(self, message):
        self.last_message = message

    def warning(self, message):
        self.last_message = message


class DummyUser:
    def __init__(self, auth_state):
        self._auth_state = auth_state

    async def get_auth_state(self):
        return self._auth_state


class RequestStub:
    def __init__(self):
        self.protocol = "https"
        self.host = "hub.example.com"
        self.path = "/hub/login"


class HandlerStub:
    def __init__(self, *, cookie=None, secure_cookie=None, valid_tokens=None):
        self.base_url = "/jupyter"
        self.request = RequestStub()
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
    class FakeTrait:
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
        metadata = {}
        if kwargs.get("config"):
            metadata["config"] = True
        return FakeTrait(default_value=default_value, metadata=metadata)

    def url_path_join(*pieces):
        filtered = [piece for piece in pieces if piece]
        if not filtered:
            return ""

        result = filtered[0].rstrip("/")
        for piece in filtered[1:]:
            result = f"{result}/{piece.strip('/')}"
        return result

    def url_concat(url, params):
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{urlencode(params)}"

    class HTTPError(Exception):
        def __init__(self, status_code, log_message=None):
            super().__init__(log_message or str(status_code))
            self.status_code = status_code
            self.log_message = log_message

    class Authenticator:
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
    @classmethod
    def setUpClass(cls):
        cls.module = load_package()

    def test_login_url_targets_external_handler(self):
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

    async def test_authenticate_records_token_history(self):
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

    def test_remove_expired_tokens_prunes_invalid_entries(self):
        authenticator = self.module.ExternalAuthenticator(log=DummyLog())
        handler = HandlerStub(valid_tokens={"fresh-token"})

        remaining_tokens = authenticator.remove_expired_tokens(
            {"fresh-token": "", "stale-token": ""},
            handler,
        )

        self.assertEqual(remaining_tokens, {"fresh-token": ""})

    def test_auth_token_valid_time_is_configurable(self):
        trait = self.module.ExternalAuthenticator.auth_token_valid_time
        self.assertTrue(trait.metadata.get("config"))
