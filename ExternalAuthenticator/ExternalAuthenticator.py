"""JupyterHub authenticator backed by an external shared-secret login flow."""

import json

from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from tornado import web
from tornado.httputil import url_concat
from traitlets import Int, Unicode

auth_token_name = 'auth-token'


def get_signed_cookie(handler, *args, **kwargs):
    """Read a signed cookie while tolerating Tornado's old method name.

    Tornado 6.3 renamed ``get_secure_cookie`` to ``get_signed_cookie`` and kept
    the former as a deprecated alias. Prefer the new name when available while
    retaining compatibility with older Tornado releases that only expose the
    original method.
    """

    cookie_getter = getattr(handler, "get_signed_cookie", None)
    if cookie_getter is None:
        cookie_getter = handler.get_secure_cookie
    return cookie_getter(*args, **kwargs)


class ExternalLoginHandler(BaseHandler):
    async def get(self):
        if not get_signed_cookie(
            self,
            auth_token_name,
            max_age_days=self.authenticator.auth_token_valid_time / 86400,
        ):
            self.log.debug("No cookie present, redirecting to login server.")
            self.redirect_to_login_server()
        else:
            self.log.debug("Cookie present! Checking if user can log in.")
            user = await self.login_user()
            if user is None:
                raise web.HTTPError(403, log_message="Invalid login attempt.")
            else:
                self.redirect(self.get_next_url(user))

    def redirect_to_login_server(self):
        required_args = ['redirect-to']
        for arg in required_args:
            if not self.get_argument(arg, ''):
                self.log.warning("Attempted external login without required argument: %r" % arg)
                raise web.HTTPError(
                    400,
                    log_message="Attempted external login without required argument: %r" % arg,
                )

        base_return_url = url_path_join(
            self.request.protocol + "://" + self.request.host,
            self.base_url,
            "/hub/external-login",
        )
        signed_base_return_url = self.create_signed_value(
            name='signed-return-url',
            value=base_return_url.encode('utf-8'),
        )

        return_url = url_concat(
            base_return_url,
            {
                'next': self.get_argument('next', default=''),
                'signed-return-url': signed_base_return_url,
            },
        )
        self.redirect(
            url_concat(
                self.get_argument('redirect-to'),
                {'return-url': return_url},
            )
        )


class ExternalAuthenticator(Authenticator):
    """Authenticate JupyterHub users via a separate trusted login service."""

    external_login_handler = ExternalLoginHandler

    login_service = Unicode(u"External Authenticator",
        help="""
        The name displayed for the external authentication service.
        """,
        config=True
    )

    auth_token_valid_time = Int(300,
        help="""
        Time in seconds that the auth token will be valid.
        """
    ).tag(config=True)

    external_login_url = Unicode(help="The url of the external login service").tag(config=True)

    def login_url(self, base_url):
        return url_concat(url_path_join(base_url, 'external-login'),
            {'redirect-to': self.external_login_url})

    async def authenticate(self, handler, data=None):
        auth_token = handler.get_cookie(auth_token_name)
        decrypted_auth_token = get_signed_cookie(
            handler,
            auth_token_name,
            max_age_days=self.auth_token_valid_time / 86400,
        )
        # Clear the browser cookie before validating the token so an expired or
        # invalid token does not trap users in a broken login loop.
        #
        # host_name, NOT host: `host` carries the port on non-default ports
        # ("hub.example.com:8081"), and a port in a cookie Domain attribute is
        # invalid per RFC 6265, so the entire Set-Cookie is discarded and the
        # clear silently does nothing. Production hides this because port 443 is
        # implicit and the two are identical there.
        #
        # host_name matches what the login service used: it sets the cookie with
        # Domain=<hostname of the return URL>, and authenticate() has already
        # required that return URL to equal one built from this request. The two
        # therefore agree by construction — unless the login service overrides
        # its auth_token_cookie_domain, in which case this clear will not match
        # and a stale cookie can linger for auth_token_valid_time.
        cookie_domain = handler.request.host_name
        self.log.debug(
            "Clearing %r with path=%r domain=%r",
            auth_token_name,
            handler.request.path,
            cookie_domain,
        )
        handler.clear_cookie(
            auth_token_name, path=handler.request.path, domain=cookie_domain
        )

        if not decrypted_auth_token:
            self.log.warning("Invalid auth_token.")
            return None

        decrypted_auth_token = json.loads(decrypted_auth_token.decode('utf-8'))
        self.log.debug("The authentication tokens value is: %r" % str(decrypted_auth_token))

        username = decrypted_auth_token['username']
        reported_return_url = decrypted_auth_token['return_url']

        true_return_url = url_path_join(
            handler.request.protocol + "://" + handler.request.host,
            handler.base_url,
            "/hub/external-login",
        )

        self.log.info("User %r is logging in with reported return url of %r." % (username, reported_return_url))

        if not reported_return_url == true_return_url:
            self.log.warning("Invalid login. Reported url %r does not match unique ID %r." % (reported_return_url, true_return_url))
            return None

        app = self.parent
        username = self.normalize_username(username)
        try:
            user = app.users[username]
        except KeyError:
            # first-time login, user not defined yet
            auth_state = None
        else:
            auth_state = await user.get_auth_state()

        userdict = {"name": username}

        if isinstance(auth_state, dict):
            token_history = auth_state.get("external_auth_state", {}).get('token_history', {})

            if auth_token in token_history:
                self.log.warning("Replay attack on user %r. Stop authentication." % username)
                return None

            userdict["auth_state"] = auth_state

        else:
            userdict["auth_state"] = auth_state = {}

        external_auth_state = auth_state.setdefault("external_auth_state", {})
        token_history = external_auth_state.setdefault('token_history', {})
        token_history[auth_token] = ''

        external_auth_state['token_history'] = self.remove_expired_tokens(token_history, handler)

        userdict = {"name": username, 'auth_state': auth_state}

        return userdict

    def remove_expired_tokens(self, token_history, handler):
        keys = list(token_history.keys())
        for x in keys:
            if not get_signed_cookie(
                handler,
                auth_token_name,
                value=x,
                max_age_days=self.auth_token_valid_time / 86400,
            ):
                token_history.pop(x)
                self.log.debug("Deleting expired token: %r" % x)
        return token_history

    def get_handlers(self, app):
        return [
            (r'/external-login', self.external_login_handler),
        ]
