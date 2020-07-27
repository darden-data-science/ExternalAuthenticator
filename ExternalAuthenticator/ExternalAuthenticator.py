from jupyterhub.handlers import BaseHandler, LoginHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Dict, Unicode, Bool, Int

import time

import json

from tornado.httputil import url_concat
from tornado import web

auth_token_name = 'auth-token'

class ExternalLoginHandler(LoginHandler):
    async def get(self):
        if auth_token_name not in self.request.arguments:
            self.redirect_to_login_server()
        else:
            user = await self.login_user()
            if user is None:
                raise web.HTTPError(403, log_message="Invalid login attempt.")
            else:
                self.redirect(self.get_next_url(user))

    def redirect_to_login_server(self):
        required_args = ['redirect-to', 'unique-id']
        for arg in required_args:
            if not self.get_argument(arg, ''):
                self.log.warning("Attempted external login without required argument: %r" % arg)
                raise web.HTTPError(400, log_message= "Attempted external login without required argument: %r" % arg)

        return_url = url_path_join(self.request.protocol + "://" + self.request.host,
                                    self.base_url, "/hub/external_login")
        
        return_url = url_concat(return_url, {'next': self.get_argument('next', default = ''),
                                             'unique-id': self.get_argument('unique-id')})
        self.redirect(url_concat(self.get_argument('redirect-to'), 
            {'return-url': return_url}))


class ExternalAuthenticator(Authenticator):
    """External Authenticator"""

    external_login_handler = ExternalLoginHandler

    login_service = Unicode(u"External Authenticator",
        help="""
        The name of the SAML based authentication service.
        """,
        config=True
    )

    unique_id = Unicode(
        help="""
        A unique string for this instance to ensure that the same token can't be used on another instance.
        """,
        allow_none=False).tag(config=True)

    auth_token_valid_time = Int(300,
        help="""
        Time in seconds that the auth token will be valid.
        """
    )

    external_login_url = Unicode(help="The url of the external login service").tag(config=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def login_url(self, base_url):
        return url_concat(url_path_join(base_url, 'external_login'),
            {'redirect-to': self.external_login_url, 
             'unique-id': self.unique_id})

    async def authenticate(self, handler, data):
        auth_token = handler.get_argument(auth_token_name)
        decrypted_auth_token = handler.get_secure_cookie(auth_token_name, value=auth_token, max_age_days=self.auth_token_valid_time/86400)

        if not decrypted_auth_token:
            self.log.warning("Invalid auth_token.")
            return None

        decrypted_auth_token = json.loads(decrypted_auth_token.decode('utf-8'))
        self.log.debug("The authentication tokens value is: %r" % str(decrypted_auth_token))

        username = decrypted_auth_token['username']
        reported_id = decrypted_auth_token['unique_id']

        self.log.info("User %r is logging in with reported ID of %r." % (username, reported_id))

        if not reported_id == self.unique_id:
            self.log.warning("Invalid login. Reported ID %r does not match unique ID %r." % (reported_id, self.unique_id))
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
            if not handler.get_secure_cookie(auth_token_name, value=x, max_age_days=self.auth_token_valid_time/86400):
                token_history.pop(x)
                self.log.debug("Deleting expired token: %r" % x)
        return token_history

    def get_handlers(self, app):
        return [
            (r'/external_login', self.external_login_handler),
        ]