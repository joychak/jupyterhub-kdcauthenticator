import kerberos

from tornado import gen, web
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen

from traitlets import (
    Any, Bool, Dict, Instance, Integer, Float, List, Unicode,
    validate,
)

class KDCLoginHandler(BaseHandler):
    scope = []

    @gen.coroutine
    def get(self):
        redirect_uri = self.authenticator.callback_url(self.base_url)
        self.redirect(redirect_uri)

class KDCCallbackHandler(BaseHandler):
    """Basic handler for OAuth callback. Calls authenticator to verify username."""

    def _unauthorized(self):
        '''
        Indicate that authentication is required
        '''
        #return Response('Unauthorized', 401, {'WWW-Authenticate': 'Negotiate'})
        #self.log.info("Request unautorized")
        self.set_status(401)
        self.set_header('WWW-Authenticate','Negotiate')
        self.finish()

    def _stop(self, username):
        html = self._render(
            login_error='Invalid username or password',
            username=username,
        )
        self.finish(html)

    def _forbidden(self):
        '''
        Indicate a complete authentication failure
        '''
        raise web.HTTPError(403)
        #return Response('Forbidden', 403)

    @gen.coroutine
    def get(self):

        header = self.request.headers.get("Authorization")
        if header:
            token = ''.join(header.split()[1:])
            result = yield self.authenticator.get_authenticated_user(self, token)

            username = None
            rc = None
            if ":" in result:
                rc, username = result.split(':')
            elif result != None:
                rc = result

            #self.log.info("self.authenticator.get_authenticated_user called")
            if rc.upper() == "KERBEROS.AUTH_GSS_COMPLETE":
                self.log.info("kerberos.AUTH_GSS_COMPLETE: Username= " + username)
                if username:
                    userId = username.split("@")[0]
                    self.log.info("User = " + userId)
                    user = self.user_from_username(userId)
                    already_running = False
                    if user.spawner:
                        status = yield user.spawner.poll()
                        already_running = (status == None)
                    if not already_running and not user.spawner.options_form:
                        yield self.spawn_single_user(user)
                    self.set_login_cookie(user)
                    next_url = self.get_argument('next', default='')
                    if not next_url.startswith('/'):
                        next_url = ''
                    next_url = next_url or self.hub.server.base_url
                    self.redirect(next_url)
                    self.log.info("User logged in: %s", username)
                else:
                    self._stop(username)

                # self.set_login_cookie(user) #ctx.kerberos_user)
                # self.redirect(url_path_join(self.hub.server.base_url, 'home'))
            elif rc.upper() != "KERBEROS.AUTH_GSS_CONTINUE":
                self.log.info("Request forbidden")
                self._forbidden()
            else:
                self._unauthorized()
        else:
            self._unauthorized()

class KDCAuthenticator(LocalAuthenticator):

    service_name = Unicode('',
                             help="This is a service principal"
                             ).tag(config=True)

    def callback_url(self, base_url):
        return url_path_join(base_url, 'kdc_callback')

    def login_url(self, base_url):
        return url_path_join(base_url, 'kdc_login')

    login_handler = KDCLoginHandler
    callback_handler = KDCCallbackHandler

    def get_handlers(self, app):
        return [
            (r'/kdc_login', self.login_handler),
            (r'/kdc_callback', self.callback_handler),
        ]

    @gen.coroutine
    def authenticate(self, handler, data):
        '''
            Performs GSSAPI Negotiate Authentication
            On success also stashes the server response token for mutual authentication
            at the top of request context with the name kerberos_token, along with the
            authenticated user principal with the name kerberos_user.
            @param token: GSSAPI Authentication Token
            @type token: str
            @returns gssapi return code or None on failure
            @rtype: int or None
            '''
        state = None
        try:
            rc, state = kerberos.authGSSServerInit('HTTP')
            self.log.info("kerberos.authGSSServerInit")
            if rc != kerberos.AUTH_GSS_COMPLETE:
                return None

            #self.log.info("rc == kerberos.AUTH_GSS_COMPLETE with data=" + data)
            rc = kerberos.authGSSServerStep(state, data)
            self.log.info("kerberos.authGSSServerStep")
            if rc == kerberos.AUTH_GSS_COMPLETE:
                #self.log.info("rc == kerberos.AUTH_GSS_COMPLETE")
                #ctx.kerberos_token = kerberos.authGSSServerResponse(state)
                user = kerberos.authGSSServerUserName(state)
                self.log.info("Extracted User = " + user)
                return "kerberos.AUTH_GSS_COMPLETE:" + user
            elif rc == kerberos.AUTH_GSS_CONTINUE:
                #self.log.info("rc == kerberos.AUTH_GSS_CONTINUE")
                return "kerberos.AUTH_GSS_CONTINUE"
            else:
                self.log.info("return None")
                return None
        except kerberos.GSSError as err:
            self.log.info("kerberos.GSSError: {0}".format(err))
            return None
        finally:
            if state:
                kerberos.authGSSServerClean(state)
