from . import config as config_lib
from . import handlers
from . import errors
from protorpc import remote
from webapp2_extras import auth as webapp2_auth
import Cookie
import os
import webapp2

__all__ = [
    'Service',
]



class Service(remote.Service, handlers.BaseHandler):
  """Enables compatibility with handlers.BaseHandler."""

  admin_verifier = None

  @webapp2.cached_property
  def app(self):
    config = config_lib.get_config()
    return webapp2.WSGIApplication(config=config)

  @webapp2.cached_property
  def request(self):
    request = webapp2.Request(environ=dict(os.environ))
    request.app = self.app
    return request

  @webapp2.cached_property
  def auth(self):
    return webapp2_auth.get_auth(request=self.request)

  def require_xsrf_protection(self):
    if self._endpoints_user is not None:
      return  # Assume endpoints clients are XSRF-protected.

    headers = self.__request_state.headers
    header_token = headers.get('X-XSRF-Token')

    # Verify XSRF token using the "double submit cookie" strategy.
    # https://www.owasp.org/index.php/
    # Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookies
    if 'X-XSRF-Token' not in headers:
      raise errors.MissingXsrfTokenError('Missing XSRF header token.')

    # Verify an XSRF cookie, if the app has opted into also using XSRF cookies.
    if self.config.get('use_xsrf_cookie', False):
      cookie = Cookie.SimpleCookie(headers.get('cookie', ''))
      cookie_name = self.config.get('xsrf_cookie_name',
                                    config_lib.Defaults.Xsrf.COOKIE_NAME)
      if cookie_name not in cookie:
        raise errors.MissingXsrfTokenError('Missing XSRF cookie token.')

      # Verify that a property of the request (the "X-XSRF-Token" header) matches
      # a cookie ("xsrf_token") included with the request. Due to the same-origin
      # policy, an XSRF-attacker would not be able to read or set cookie values on
      # our domain, preventing the attacker from submitting a cookie that maches
      # the header.
      cookie_token = cookie.get(cookie_name).value
      if header_token != cookie_token:
        raise errors.XsrfTokenMismatchError('XSRF token mismatch.')

    # Also, verify that the token is actually for the current user.
    if not self.me.validate_token(header_token):
      raise errors.BadXsrfTokenError('Invalid XSRF token.')

  @staticmethod
  def xsrf_protected(method):
    def wrapped_func(*args, **kwargs):
      self = args[0]
      self.require_xsrf_protection()
      return method(*args, **kwargs)
    return wrapped_func
