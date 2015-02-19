from . import config as config_lib
from . import handlers
from .errors import *
from protorpc import remote
from webapp2_extras import auth as webapp2_auth
import Cookie
import logging
import os
import webapp2

__all__ = [
    'Service',
]


class Service(remote.Service, handlers.BaseHandler):

  admin_verifier = None

  @webapp2.cached_property
  def app(self):
    config = config_lib.get_config()
    return webapp2.WSGIApplication(config=config)

  @webapp2.cached_property
  def request(self):
    # Allows compatibility with handlers.BaseHandler.
    request = webapp2.Request(environ=dict(os.environ))
    request.app = self.app
    return request

  @webapp2.cached_property
  def auth(self):
    return webapp2_auth.get_auth(request=self.request)

  def require_me(self):
    if not self.me.is_registered:
      raise NotAuthorizedError('You must be logged in.')

  def require_admin(self):
    if not self.me.is_registered or not self.admin_verifier(self.me.email):
      logging.error('User is unauthorized: {}'.format(self.me))
      raise NotAuthorizedError('Not authorized.')

  def require_xsrf_protection(self):
    self.require_me()
    if self._endpoints_user is not None:
      return  # Assume endpoints clients are XSRF-protected.

    headers = self.__request_state.headers

    # Verify XSRF token using the "double submit cookie" strategy.
    # https://www.owasp.org/index.php/
    # Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookies
    if 'X-XSRF-Token' not in headers or 'cookie' not in headers:
      raise MissingXsrfTokenError('Missing XSRF header token.')

    cookie = Cookie.SimpleCookie(headers['cookie'])
    if 'xsrf_token' not in cookie:
      raise MissingXsrfTokenError('Missing XSRF cookie token.')

    # Verify that a property of the request (the "X-XSRF-Token" header) matches
    # a cookie ("xsrf_token") included with the request. Due to the same-origin
    # policy, an XSRF-attacker would not be able to read or set cookie values on
    # our domain, preventing the attacker from submitting a cookie that maches
    # the header.
    cookie_token = cookie.get('xsrf_token').value
    header_token = headers.get('X-XSRF-Token')
    if header_token != cookie_token:
      raise XsrfTokenMismatchError('XSRF token mismatch.')

    # Also, verify that the token is actually for the current user.
    if not self.me.validate_token(header_token):
      raise BadXsrfTokenError('Invalid XSRF token.')

  @staticmethod
  def admin_required(admin_func):
    def decorator(method):
      def wrapped_func(*args, **kwargs):
        self = args[0]
        self.require_admin()
        return method(*args, **kwargs)
      return wrapped_func
    return decorator

  @staticmethod
  def me_required(method):
    def wrapped_func(*args, **kwargs):
      self = args[0]
      self.require_me()
      return method(*args, **kwargs)
    return wrapped_func

  @staticmethod
  def xsrf_protected(method):
    def wrapped_func(*args, **kwargs):
      self = args[0]
      self.require_xsrf_protection()
      return method(*args, **kwargs)
    return wrapped_func
