from . import config as config_lib
from protorpc import remote
from webapp2_extras import auth as webapp2_auth
import Cookie
import endpoints
import logging
import os
import webapp2

__all__ = [
    'Service',
]


class Error(Exception):

  def __init__(self, message):
    super(Error, self).__init__(message)
    self.message = message


class BadRequestError(Error, remote.ApplicationError):
  pass


class XsrfTokenError(BadRequestError):
  pass


class MissingXsrfTokenError(XsrfTokenError):
  pass


class XsrfTokenMismatchError(XsrfTokenError):
  pass


class BadXsrfTokenError(XsrfTokenError):
  pass


class NotFoundError(Error, remote.ApplicationError):
  pass


class ConflictError(Error, remote.ApplicationError):
  pass


class NotAuthorizedError(Error, remote.ApplicationError):
  pass


class Service(remote.Service):

  admin_verifier = None

  @webapp2.cached_property
  def auth(self):
    config = config_lib.get_config()
    request = webapp2.Request(environ=dict(os.environ))
    request.app = webapp2.WSGIApplication(config=config)
    return webapp2_auth.get_auth(request=request)

  @property
  def user_model(self):
    return self.auth.store.user_model

  @webapp2.cached_property
  def _endpoints_user(self):
    try:
      return endpoints.get_current_user()
    except endpoints.InvalidGetUserCall:
      return None  # Not inside an endpoints request.

  @webapp2.cached_property
  def me(self):
    if self._endpoints_user is not None:
      return self.user_model.get_by_email(self._endpoints_user.email())
    user_dict = self.auth.get_user_by_session()
    if user_dict:
      return self.user_model.get_by_auth_id(str(user_dict['user_id']))

  def require_me(self):
    if self.me is None:
      raise NotAuthorizedError('You must be logged in.')

  def require_admin(self):
    if self.me is None or not self.admin_verifier(self.me.email):
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
      raise MissingXsrfTokenError('Missing header token.')

    cookie = Cookie.SimpleCookie(headers['cookie'])
    if 'xsrf_token' not in cookie:
      raise MissingXsrfTokenError('Missing cookie token.')

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
