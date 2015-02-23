import endpoints
from . import config as config_lib
from . import handlers
import webapp2
from google.appengine.api import users

__all__ = [
    'middleware',
    'WSGIApplication',
]


def _get_airlock_app(config):
  return webapp2.WSGIApplication([
      ('/_airlock/oauth2callback', handlers.OAuth2CallbackHandler),
      ('/_airlock/signout', handlers.SignOutHandler),
  ], config=config)


def allowed_user_domains_middleware(wsgi_app):

  def middleware(environ, start_response):
    try:
      # Allow endpoints requests.
      # TODO: Make this configurable.
      endpoints.get_current_user()
      return wsgi_app(environ, start_response)
    except endpoints.InvalidGetUserCall:
      # Not inside an endpoints request.
      pass
    config = config_lib.get_config()
    allowed_user_domains = config.get('allowed_user_domains')
    # If all domains are allowed, continue.
    if allowed_user_domains is None:
      return wsgi_app(environ, start_response)
    user = users.get_current_user()
    # Redirect anonymous users to login.
    if user is None:
      url =  users.create_login_url(environ['PATH_INFO'])
      start_response('302', [('Location', url)])
      return []
    # Ban forbidden users.
    if user.email().split('@')[-1] not in allowed_user_domains:
      start_response('403', [])
      url = users.create_logout_url(environ['PATH_INFO'])
      return ['Forbidden. <a href="{}">Sign out</a>.'.format(url)]
    return wsgi_app(environ, start_response)
  return middleware


def middleware(wsgi_app, config):
  def respond(environ, start_response):
    if environ['PATH_INFO'].startswith('/_airlock'):
      airlock_app = _get_airlock_app(config)
      return airlock_app(environ, start_response)
    return wsgi_app(environ, start_response)
  return respond


def WSGIApplication(routes, config=None):
  if config is None:
    config = config_lib.get_config()
  wsgi_app = allowed_user_domains_middleware(
      webapp2.WSGIApplication(routes, config=config))
  return middleware(wsgi_app, config)
