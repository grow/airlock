from . import config as config_lib
from . import handlers
import webapp2

__all__ = [
    'middleware',
    'WSGIApplication',
]


def _get_airlock_app(config):
  return webapp2.WSGIApplication([
      ('/_airlock/oauth2callback', handlers.OAuth2CallbackHandler),
      ('/_airlock/signout', handlers.SignOutHandler),
  ], config=config)


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
  wsgi_app = webapp2.WSGIApplication(routes, config=config)
  return middleware(wsgi_app, config)
