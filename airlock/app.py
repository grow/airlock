import endpoints
from . import config as config_lib
from . import oauth
import webapp2
from google.appengine.api import users

__all__ = [
    'WSGIApplication',
]


def middleware(app):
  def respond(environ, start_response):
    # Handle _airlock internal URLs for sign in and sign out.
    if environ['PATH_INFO'].startswith('/_airlock'):
      airlock_app = webapp2.WSGIApplication([
          ('/_airlock/oauth2callback', oauth.OAuth2CallbackHandler),
          ('/_airlock/signout', oauth.SignOutHandler),
      ], debug=app.debug, config=app.config)
      return airlock_app(environ, start_response)

    # Endpoints requests are allowed.
    # TODO: Make this configurable.
    try:
      endpoints.get_current_user()
      return app(environ, start_response)
    except endpoints.InvalidGetUserCall:
      # Not inside an endpoints request.
      pass

    # If all domains are allowed, continue.
    # TODO: Make allowed paths configurable.
    allowed_user_domains = app.config.get('allowed_user_domains')
    if (allowed_user_domains
        and not environ['PATH_INFO'].startswith('/_')):
      # Redirect anonymous users to login.
      user = users.get_current_user()
      if user is None:
        url =  users.create_login_url(environ['PATH_INFO'])
        start_response('302 Redirect', [('Location', url)])
        return ['']
      # Ban forbidden users.
      if user.email().split('@')[-1] not in allowed_user_domains:
        start_response('403 Forbidden', [('Content-Type', 'text/html'),])
        url = users.create_logout_url(environ['PATH_INFO'])
        return ['Forbidden. <a href="{}">Sign out</a>.'.format(url)]
    return app(environ, start_response)
  return respond


def WSGIApplication(*args, **kwargs):
  config = kwargs.get('config')
  if config is None:
    config = config_lib.get_config()
    kwargs['config'] = config
  return middleware(webapp2.WSGIApplication(*args, **kwargs))
