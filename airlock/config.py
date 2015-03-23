"""
In your program's main, call `airlock.set_config` and provide
a configuration object that follows the below format.

{
    'client_secrets_path': client_secrets_path,
    'scopes': airlock.config.Defaults.OAUTH_SCOPES,
    'xsrf_cookie_name': airlock.config.Defaults.Xsrf.COOKIE_NAME,
    'policies': {
        'csp': airlock.config.Defaults.Policies.CSP,
        'frame_options': airlock.config.Defaults.XFrameOptions.SAMEORIGIN,
        'hsts': airlock.config.Defaults.Policies.HSTS,
    },
    'webapp2_extras.auth': {
        'token_cache_age': airlock.config.Defaults.Xsrf.TOKEN_AGE,
        'token_max_age': airlock.config.Defaults.Xsrf.TOKEN_AGE,
        'token_new_age': airlock.config.Defaults.Xsrf.TOKEN_AGE,
        'user_model': '<path.to.user.model.subclass.User>',
    },
    'webapp2_extras.sessions': {
        'secret_key': '<secret_key>',
        'user_model': '<path.to.user.model.subclass.User>',
    },
}
"""
import os

__all__ = [
    'set_config',
    'Defaults',
]

_airlock_config = None


class Error(Exception):
  pass


class ConfigError(Error, ValueError):
  pass


def set_config(config):
  # Enforce "secure" and "httponly" properties for webapp2 sessions.
  if 'webapp2_extras.sessions' not in config:
    config['webapp2_extras.sessions'] = {}
  if 'cookie_args' not in config['webapp2_extras.sessions']:
    config['webapp2_extras.sessions']['cookie_args'] = {}
  config['webapp2_extras.sessions']['cookie_args']['httponly'] = True
  _is_secure = os.getenv('wsgi.url_scheme', '') == 'https'
  config['webapp2_extras.sessions']['cookie_args']['secure'] = _is_secure
  # Set defaults for auth tokens.
  if 'webapp2_extras.auth' not in config:
    config['webapp2_extras.auth'] = {}
  if 'token_cache_age' not in config['webapp2_extras.auth']:
    config['webapp2_extras.auth']['token_cache_age'] = Defaults.Xsrf.TOKEN_AGE
  if 'token_max_age' not in config['webapp2_extras.auth']:
    config['webapp2_extras.auth']['token_max_age'] = Defaults.Xsrf.TOKEN_AGE
  if 'token_new_age' not in config['webapp2_extras.auth']:
    config['webapp2_extras.auth']['token_new_age'] = Defaults.Xsrf.TOKEN_AGE
  global _airlock_config
  _airlock_config = config


def get_config():
  return _airlock_config


class Defaults(object):

  class Xsrf(object):
    COOKIE_NAME = 'XSRF_TOKEN'
    TOKEN_AGE = 60 * 60 * 24 * 7 * 1  # 1 week.

  class XFrameOptions(object):
    DENY = 'DENY'
    SAMEORIGIN = 'SAMEORIGIN'

  class Policies(object):
    CSP = None
    HSTS = {'max_age': 2592000, 'includeSubdomains': True,}

  OAUTH_SCOPES = [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
  ]
