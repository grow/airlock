"""
In your program's main, call `airlock.set_config` and provide
a configuration object that follows the below format.

AIRLOCK_CONFIG = {
    'client_secrets_path': client_secrets_path,
    'xsrf_cookie_name': airlock.config.Defaults.Xsrf.COOKIE_NAME,
    'policies': {
        'csp': airlock.config.Defaults.Policies.CSP,
        'frame_options': airlock.config.Defaults.XFrameOptions.SAMEORIGIN,
        'hsts': airlock.config.Defaults.Policies.HSTS,
    },
    'scopes': airlock.config.Defaults.OAUTH_SCOPES,
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
    HSTS = {'max_age': 2592000, 'includeSubdomains': True}

  OAUTH_SCOPES = [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
  ]
