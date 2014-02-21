"""
In your program's main, call `airlock.set_config` and provide
a configuration object that follows the below format.

_token_age = 60 * 60 * 24 * 7 * 1  # 1 week.

AIRLOCK_CONFIG = {
    'client_secrets_path': client_secrets_path,
    'scopes': [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
    ],
    'webapp2_extras.auth': {
        'token_cache_age': _token_age,
        'token_max_age': _token_age,
        'token_new_age': _token_age,
        'user_model': 'path.to.user.model.subclass.User',
    },
    'webapp2_extras.sessions': {
        'secret_key': _secret_key,
        'user_model': 'path.to.user.model.subclass.User',
    },
}
"""

__all__ = [
    'set_config',
]

_airlock_config = None


class Error(Exception):
  pass


def set_config(config):
  global _airlock_config
  _airlock_config = config


def get_config():
  return _airlock_config
