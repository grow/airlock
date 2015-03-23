from . import config as config_lib
from oauth2client import xsrfutil
from webapp2_extras.appengine.auth import models
from google.appengine.ext import ndb

__all__ = [
    'User',
]


class UserStub(object):
  """Stub user for anonymous sessions."""

  def __init__(self, sid):
    self.sid = sid

  def user_id(self):
    # Provides compatibility with oauth2client's {_build|_parse}_state_value.
    return self.sid


class User(models.User):
  session_id = ndb.StringProperty()

  @property
  def registered(self):
    return self.key is not None

  @property
  def is_registered(self):
    return self.key is not None

  def user_id(self):
    if self.registered:
      return str(self.key.id())
    return self.session_id

  def create_xsrf_token(self):
    config = config_lib.get_config()
    key = config['webapp2_extras.sessions']['secret_key']
    return xsrfutil.generate_token(key, self.user_id())

  def validate_token(self, token):
    config = config_lib.get_config()
    key = config['webapp2_extras.sessions']['secret_key']
    return xsrfutil.validate_token(key, token, self.user_id())

  def delete(self):
    name = self.__class__.__name__
    User.unique_model.delete_multi([
        '{}.auth_id:{}'.format((name, auth_id)) for auth_id in self.auth_ids
    ])
    self.key.delete()

  @classmethod
  def get_by_email(cls, email):
    query = cls.query()
    query = query.filter(cls.email == email)
    return query.get()

  @classmethod
  def get_or_create_by_email(cls, email):
    ent = cls.get_by_email(email)
    if ent is None:
      ent = cls(email=email)
      ent.put()
    return ent
