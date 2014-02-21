from . import config as config_lib
from oauth2client import xsrfutil
from webapp2_extras.appengine.auth import models

__all__ = [
    'User',
]


class User(models.User):

  def user_id(self):
    return str(self.key.id())

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
