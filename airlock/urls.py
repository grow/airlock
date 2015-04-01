from . import config as config_lib
from oauth2client import xsrfutil
import urllib



class AuthUrls(object):

  def __init__(self, handler):
    self.handler = handler

  def sign_in(self):
    """Returns a signed URL to use to kick off the oauth2 flow."""
    return self.handler.decorator.authorize_url()

  def sign_out(self, redirect_url=None):
    """Returns a signed URL to disassociate the ouath2 user from the session."""
    config = config_lib.get_config()
    key = self.handler.app.config['webapp2_extras.sessions']['secret_key']
    if redirect_url is None:
      redirect_url = self.handler.request.url
    user_id = self.handler.me.user_id()
    token = xsrfutil.generate_token(key, user_id, action_id=redirect_url)
    return '{}/signout?{}'.format(config['airlock_path'], urllib.urlencode({
        'redirect': redirect_url,
        'token': token,
    }))
