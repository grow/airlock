from apiclient import discovery
from google.appengine.api import memcache
from oauth2client import appengine
from oauth2client import xsrfutil
from webapp2_extras import auth as webapp2_auth
from webapp2_extras import security
from webapp2_extras import sessions
import httplib2
import json
import logging
import urllib
import webapp2

__all__ = [
    'Handler',
]


class UserStub(object):
  """Stub user for anonymous sessions."""

  def __init__(self, sid):
    self.sid = sid

  def user_id(self):
    # Provides compatibility with oauth2client's {_build|_parse}_state_value.
    return self.sid


class Handler(webapp2.RequestHandler):
  """A request handler that supports webapp2 sessions."""

  @webapp2.cached_property
  def urls(self):
    return AuthUrls(self)

  @property
  def user_model(self):
    return self.auth.store.user_model

  @webapp2.cached_property
  def decorator(self):
    config = self.app.config
    decorator = appengine.oauth2decorator_from_clientsecrets(
        config['client_secrets_path'], scope=config['scopes'])
    decorator._callback_path = '/_airlock/oauth2callback'
    return decorator

  def dispatch(self):
    """Wraps the dispatch method to add session handling."""
    self.session_store = sessions.get_store(request=self.request)

    # Add the user's credentials to the decorator if we have them.
    if self.me:
      self.decorator.credentials = self.decorator._storage_class(
          self.decorator._credentials_class, None,
          self.decorator._credentials_property_name, user=self.me).get()
    else:
      # Create a session ID for the session if it does not have one already.
      # This is used to create an opaque string that can be passed to the OAuth2
      # authentication server via the 'state' parameter.
      if not self.session.get('sid'):
        self.session['sid'] = security.generate_random_string(entropy=128)

      # Store the state for the session user in a parameter on the flow.
      # We only need to do this if we're not logged in.
      self.decorator._create_flow(self)
      session_user = UserStub(self.session['sid'])
      self.decorator.flow.params['state'] = appengine._build_state_value(
          self, session_user)

    try:
      webapp2.RequestHandler.dispatch(self)
    finally:
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def auth(self):
    return webapp2_auth.get_auth()

  @webapp2.cached_property
  def me(self):
    user_dict = self.auth.get_user_by_session()
    if user_dict:
      return self.user_model.get_by_auth_id(str(user_dict['user_id']))

  @webapp2.cached_property
  def session(self):
    return self.session_store.get_session()


class AuthUrls(object):

  def __init__(self, handler):
    self.handler = handler

  def sign_in(self):
    return self.handler.decorator.authorize_url()

  def sign_out(self, redirect_url=None):
    key = self.handler.app.config['webapp2_extras.sessions']['secret_key']
    if redirect_url is None:
      redirect_url = self.handler.request.url
    token = xsrfutil.generate_token(key, self.handler.me.user_id(), action_id=redirect_url)
    return '/_airlock/signout?{}'.format(urllib.urlencode({
        'redirect': redirect_url,
        'token': token,
    }))


class OAuth2CallbackHandler(Handler):
  """Callback handler for OAuth2 flow."""

  def get(self):
    # In order to use our own User class and webapp2 sessions
    # for user management instead of the App Engine Users API (which requires
    # showing a very ugly sign in page and requires the user to authorize
    # Google twice, essentially), we've created our own version of oauth2client's
    # OAuth2CallbackHandler.
    error = self.request.get('error')
    if error:
      message = self.request.get('error_description', error)
      text = 'Authorization request failed: {}'
      self.response.out.write(text.format(message))
      return

    # Resume the OAuth flow.
    self.decorator._create_flow(self)
    credentials = self.decorator.flow.step2_exchange(self.request.params)

    # Get a Google Account ID for the user that just OAuthed in.
    http = credentials.authorize(httplib2.Http(memcache))
    service = discovery.build('oauth2', 'v2', http=httplib2.Http(memcache))

    # Keys are: name, email, given_name, family_name, link, locale, id,
    # gender, verified_email (which is a bool), picture (url).
    data = service.userinfo().v2().me().get().execute(http=http)
    auth_id = 'google:{}'.format(data['id'])

    # If the user is returning, try and find an existing User.
    # If the user is signing in for the first time, create a User.
    user = self.user_model.get_by_auth_id(auth_id)
    if user is None:
      nickname = data['email']
      data.pop('id', None)
      unique_properties = ['nickname', 'email']
      ok, user = self.user_model.create_user(
          auth_id, unique_properties=unique_properties, nickname=nickname,
          **data)
      if not ok:
        logging.exception('Invalid values: {}'.format(user))
        self.error(500, 'Error creating user.')
        return

    # Store the User in the session.
    self.auth.set_session({'user_id': auth_id}, remember=True)

    session_user = UserStub(self.session['sid'])
    redirect_uri = appengine._parse_state_value(
        str(self.request.get('state')), session_user)

    # Store the user's credentials for later possible use.
    storage = self.decorator._storage_class(
        model=self.decorator._credentials_class,
        key_name='user:{}'.format(user.user_id()),
        property_name=self.decorator._credentials_property_name)
    storage.put(credentials)

    # Adjust the redirect uri in case this callback occurred as part of an
    # authenticated request to get some data.
    if self.decorator._token_response_param and credentials.token_response:
      resp = json.dumps(credentials.token_response)
      redirect_uri = appengine.util._add_query_parameter(
          redirect_uri, self.decorator._token_response_param, resp)

    self.redirect(redirect_uri)


class SignOutHandler(Handler):

  def get(self):
    key = self.app.config['webapp2_extras.sessions']['secret_key']
    redirect_url = str(self.request.get('redirect'))
    if self.me is not None:
      token = str(self.request.get('token'))
      xsrfutil.validate_token(key, token, self.me.user_id(), action_id=redirect_url)
      self.auth.unset_session()
    self.redirect(redirect_url)
