from . import handlers
from . import users
from apiclient import discovery
from google.appengine.api import memcache
from oauth2client import appengine
from oauth2client import xsrfutil
import httplib2
import json
import logging



class OAuth2CallbackHandler(handlers.Handler):
  """Callback handler for oauth2 flow."""

  def get(self):
    # In order to use our own User class and webapp2 sessions
    # for user management instead of the App Engine Users API (which requires
    # showing a very ugly sign in page and requires the user to authorize
    # Google twice, essentially), we've created our own version of oauth2client's
    # OAuth2CallbackHandler.
    error = self.request.get('error')
    if error:
      message = self.request.get('error_description', error)
      logging.error(message)
      self.response.out.write('Authorization request failed.')
      return

    # Resume the oauth flow.
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

    # Store the user in the session.
    self.auth.set_session({'user_id': auth_id}, remember=True)

    session_user = users.UserStub(self.session['sid'])
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


class SignOutHandler(handlers.Handler):

  def get(self):
    key = self.config['webapp2_extras.sessions']['secret_key']
    redirect_url = str(self.request.get('redirect'))
    if self.me is not None:
      token = str(self.request.get('token'))
      xsrfutil.validate_token(key, token, self.me.user_id(), action_id=redirect_url)
      self.auth.unset_session()
    self.redirect(redirect_url)
