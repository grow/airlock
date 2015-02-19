from protorpc import remote


class Error(Exception):

  def __init__(self, message):
    super(Error, self).__init__(message)
    self.message = message


class BadRequestError(Error, remote.ApplicationError):
  pass


class XsrfTokenError(BadRequestError):
  pass


class MissingXsrfTokenError(XsrfTokenError):
  pass


class XsrfTokenMismatchError(XsrfTokenError):
  pass


class BadXsrfTokenError(XsrfTokenError):
  pass


class NotFoundError(Error, remote.ApplicationError):
  pass


class ConflictError(Error, remote.ApplicationError):
  pass


class NotAuthorizedError(Error, remote.ApplicationError):
  pass
