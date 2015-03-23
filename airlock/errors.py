from protorpc import remote


class Error(Exception):

  def __init__(self, message):
    super(Error, self).__init__(message)
    self.message = message


class BadRequestError(Error, remote.ApplicationError):
  status = 400


class XsrfTokenError(BadRequestError):
  pass


class MissingXsrfTokenError(XsrfTokenError):
  pass


class XsrfTokenMismatchError(XsrfTokenError):
  pass


class BadXsrfTokenError(XsrfTokenError):
  pass


class NotFoundError(Error, remote.ApplicationError):
  status = 404


class ConflictError(Error, remote.ApplicationError):
  status = 409


class NotAuthorizedError(Error, remote.ApplicationError):
  status = 401


class ForbiddenError(Error, remote.ApplicationError):
  status = 403
