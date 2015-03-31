# airlock

Airlock is a lightweight, web-security-concious wrapper for *webapp2* on
Google App Engine. It provides oauth2 integration for identity management
with Google Accounts, sessions, and user management.

## Comparison

Airlock is a drop-in replacement for several `webapp2` and `protorpc`
objects. Specifically, it wraps `remote.Service`, `webapp2.WSGIApplication`,
and `webapp2.RequestHandler` to provide authentication and session features
via oauth2 and the `oauth2client` library.

| original | airlock variant |
| -------- | --------------- |
| `protorpc.remote.Service` | `airlock.Service` |
| `webapp2.RequestHandler` | `airlock.Handler` |
| `webapp2.WSGIApplication` | `airlock.WSGIApplication` |

## User features

* Oauth2 integration with Google Accounts (sign in and sign out).
* Anonymous user/session support.

## Security features

* A standard configuration format for specifying the security characteristics of an application.
* Provides a framework for setting the following headers:
  * Content security policy.
  * HSTS policy.
  * XSRF.

## Usage

1. Download client secrets.
1. In appengine config, use airlock.set_config
1. Use airlock's subclasses.
1. Set up a `User` model.
