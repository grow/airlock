# airlock

A lightweight wrapper providing Google oauth2 integration, sessions,
XSRF validators, and user management for App Engine apps.

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

## Usage

TODO(jeremydw): Documentation

1. Download client secrets.
1. In appengine config, use airlock.set_config
1. Use airlock's subclasses.
1. Set up a `User` model.
