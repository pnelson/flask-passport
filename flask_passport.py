# -*- coding: utf-8 -*-
"""
    flask.ext.passport
    ~~~~~~~~~~~~~~~~~~

    Adds authorization and authentication support to your Flask application.

    :copyright: (c) 2011 by Philip Nelson.
    :license: BSD, see LICENSE for more details.
"""

from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer as Serializer
from werkzeug.exceptions import Forbidden

__all__ = ['Passport', 'Permission', 'Refusal']

class Passport(object):
    """This class is used to control the Passport integration with a Flask
    application. There are two usage modes which are similar.

    The first usage mode is to bind the instance to a specific application::

        app = Flask(__name__)
        passport = Passport(app)

    The second usage mode is to initialize the extension and provide an
    application object later::

        passport = Passport()

        def create_app():
          app = Flask(__name__)
          passport.init_app(app)
          return app

    The latter of course has the benefit of avoiding all kinds of problems as
    described in the Flask documentation on the :ref:`~app-factories` pattern.
    """

    #: The namespace for signed passport data.
    namespace = "passport"

    #: The prefix for session keys.
    session_prefix = "passport."

    #: The name of the persistent passport cookie.
    persistent_cookie_name = "passport"

    def __init__(self, app=None):
        self._loader = None
        self._on_authenticate_401 = None
        self._on_reauthenticate_401 = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initializes `app`, a :class:`~flask.Flask` application, for use with
        the specified configuration variables.
        """
        #: The session key to store the user ID.
        self.user_id_key = self.session_prefix + "user_id"

        #: The session key to store the user agent.
        self.user_agent_key = self.session_prefix + "user_agent"

        #: The session key to store the stale status.
        self.stale_key = self.session_prefix + "stale"

        #: The session key to store the persistent option.
        self.persist_key = self.session_prefix + "persist"

        #: The endpoint used in :meth:`redirect_to_login`.
        self.login_endpoint = app.config.get('PASSPORT_LOGIN_ENDPOINT')

        #: The key of the GET argument used in :meth:`redirect_to_login`.
        self.next_key = app.config.get('PASSPORT_NEXT_KEY', "next")

        #: A duration in seconds or as a :class:`~datetime.timedelta` which
        #: is used to set the expiration date of the passport cookie. The
        #: default is 14 days.
        self.duration = app.config.get('PASSPORT_COOKIE_DURATION', 1209600)

        #: The path for the passport cookie. If this is not set, the cookie
        #: will be valid for all of ``APPLICATION_ROOT`` or ``"/"`` if that
        #: is not set.
        self.path = app.config.get('PASSPORT_COOKIE_PATH') or \
                    app.config['APPLICATION_ROOT'] or "/"

        #: The domain for the passport cookie. If this is not set, the
        #: cookie will be valid for all subdomains of ``SERVER_NAME``.
        self.domain = app.config.get('PASSPORT_COOKIE_DOMAIN')
        if self.domain is None and app.config['SERVER_NAME'] is not None:
            self.domain = "." + app.config['SERVER_NAME'].rsplit(":", 1)[0]

        #: This controls if the cookie should be set with the `secure` flag.
        self.secure = app.config.get('PASSPORT_COOKIE_SECURE', True)

        #: This controls if the cookie should be set with the `httponly` flag.
        self.httponly = app.config.get('PASSPORT_COOKIE_HTTPONLY', True)

        self.serializer = Serializer(app.secret_key, salt=self.namespace)
        self.dumps = self.serializer.dumps
        self.loads = self.serializer.loads

        app.before_request(self._set_global_identity)
        app.after_request(self._update_cookie)

    def authenticate(self, f):
        """A decorator to ensure the the user is signed in. If the user is not
        found in the session, the authentication handler will be called. If an
        authentication handler was not set, :meth:`redirect_to_login` will be
        called.
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get(self.user_id_key) is None:
                rv = self._on_authenticate_401 or self.redirect_to_login
                return rv()
            return f(*args, **kwargs)
        return wrapper

    def reauthenticate(self, f):
        """A decorator to ensure the user is signed in recently. At first this
        behaves like :meth:`authenticate` but if the user is found in the
        the session, it ensures that it is not a stale session loaded from the
        persistent cookie. If the session is found to be stale, the
        reauthentication handler will be called. If the reauthentication
        handler was not set, it will fall back and call the authentication
        handler instead. Finally if the authentication handler was not set,
        :meth:`redirect_to_login` will be called.
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get(self.user_id_key) is None:
                rv = self._on_authenticate_401 or self.redirect_to_login
                return rv()
            elif session.get(self.stale_key):
                rv = self._on_reauthenticate_401 or \
                     self._on_authenticate_401 or \
                     self.redirect_to_login
                return rv()
            return f(*args, **kwargs)
        return wrapper

    def login(self, user_id, persist=False):
        """Logs the user in by filling out the Passport and preparing the
        persistent cookie to be saved if specified.
        """
        session[self.user_id_key] = str(user_id)
        session[self.user_agent_key] = request.headers.get('User-Agent')
        session[self.stale_key] = False
        if persist:
            session[self.persist_key] = True

    def logout(self):
        """Logs the user out by clearing the Passport and preparing the
        persistent cookie to be deleted by the after request hook.
        """
        session.pop(self.user_id_key, None)
        session.pop(self.user_agent_key, None)
        session.pop(self.stale_key, None)
        if self.persistent_cookie_name in request.cookies:
            session[self.persist_key] = False

    def redirect_to_login(self, *args, **kwargs):
        """A convenience method to redirect to the login page as defined by
        te `PASSPORT_LOGIN_ENDPOINT` configuration value. If the
        `PASSPORT_NEXT_KEY` configuration value was set, this method will
        also add the originally requested path as a GET argument with the
        configured key.
        """
        if self.next_key:
            kwargs[self.next_key] = request.path
        assert self.login_endpoint, "Configuration variable " \
            "PASSPORT_LOGIN_ENDPOINT was not properly set."
        return redirect(url_for(self.login_endpoint, *args, **kwargs))

    def loader(self, f):
        """The decorator to set a callback for loading the authorized user
        into `g.user`. The identity loader callback is expected to take a
        single string `user_id` and return a user object of some sort or
        `None` if a user is not found. Do not raise an exception here.
        """
        self._loader = f

    def on_authenticate_401(self, f):
        """The decorator to set a callback for authentication errors."""
        self._on_authenticate_401 = f

    def on_reauthenticate_401(self, f):
        """The decorator to set a callback for stale authentication errors."""
        self._on_reauthenticate_401 = f

    def _set_global_identity(self):
        g.user = self._get_user()
        if g.user is None:
            self.logout()
    
    def _update_cookie(self, rv):
        persist = session.pop(self.persist_key, None)

        if persist is None:
            return rv

        if persist:
            data = self.dumps([session[self.user_id_key],
                               request.headers.get('User-Agent')])
            rv.set_cookie(self.persistent_cookie_name, data,
                          max_age=self.duration, path=self.path,
                          domain=self.domain, secure=self.secure,
                          httponly=self.httponly)
        else:
            rv.delete_cookie(self.persistent_cookie_name, path=self.path,
                             domain=self.domain)

        return rv

    def _get_user(self):
        user_id = session.get(self.user_id_key)
        user_agent = session.get(self.user_agent_key)

        if user_id is None:
            data = request.cookies.get(self.persistent_cookie_name)

            if data is None:
                return None

            try:
                user_id, user_agent = self.loads(data, max_age=self.duration)
            except BadSignature:
                return None

            session[self.user_id_key] = user_id
            session[self.user_agent_key] = user_agent
            session[self.stale_key] = True

        if user_agent != request.headers.get('User-Agent'):
            return None

        return self._loader(user_id)

class Permission(object):
    """Represents a set of permissions with a set of required entities and a
    set of forbidden entities. Entities can be anything, but a named tuple
    is often the preferred choice as they can describe entities with much
    greater control.

    :param *required: Initializes the permission with required entities.
    """

    def __init__(self, *required):
        self.required = set(required)
        self.forbidden = set()

    def union(self, other):
        """Returns a new set of permissions with entities from itself and
        `other`.
        """
        rv = Permission(*self.required | other.required)
        rv.forbidden.update(self.forbidden | other.forbidden)
        return rv

    def intersection(self, other):
        """Returns a new set of permissions with entities common to itself
        and `other`.
        """
        rv = Permission(*self.required & other.required)
        rv.forbidden.update(self.forbidden & other.forbidden)
        return rv

    def difference(self, other):
        """Returns a new set of permissions with entities in itself that are
        not in `other`.
        """
        rv = Permission(*self.required - other.required)
        rv.forbidden.update(self.forbidden - other.forbidden)
        return rv

    def symmetric_difference(self, other):
        """Returns a new set of permissions with entities that are in either
        itself or `other` but not in both.
        """
        rv = Permission(*self.required ^ other.required)
        rv.forbidden.update(self.forbidden ^ other.forbidden)
        return rv

    def isdisjoint(self, other):
        """Returns `True` if the intersection between itself and `other` is
        empty.
        """
        return not self & other

    def issubset(self, other):
        """Returns `True` if every entity in itself is in `other`."""
        return self.required.issubset(other.required) and \
               self.forbidden.issubset(other.forbidden)

    def issuperset(self, other):
        """Returns `True` if every entity in `other` is in itself."""
        return self.required.issuperset(other.required) and \
               self.forbidden.issuperset(other.forbidden)

    def authorize_or_403(self, provided):
        """TODO"""
        if not isinstance(provided, (set, frozenset)):
            provided = frozenset(provided)
        if provided < self.required or provided & self.forbidden:
            raise Forbidden

    def __lt__(self, other):
        """Like :meth:`issubset` but the sets must not be equal."""
        return self.issubset(other) and self != other

    def __le__(self, other):
        """The operator shortcut for :meth:`issubset`."""
        return self.issubset(other)

    def __eq__(self, other):
        """Returns `True` if the required and forbidden sets of itself are
        equal to the required and forbidden sets of `other`.
        """
        return self.required == other.required and \
               self.forbidden == other.forbidden

    def __ne__(self, other):
        """Returns `True` if the required and forbidden sets of itself are not
        equal to the required and forbidden sets of `other`.
        """
        return not self.__eq__(other)

    def __gt__(self, other):
        """Like :meth:`issuperset` but the sets must not be equal."""
        return self.issuperset(other) and self != other

    def __ge__(self, other):
        """The operator shortcut for :meth:`issuperset`."""
        return self.issuperset(other)

    def __nonzero__(self):
        """The set of permissions is considered `True` by truth value testing
        and the built-in :func:`~bool` operation if both the required and
        forbidden sets are empty.
        """
        return len(self.required) or len(self.forbidden)

    def __or__(self, other):
        """The operator shortcut for :meth:`union`."""
        return self.union(other)

    def __and__(self, other):
        """The operator shortcut for :meth:`intersection`."""
        return self.intersection(other)

    def __sub__(self, other):
        """The operator shortcut for :meth:`difference`."""
        return self.difference(other)

    def __xor__(self, other):
        """The operator shortcut for :meth:`symmetric_difference`."""
        return self.symmetric_difference(other)

    def __repr__(self):
        return "<%s required=%s, forbidden=%s>" % (
            self.__class__.__name__,
            self.required,
            self.forbidden
        )

class Refusal(Permission):
    """The opposite of a :class:`Permission`. This is a convenience class that
    can be operated on with permissions instead of directly modifying the
    forbidden attribute. This is the recommended approach.

    :param *forbidden: Initializes the permission with forbidden entities.
    """

    def __init__(self, *forbidden):
        self.required = set()
        self.forbidden = set(forbidden)
