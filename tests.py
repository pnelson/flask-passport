from flask import Flask, g, session
from flask.ext.passport import Passport, Permission, Refusal
from werkzeug.exceptions import Forbidden

def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)
    return app

class User(object):

    total = 0

    def __init__(self, name):
        User.total += 1
        self.id = User.total
        self.name = name

class TestInitialization(object):

    TESTING = True

    def test_app_immediately_bound(self):
        app = create_app(self)
        passport = Passport(app)

    def test_app_delayed_bound(self):
        app = create_app(self)
        passport = Passport()
        passport.init_app(app)

class TestPassport(object):

    TESTING = True
    SECRET_KEY = "testing"
    PASSPORT_LOGIN_ENDPOINT = "login"

    def setup(self):
        app = create_app(self)
        passport = Passport(app)

        self.db = [User("A"), User("B")]
        self.client = app.test_client()

        @passport.loader
        def loader(user_id):
            try:
                return self.db[int(user_id) - 1]
            except KeyError:
                return None

        @passport.on_authenticate_401
        def authentication():
            return "Authentication Required", 401

        @passport.on_reauthenticate_401
        def reauthentication():
            return "Reauthentication Required", 401

        @app.route("/")
        def index():
            return "index"

        @app.route("/login")
        def login():
            passport.login(1)
            return "login"

        @app.route("/login/persist")
        def persist():
            passport.login(1, persist=True)
            return "persist"

        @app.route("/logout")
        def logout():
            passport.logout()
            return "logout"

        @app.route("/add")
        @passport.authenticate
        def add():
            return "add"

        @app.route("/edit/<int:id>")
        @passport.authenticate
        def edit(item_id):
            return "edit"

        @app.route("/settings")
        @passport.reauthenticate
        def settings():
            return "settings"

        @app.route("/redirect")
        def redirect():
            return passport.redirect_to_login()

        self.app = app
        self.passport = passport

    def test_loader_logged_in(self):
        with self.app.test_request_context("/"):
            self.passport.login(1)
            self.app.preprocess_request()
            assert g.user is not None

    def test_loader_not_logged_in(self):
        with self.app.test_request_context("/"):
            self.app.preprocess_request()
            assert g.user is None

    def test_login_persist(self):
        rv = self.client.get("/login/persist")
        assert rv.data == "persist"
        self.client.cookie_jar.clear_session_cookies()
        rv = self.client.get("/add")
        assert rv.data == "add"

    def test_login_not_persist(self):
        rv = self.client.get("/login")
        assert rv.data == "login"
        rv = self.client.get("/add")
        assert rv.data == "add"

    def test_logout(self):
        rv = self.client.get("/login")
        assert rv.data == "login"
        rv = self.client.get("/add")
        assert rv.data == "add"
        rv = self.client.get("logout")
        assert rv.data == "logout"
        rv = self.client.get("/add")
        assert rv.status_code == 401

    def test_redirect_to_login(self):
        with self.app.test_request_context("/redirect"):
            rv = self.passport.redirect_to_login()
            assert rv.headers['location'] == "/login?next=%2Fredirect"

    def test_user_agent_modified(self):
        rv = self.client.get("/login")
        assert rv.data == "login"
        rv = self.client.get("/add", headers=[('User-Agent', "modified")])
        assert rv.status_code == 401

    def test_on_exception_missing(self):
        self.passport._on_authenticate_401 = None
        rv = self.client.get("/add", follow_redirects=True)
        assert rv.data == "login"

    def test_on_authenticate_401(self):
        rv = self.client.get("/add", follow_redirects=True)
        assert rv.status_code == 401
        assert rv.data == "Authentication Required"

    def test_on_reauthenticate_401(self):
        rv = self.client.get("/login/persist")
        assert rv.data == "persist"
        self.client.cookie_jar.clear_session_cookies()
        rv = self.client.get("/settings")
        assert rv.status_code == 401
        assert rv.data == "Reauthentication Required"

class TestPermission(object):

    def test_init(self):
        p = Permission()
        assert p.required == set()
        assert p.forbidden == set()

    def test_init_args(self):
        p = Permission(1, 2, 3)
        assert p.required == set([1, 2, 3])
        assert p.forbidden == set()

    def test_init_refusal(self):
        p = Refusal()
        assert p.required == set()
        assert p.forbidden == set()

    def test_init_refusal_args(self):
        p = Refusal(1, 2, 3)
        assert p.required == set()
        assert p.forbidden == set([1, 2, 3])

    def test_authorize_or_403_required(self):
        needs = Permission(1, 2)
        provides = [1, 2]
        try:
            needs.authorize_or_403(provides)
        except Forbidden:
            assert False
        else:
            assert True

    def test_authorize_or_403_required_missing(self):
        needs = Permission(1, 2, 3)
        provides = [1, 2]
        try:
            needs.authorize_or_403(provides)
        except Forbidden:
            assert True
        else:
            assert False

    def test_authorize_or_403_forbidden(self):
        needs = Permission(1, 2) | Refusal(3)
        provides = [1, 2, 3]
        try:
            needs.authorize_or_403(provides)
        except Forbidden:
            assert True
        else:
            assert False

    def test_repr(self):
        p = Permission(1)
        assert repr(p) == "<Permission required=set([1]), forbidden=set([])>"

    def test_repr_refusal(self):
        p = Refusal(1)
        assert repr(p) == "<Refusal required=set([]), forbidden=set([1])>"

class TestPermissionOperations(object):

    def setup(self):
        self.p1 = Permission(1, 2)
        self.p2 = Permission(2, 3) | Refusal(4)

    def test_union(self):
        assert self.p1.union(self.p2) == Permission(1, 2, 3) | Refusal(4)

    def test_union_operator(self):
        assert self.p1 | self.p2 == Permission(1, 2, 3) | Refusal(4)

    def test_intersection(self):
        assert self.p1.intersection(self.p2) == Permission(2)

    def test_intersection_operator(self):
        assert self.p1 & self.p2 == Permission(2)

    def test_difference(self):
        assert self.p1.difference(self.p2) == Permission(1)

    def test_difference_operator(self):
        assert self.p1 - self.p2 == Permission(1)

    def test_symmetric_difference(self):
        assert self.p1.symmetric_difference(self.p2) == \
            Permission(1, 3) | Refusal(4)

    def test_symmetric_difference_operator(self):
        assert self.p1 ^ self.p2 == Permission(1, 3) | Refusal(4)

class TestPermissionComparisons(object):

    def setup(self):
        self.p1 = Permission(1, 2) | Refusal(4)
        self.p2 = Permission(1, 2) | Refusal(4)
        self.p3 = Permission(1, 2, 3) | Refusal(4, 5)

    def test_equals(self):
        assert self.p1 == self.p2

    def test_not_equals(self):
        assert self.p1 != self.p3

    def test_isdisjoint(self):
        p = Permission(3, 4) | Refusal(5)
        assert self.p1.isdisjoint(p)

    def test_issubset(self):
        assert self.p1.issubset(self.p2)
        assert self.p1.issubset(self.p3)

    def test_issubset_operator(self):
        assert self.p1 <= self.p2
        assert self.p1 <= self.p3

    def test_issubset_strict_operator(self):
        assert not self.p1 < self.p2
        assert self.p1 < self.p3

    def test_issuperset(self):
        assert self.p1.issuperset(self.p2)
        assert self.p3.issuperset(self.p1)

    def test_issuperset_operator(self):
        assert self.p1 >= self.p2
        assert self.p3 >= self.p1

    def test_issuperset_strict_operator(self):
        assert not self.p1 > self.p2
        assert self.p3 > self.p1

    def test_nonzero_true(self):
        assert self.p1

    def test_nonzero_false(self):
        assert not Permission()
