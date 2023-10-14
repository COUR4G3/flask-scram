import base64
import secrets

from functools import wraps

from flask import (
    abort,
    after_this_request,
    current_app,
    has_app_context,
    make_response,
    request,
    session,
)
from scramp import ScramException, ScramMechanism

DEFAULT_SCRAM_MECHANISM = "SCRAM-SHA-256"


class Scram:
    """Implements RFC 7804 SCRAM HTTP Authentication Mechanism."""

    def __init__(self, app=None, **options):
        self.app = app
        self.options = options
        if app:
            self.init_app(app)

    def init_app(self, app, **options):
        options = {**self.options, **options}

        app.config.setdefault("SCRAM_MECHANISM", DEFAULT_SCRAM_MECHANISM)

        realm = options.get("realm")
        if realm:
            app.config.setdefault("SCRAM_REALM", realm)

    def _get_app(self):
        if not has_app_context() and self.app:
            return self.app
        return current_app

    def _get_options(self):
        app = self._get_app()
        return app.config.get_namespace("SCRAM_")

    def _get_user_key(self, user):
        options = self._get_options()
        if "auth_fn" not in options:
            raise RuntimeError("`auth_fn` not configured for flask-scram")
        return options["auth_fn"](user)

    def _unauthorized(self):
        response = make_response("", 401)

        options = self._get_options()

        mechanism = options["mechanism"]
        realm = options.get("realm", request.host)

        sid = session.get("flask_scramp.sid")
        s_nonce = session.get("flask_scramp.s_nonce")

        auth_header = f'{mechanism} realm="{realm}"'
        if sid and s_nonce:
            auth_header = f", sid={sid}, s={s_nonce}"

        response.headers.add("WWW-Authenticate", auth_header)

        abort(response)

    def authenticate(self):
        """Authenticate the current request."""
        if not request.authorization:
            self._unauthorized()

        options = self._get_options()

        type = request.authorization.type.upper()
        if not type or type != options["mechanism"]:
            self._unauthorized()

        sid = request.authorization.parameters.get("sid")
        if sid and sid != session.pop("flask_scramp.sid"):
            self._unauthorized()

        s_nonce = session.pop("flask_scramp.s_nonce", None)
        if not s_nonce:
            session["flask_scramp.s_nonce"] = s_nonce = secrets.token_hex(16)

        mechanism = ScramMechanism(type)
        server = mechanism.make_server(self._get_user_key, s_nonce=s_nonce)

        data = request.authorization.parameters.get("data")
        if not data:
            self._unauthorized()

        decoded_data = base64.b64decode(data).decode("utf-8")

        try:
            if sid:
                # can't think of a better way than storing cfirst
                server.set_client_first(session.pop("flask_scramp.cfirst", ""))

                server.get_server_first()
                server.set_client_final(decoded_data)
                returned_data = server.get_server_final()
                encoded_data = base64.b64encode(returned_data.encode("utf-8")).decode(
                    "utf-8",
                )

                @after_this_request
                def set_authentication_info_header(response):
                    auth_header = f"sid={sid}, data={encoded_data}"
                    response.headers["Authentication-Info"] = auth_header
                    return response

                return server.user
            else:
                server.set_client_first(decoded_data)
                session["flask_scramp.cfirst"] = decoded_data
                session["flask_scramp.s_nonce"] = s_nonce
                session["flask_scramp.sid"] = sid = secrets.token_hex(16)
                returned_data = server.get_server_first()
        except ScramException:
            if server.stage and server.stage >= 3:
                returned_data = server.get_server_final()
            else:
                returned_data = server.get_server_first()

        encoded_data = base64.b64encode(returned_data.encode("utf-8")).decode("utf-8")

        response = make_response("", 401)
        response.headers["WWW-Authenticate"] = f"{type} sid={sid}, data={encoded_data}"

        abort(response)

    def login_required(self, f=None):
        """Wrap a route to require authentication."""

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                self.authenticate()

                return f(*args, **kwargs)

            return wrapper

        return f and decorator(f) or decorator

    def make_auth_info(self, *args, **kwargs):
        """Make authentication parameters from given password and parameters."""
        options = self._get_options()
        mechname = options["mechanism"]

        mechanism = ScramMechanism(mechname)
        return mechanism.make_auth_info(*args, **kwargs)

    def make_stored_server_keys(self, *args, **kwargs):
        """Make authentication parameters from given digest and parameters."""
        options = self._get_options()
        mechname = options["mechanism"]

        mechanism = ScramMechanism(mechname)
        return mechanism.make_stored_server_keys(*args, **kwargs)
