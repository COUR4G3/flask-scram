# flask-scram

Implements RFC 7804 Salted Challenge Response (SCRAM) HTTP Authentication Mechanism for the
[Flask](https://flask.palletsprojects.com/) web framework.

See [requests-scram](https://github.com/COUR4G3/requests-scram) for a client-side implementation.


## Getting Started

Initialize the extension with the application or with ``init_app`` in an application factory, and then decorate your
route with the ``login_required`` method:


```python
from flask import Flask
from flask_scram import Scram


USERNAME = 'user'
PASSWORD = 'pass'

app = Flask(__name__)

db = {}

def auth_fn(username):
    return db[username]

scram = ScramAuth(app, auth_fn=auth_fn)

# or, later in your application factory: scram.init_app(app)

# store your authentication key in your "database"
db[USERNAME] = scram.make_auth_info(PASSWORD)


@app.route("/")
@scram.login_required
def index():
    return "OK"

```

You may specify the following configuration variables:

- ``SCRAM_MECHANISM`` - supported SCRAM Authentication mechanism e.g. ``SCRAM-SHA-256``
- ``SCRAM_REALM`` - the realm parameter to use e.g. defaults to ``request.host``


You may also use the ``authenticate`` method in your code or before request handler.

See [scramp](https://github.com/tlocke/scramp) for examples of the ``make_auth_info`` and
``make_stored_server_keys`` functions which the same methods implement.


## Todo

- Implement [One Round-Trip Reauthentication](https://datatracker.ietf.org/doc/html/rfc7804#section-5.1)


## License

Licensed under the MIT License.
