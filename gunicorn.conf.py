#!/usr/bin/env python3

"""Config stuff for gunicorn"""

import gunicorn


bind = "0.0.0.0:8080"
wsgi_app = "app.wsgi:app"
gunicorn.SERVER = "Apache"
accesslog = "-"
