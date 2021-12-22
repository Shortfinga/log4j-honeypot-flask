#!/usr/bin/env python3

"""the app object for wsgi servers"""

from .app import app_factory

app = application = app_factory()
