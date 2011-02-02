#!/usr/bin/env python
# -*- coding: utf-8 -*-
from distutils.core import setup
 
setup(
    name='django-iframe-facebook',
    version='0.1',
    description='this app extends the basic Facebook Python SDK with full support of authentification und permission granding in a facebook iframe app',
    author='cfrohmader',
    url='http://github.com/facebook/python-sdk',
    package_dir={'': 'src'},
    py_modules=[
        'iframefacebook',
    ],
)
