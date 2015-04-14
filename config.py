# -*- coding: utf-8 -*-

import os

current_dir = os.path.dirname(os.path.abspath(__file__))

debug = True
db_uri = 'sqlite:///db.sqlite'
dirs = dict(
    template = os.path.join(current_dir, 'templates'),
    static = os.path.join(current_dir, 'static'),
)
secret_key = 'kwzrhouse random string'
twitter = dict(
    consumer_key = 'xxx',
    consumer_secret = 'xxx',
)
