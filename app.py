# -*- coding: utf-8 -*-

import config
from functools import wraps
from datetime import datetime, timedelta
from flask import (
    Flask, 
    session, request, render_template, 
    redirect, jsonify, g, url_for
)
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.client import OAuth
from flask_oauthlib.provider import OAuth2Provider
from werkzeug.security import gen_salt

app = Flask(__name__)
app.debug = config.debug
app.secret_key = config.secret_key
app.config.update({
    'SQLALCHEMY_DATABASE_URI': config.db_uri,
    'TEMPLATE_FOLDER': config.dirs['template'],
    'STATIC_FOLDER': config.dirs['static'],
})

db = SQLAlchemy(app)
provider = OAuth2Provider(app)
oauth = OAuth(app)

twitter = oauth.remote_app(
    'twitter',
    consumer_key=config.twitter['consumer_key'],
    consumer_secret=config.twitter['consumer_secret'],
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
)

from models import *

def current_user():
    if 'user' in session:
        return session['user']
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@twitter.tokengetter
def get_twitter_token():
    if 'twitter_oauth' in session:
        res = session['twitter_oauth']
        return res['oauth_token'], res['oauth_token_secret']

@app.before_request
def before_request():
    g.user = None
    if 'twitter_oauth' in session:
        g.user = session['twitter_oauth']

@provider.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()

@provider.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@provider.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    user_id = Client.query.filter_by(client_id=client_id).first().user_id
    expires = datetime.utcnow() + timedelta(seconds=60)

    grant = Grant(
        user_id=user_id,
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        expires=expires,
        raw_scopes=' '.join(request.scopes),
    )

    db.session.add(grant)
    db.session.commit()
    return grant

@provider.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()

@provider.tokensetter
def save_token(token, request, *args, **kwargs):
    tokens = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id,
    )

    for t in tokens:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    new_token = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        raw_scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(new_token)
    db.session.commit()
    return new_token

@app.route('/oauth/token')
@provider.token_handler
def access_token():
    return None

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@provider.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@app.route('/')
def index():
    return render_template('index.html', user=current_user())

@app.route('/login/twitter')
def login_twitter():
    callback_url = url_for('oauthorized', next=request.args.get('next'))
    return twitter.authorize(callback=callback_url or request.referrer or None)

@app.route('/oauthorized')
def oauthorized():
    res = twitter.authorized_response()
    if res is None:
        return redirect(url_for('index'))

    session['twitter_oauth'] = res
    user = User.query.filter_by(twitter_id=res['user_id']).first()
    if user is None:
        return redirect(url_for('sign_up'))

    session['user'] = user.as_dict()
    return redirect(url_for('index'))

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if not 'twitter_oauth' in session:
        redirect(url_for('index'))

    if request.method == 'POST':
        res = session['twitter_oauth']

        user = User.query.filter_by(twitter_id=res['user_id']).first()
        if user is not None:
            return redirect(url_for('index'))

        name = request.form['name']
        user = User.query.filter_by(name=name).first()
        if user is not None:
            return redirect(url_for('sign_up'))

        user = User(
            name = name,
            twitter_id = res['user_id'],
        )

        db.session.add(user)
        db.session.commit()

        session['user'] = user.as_dict()
        return redirect(url_for('index'))
    return render_template('sign_up.html', user=current_user())

@app.route('/logout')
@login_required
def logout():
    session.pop('twitter_oauth', None)
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/clients', methods=['GET'])
@login_required
def clients():
    clients = Client.query.filter_by(user_id=current_user()['id']).all()
    clients = map(lambda c: c.as_dict(), clients)
    return render_template('clients.html', clients=clients)

@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    if request.method == 'POST':
        client = Client(
            name = request.form['name'],
            client_id = gen_salt(40),
            client_secret = gen_salt(50),
            user_id = current_user()['id'],
            raw_redirect_uris = request.form['redirect_uri'],
            raw_default_scopes='general',
        )

        db.session.add(client)
        db.session.commit()
    else:
        return render_template('add_client.html')

    return redirect(url_for('clients'))

@app.route('/remove_client', methods=['POST'])
@login_required
def remove_client():
    client = Client.query.filter_by(client_id=request.form['id']).first()
    if client is None:
        return ('ID Not Found', 500)

    db.session.delete(client)
    db.session.commit()

    return redirect(url_for('clients'))

@app.route('/reset_api_key', methods=['POST'])
@login_required
def reset_api_key():
    client = Client.query.filter_by(client_id=request.form['id']).first()
    if client is None:
        return ('ID Not Found', 500)

    client.client_id = gen_salt(40)
    client.client_secret = gen_salt(50)

    db.session.add(client)
    db.session.commit()

    return redirect(url_for('clients'))

@app.route('/api/me')
@provider.require_oauth()
def me():
    return jsonify(request.oauth.user.as_dict())

if __name__ == '__main__':
    db.create_all()
    app.run()
