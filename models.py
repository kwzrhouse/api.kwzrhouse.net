# -*- coding: utf-8 -*-

import inspect

db = inspect.getmodule(inspect.stack()[1][0]).db

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)
    twitter_id = db.Column(db.String(255), unique=True)
    authority = db.Column(db.String(255))

    def as_dict(self):
       return { c.name: getattr(self, c.name) for c in self.__table__.columns }

class Client(db.Model):
    __tablename__ = 'client'

    name = db.Column(db.String(255))

    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(50))

    user_id = db.Column(db.ForeignKey('user.id'))

    raw_redirect_uris = db.Column(db.Text)
    raw_default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self.raw_redirect_uris:
            return self.raw_redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self.raw_default_scopes:
            return self.raw_default_scopes.split()
        return []

    def as_dict(self):
       return { c.name: getattr(self, c.name) for c in self.__table__.columns }

class Grant(db.Model):
    __tablename__ = 'grant'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    client_id = db.Column(db.String(40), db.ForeignKey('client.client_id'), nullable=False)
    client = db.relationship('Client')
    code = db.Column(db.String(255), index=True, nullable=False)
    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    raw_scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.raw_scopes:
            return self.raw_scopes.split()
        return []

class Token(db.Model):
    __tablename__ = 'token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    client_id = db.Column(db.String(40), db.ForeignKey('client.client_id'), nullable=False)
    client = db.relationship('Client')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    raw_scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self.raw_scopes:
            return self.raw_scopes.split()
        return []
