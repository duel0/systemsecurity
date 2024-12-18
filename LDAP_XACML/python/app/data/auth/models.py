from flask_wtf import Form
from wtforms import StringField,PasswordField
from wtforms import validators
from ldap3 import Server, Connection
from data import db, app
from data import settings
import json
import sys

# Get LDAP server
def get_ldap_server():
    return Server(app.config['LDAP_PROVIDER_URL'], app.config['LDAP_PROVIDER_PORT'])


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100))
    role = db.Column(db.String(100))

    def __init__(self, username, role = 'user'):
        self.username = username
        self.role = role

    @staticmethod
    def try_login(username, password):
        with Connection(Server(app.config['LDAP_PROVIDER_URL'], app.config['LDAP_PROVIDER_PORT']), user='cn=%s,dc=ramhlocal,dc=com' % username, password='%s' % password) as conn:
            pass
        with Connection(Server (app.config['LDAP_PROVIDER_URL'], app.config['LDAP_PROVIDER_PORT']), user=settings["LDAP_ADMIN_DN"], password=settings["LDAP_ADMIN_PASSWORD"]) as conn:
            conn.search('dc=ramhlocal,dc=com', '(objectClass=person)')
            # If user is in LDAP, check if he is not admin
            for entry in conn.entries:
                if username in json.loads(entry.entry_to_json())['dn']:
                    return settings["USER_ROLE_NAME"]
            return settings["ADMIN_ROLE_NAME"]

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


class LoginForm(Form):
    username = StringField('Username',[validators.DataRequired()])
    password = PasswordField('Password',[validators.DataRequired()])