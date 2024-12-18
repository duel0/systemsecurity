from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import secrets
import sys
import json
import data.decrypt as dc

try:
    settings = json.loads(dc.decrypt_file('./settings.enc', sys.argv[1], sys.argv[2]))
except:
    print("Error: Invalid password or username")
    exit(1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = settings["SQLALCHEMY_DATABASE_URI"]

secret = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+") for _ in range(512))

app.config['WTF_CSRF_SECRET_KEY'] = secret
app.config['LDAP_PROVIDER_URL'] = settings["LDAP_PROVIDER_URL"]
app.config['LDAP_PROVIDER_PORT'] = settings["LDAP_PROVIDER_PORT"]
app.config['LDAP_PROTOCOL_VERSION'] = 3

db = SQLAlchemy(app)

# Generate a random secret key for the session
secret_key = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+") for _ in range(512))

app.secret_key = secret_key
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
ctx = app.test_request_context()
ctx.push()

from data.auth.views import auth

app.register_blueprint(auth)
db.create_all()