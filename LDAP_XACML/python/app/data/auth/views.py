from flask import request, render_template, flash, redirect, url_for, Blueprint, g
from flask_login import current_user, login_user, logout_user, login_required
from data import login_manager,db
from data import settings
import requests
import json

auth = Blueprint('auth', __name__)

from data.auth.models import User,LoginForm

def xacml_evaluation(role : str, action : str, resource : str):
    url = settings["XACML_SERVER_URL"]
    headers = {"Content-Type": "application/json"}
    body = { 'role': role, 'resource': resource, 'action': action }
    json_body = json.dumps(body)
    # send POST request to XACML server
    r = requests.post(url = url, headers=headers, data = json_body).text
    print("XACML response: ", r)
    # if XACML server returns 0, access is granted
    if r == '0':
        return True
    else:
        return False


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@auth.before_request
def get_current_user():
    g.user = current_user


@auth.route('/')
@auth.route('/home')
def home():
    return render_template('home.html')


@auth.route('/login', methods = ['GET','POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.')
        return redirect(url_for('auth.home'))

    form = LoginForm(request.form)
    role = None

    if request.method == 'POST' and form.validate():
        username = request.form['username']
        password = request.form['password']

        try:
            role = User.try_login(username,password)
        except:
            flash('Invalid username or password. Please try again.','danger')
            return render_template('login.html', form=form)

        # Search for user in database
        user = User.query.filter_by(username = username, role = role).first()

        if not user:
            user = User(username = username, role = role)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        # Update user role
        current_user.role = role

        flash('You have successfully logged in.', 'success')

        if current_user.username == 'dottore1':
            return redirect(url_for('auth.home'))
        elif current_user.username == 'paziente1':
            return redirect(url_for('auth.paziente1'))
        else:
            return redirect(url_for('auth.paziente2'))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home'))

@auth.route('/private')
@login_required
def private():
    role = current_user.role
    action = 'GET'
    resource = 'http://localhost:1200/private/*'
    print(current_user.username, role, action, resource)
    if xacml_evaluation(role, action, resource):
        return 'This is a private page.'
    else:
        return render_template('forbidden.html')

@auth.route('/AG')
@login_required
def AG():
    username = current_user.username.lower()
    action = 'GET'
    resource = 'http://localhost:1200/AG/*'
    print(current_user.username, username, action, resource)
    if xacml_evaluation(username, action, resource):
        return 'This is a page for AG.'
    else:
        return render_template('forbidden.html')

@auth.route('/HZ')
@login_required
def HZ():
    username = current_user.username.lower()
    action = 'GET'
    resource = 'http://localhost:1200/HZ/*'
    print(current_user.username, username, action, resource)
    if xacml_evaluation(username, action, resource):
        return 'This is a page for HZ.'
    else:
        return render_template('forbidden.html')

@auth.route('/paziente2')
@login_required
def paziente2():
    username = current_user.username.lower()
    action = 'GET'
    resource = 'http://localhost:1200/paziente2/*'
    print(current_user.username, username, action, resource)
    if xacml_evaluation(username, action, resource):
        return render_template('paziente2.html')
    else:
        return render_template('forbidden.html')
    
@auth.route('/paziente1')
@login_required
def paziente1():
    username = current_user.username.lower()
    action = 'GET'
    resource = 'http://localhost:1200/paziente1/*'
    print(current_user.username, username, action, resource)
    if xacml_evaluation(username, action, resource):
        return render_template('paziente1.html')
    else:
        return render_template('forbidden.html')