from flask import Flask,current_app, Blueprint, render_template, abort, request, flash, redirect, url_for
from flask.ext.bootstrap import Bootstrap
from config import flask_bcrypt,login_manager
from flask.ext.login import LoginManager
from flask.ext.login import (current_user, login_required, login_user, logout_user, confirm_login, fresh_login_required)
import json
import pymongo
from bson import json_util
from bson.objectid import ObjectId
from datetime import datetime
import forms
from libs.Users import User

app = Flask(__name__)
bootstrap = Bootstrap(app)


mongoClient = pymongo.MongoClient('localhost', 27017)
db = mongoClient['NewsDB']

def toJson(data):
    return json.dumps(data, default=json_util.default)
@app.route('/',methods = ['GET','POST'])
def index():
   if request.method == 'GET':
        results = db['uknews'].find().sort('time',-1)
        return render_template('user.html',results=results)
   

    #if request.method == 'GET':
        #results = db['uknews'].find()
        #json_results = []
        #for result in results:
            #json_results.append(result)
        #return render_template('user.html',results=results)
@app.route('/news/', methods = ['GET'])
def finduknews():
    if request.method == 'GET':
        results = db['uknews'].find().sort('time',-1)
        return render_template('user.html',results=results)

@app.route('/tech/', methods = ['GET'])
def findnews():
    if request.method == 'GET':
        results = db['technews'].find().sort('time',-1)
        return render_template('user.html',results=results)

@app.route('/entertainment/',methods = ['GET'])
def findenternews():

    if request.method == 'GET':
        results = db['entertainmentnews'].find().sort('time',-1).limit(20)
        return render_template('user.html',results=results)

@app.route('/sport/',methods = ['GET'])
def findsportnews():

    if request.method == 'GET':
        results = db['sportnews'].find().sort('time',-1)
        return render_template('user.html',results=results)

@app.route('/world/',methods = ['GET'])
def findworldnews():

    if request.method == 'GET':
        results = db['worldnews'].find().sort('time',-1)
        return render_template('user.html',results=results)

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST" and "email" in request.form:
        email = request.form["email"]
        userObj = User()
        user = userObj.get_by_email_w_password(email)
        if user and flask_bcrypt.check_password_hash(user.password,request.form["password"]) and user.is_active():
            remember = request.form.get("remember", "no") == "yes"

            if login_user(user, remember=remember):
                flash("Logged in!")
                return redirect('/')
            else:
                flash("unable to log you in")

    return render_template("login.html")

@app.route('/register',methods=['GET','POST'])
def register():
    
    registerForm = forms.SignupForm(request.form)
    current_app.logger.info(request.form)

    if request.method == 'POST' and registerForm.validate() == False:
        current_app.logger.info(registerForm.errors)
        return "uhoh registration error"

    elif request.method == 'POST' and registerForm.validate():
        email = request.form['email']
        
        # generate password hash
        password_hash = flask_bcrypt.generate_password_hash(request.form['password'])

        # prepare User
        user = User(email,password_hash)
        print user

        try:
            user.save()
            if login_user(user, remember="no"):
                flash("Logged in!")
                return redirect('/sportnews')
            else:
                flash("unable to log you in")

        except:
            flash("unable to register with that email address")
            current_app.logger.error("Error on registration - possible duplicate emails")

    # prepare registration form         
    # registerForm = RegisterForm(csrf_enabled=True)
    templateData = {

        'form' : registerForm
    }

    return render_template("register.html", **templateData)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("log out")
    return redirect('/')
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

@login_manager.user_loader
def load_user(id):
    if id is None:
        redirect('/login')
    user = User()
    user.get_by_id(id)
    if user.is_active():
        return user
    else:
        return None
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

@login_manager.user_loader
def load_user(id):
    if id is None:
        redirect('/login')
    user = User()
    user.get_by_id(id)
    if user.is_active():
        return user
    else:
        return None




if __name__ == '__main__':
         app.run(debug=True)