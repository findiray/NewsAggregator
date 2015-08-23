from flask import Flask, render_template, request, redirect  # etc.
from flask.ext.mongoengine import MongoEngine, MongoEngineSessionInterface
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt

app = Flask("NewsAggregator")

app.config['MONGODB_SETTINGS'] = {'DB':"Users"}
app.config['SECRET_KEY'] = "keepitsecret"
#app.debug = 

db = MongoEngine(app)
app.sessin_interface = MongoEngineSessionInterface(db)

flask_bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/login'
app.debug = True