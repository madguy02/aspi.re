from flask import Flask, render_template_string, redirect
from sqlalchemy import create_engine, MetaData
from flask.ext.login import UserMixin, LoginManager, \
    login_user, logout_user
from flask.ext.blogging import SQLAStorage, BloggingEngine
from flask import Flask, request, g, session, redirect, url_for
from flask import render_template_string
from flask_github import GitHub

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base



DATABASE_URI = 'sqlite:////tmp/github-flask.db'
SECRET_KEY = 'development key'
DEBUG = True

# Set these values
GITHUB_CLIENT_ID = '8456ae94b5cd97a59a05'
GITHUB_CLIENT_SECRET = '3ae484597f82aaa7c3c3d6283eb6b24d6e47be1b'

# setup flask
app = Flask(__name__)
app.config.from_object(__name__)

# setup github-flask
github = GitHub(app)

# setup sqlalchemy
engine = create_engine(app.config['DATABASE_URI'])
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(200))
    github_access_token = Column(String(200))

    def __init__(self, github_access_token):
        self.github_access_token = github_access_token


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.after_request
def after_request(response):
    db_session.remove()
    return response


@app.route('/')
def index():
    if g.user:
        t = 'Here is the app! <a href="{{ url_for("user") }}">Get user</a> ' \
            '<a href="{{ url_for("logout") }}">Logout</a>'
    else:
        t = 'Hello! <a href="{{ url_for("login") }}">Login</a>'

    return render_template_string(t)


@github.access_token_getter
def token_getter():
    user = g.user
    if user is not None:
        return user.github_access_token


@app.route('/github-callback')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or url_for('index')
    if access_token is None:
        return redirect(next_url)

    user = User.query.filter_by(github_access_token=access_token).first()
    if user is None:
        user = User(access_token)
        db_session.add(user)
    user.github_access_token = access_token
    db_session.commit()

    session['user_id'] = user.id
    return redirect(next_url)




app = Flask(__name__)
app.config["SECRET_KEY"] = "secret"  
app.config["BLOGGING_URL_PREFIX"] = "/blog"
app.config["BLOGGING_DISQUS_SITENAME"] = "test"
app.config["BLOGGING_SITEURL"] = "http://0.0.0.0:5000"

# extensions
engine = create_engine('sqlite:////tmp/blog.db')
meta = MetaData()
sql_storage = SQLAStorage(engine, metadata=meta)
blog_engine = BloggingEngine(app, sql_storage)
login_manager = LoginManager(app)
meta.create_all(bind=engine)

# user class for providing authentication
class User(UserMixin):
    def __init__(self, user_id):
            self.id = user_id

    def get_name(self):
        return "manish(madguy02)"  # typically the user's name

@login_manager.user_loader
@blog_engine.user_loader
def load_user(user_id):
    return User(user_id)

index_template = """
<!DOCTYPE html>
<html>
    <head> </head>
    <body>
        <h1><strong>Please click on the logout button to continue..... </strong></h1>
        {% if current_user.is_authenticated %}
            <a href="/logout/">Logout</a>
        {% else %}
            <a href="/login/">Login</a>
        {% endif %}
        &nbsp&nbsp<a href="/blog/">Blog</a>
        
    </body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(index_template)

@app.route("/login/")
def login():
    user = User("testuser")
    login_user(user)
    return redirect("/blog")

@app.route("/logout/")
def logout():
    logout_user()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, port=5000, use_reloader=False)
