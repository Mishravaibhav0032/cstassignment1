import json
import logging
from datetime import datetime
from os import environ as env
from urllib.parse import quote_plus, urlencode
from flask import Flask, redirect, render_template, session, url_for, request
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
    print("DEBUG - AUTH0_DOMAIN =", env.get("AUTH0_DOMAIN"))

# Set up logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Auth0 setup
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f"https://{env.get('AUTH0_DOMAIN')}/.well-known/openid-configuration"
)

@app.route("/")
def home():
    user = session.get('user')
    return render_template("home.html", user=user, pretty=json.dumps(user, indent=4))


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token["userinfo"]
    user = session["user"]
    app.logger.info(f"Login: user_id={user['sub']}, email={user['email']}, timestamp={datetime.utcnow()}")
    return redirect("/protected")

@app.route("/protected")
def protected():
    user = session.get("user")
    if not user:
        app.logger.warning(f"Unauthorized access attempt to /protected at {datetime.utcnow()}")
        return redirect("/login")

    app.logger.info(f"Access /protected: user_id={user['sub']}, email={user['email']}, timestamp={datetime.utcnow()}")
    return f"Welcome to the protected page, {user['name']}!"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"https://{env.get('AUTH0_DOMAIN')}/v2/logout?" + urlencode({
            "returnTo": url_for("home", _external=True),
            "client_id": env.get("AUTH0_CLIENT_ID")
        }, quote_via=quote_plus)
    )

if __name__ == "__main__":
    app.run(port=3000, debug=True)
