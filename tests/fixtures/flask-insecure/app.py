import os

from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = "dev"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["WTF_CSRF_ENABLED"] = False


@app.route("/run")
def run():
    os.system(f"ping {request.args['host']}")
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
