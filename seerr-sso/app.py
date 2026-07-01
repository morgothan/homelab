import os
import json
import requests
from flask import Flask, request, make_response

app = Flask(__name__)
SEERR_URL = os.environ["SEERR_URL"]
USERS = json.loads(os.environ["SEERR_SSO_USERS"])  # {"email": "password"}


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def check(path):
    if "connect.sid" in request.cookies:
        return "", 200

    email = request.headers.get("Remote-Email", "")
    password = USERS.get(email)
    if not password:
        return "Unauthorized", 401

    try:
        resp = requests.post(
            f"{SEERR_URL}/api/v1/auth/local",
            json={"email": email, "password": password},
            timeout=5,
        )
    except requests.RequestException:
        return "Seerr unreachable", 503

    if resp.status_code != 200:
        return "Login failed", 401

    proto = request.headers.get("X-Forwarded-Proto", "https")
    host = request.headers.get("X-Forwarded-Host", "")
    uri = request.headers.get("X-Forwarded-Uri", "/")

    r = make_response("", 302)
    r.headers["Location"] = f"{proto}://{host}{uri}"
    cookie = resp.headers.get("Set-Cookie")
    if cookie:
        r.headers["Set-Cookie"] = cookie
    return r


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5056)
