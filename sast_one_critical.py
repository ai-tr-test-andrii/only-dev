import os
from flask import Flask, request, Response

app = Flask(__name__)


@app.after_request
def set_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    result = os.popen("nslookup " + domain).read()
    return Response(result, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
