import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/ping")
def ping():
    domain = request.args.get("domain", "")
    # Fix for CWE-77 Command Injection:
    # Pass the command as a list (argv) with shell=False so the OS never
    # interprets the user-supplied value as a shell string.  The domain is
    # passed as a discrete argument to ping, not concatenated into a shell
    # command, which eliminates the injection vector entirely.
    result = subprocess.run(
        ["ping", "-c", "1", domain],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,  # explicit — never interpret via shell
    )
    return jsonify({"output": result.stdout, "error": result.stderr, "returncode": result.returncode})


if __name__ == "__main__":
    app.run()
