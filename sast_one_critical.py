import subprocess
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# Allowlist: only valid domain/hostname characters are permitted.
# A domain label may contain letters, digits, and hyphens; labels are separated by dots.
_VALID_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')


@app.route('/ping')
def ping():
    # Source: user-supplied domain parameter (CWE-77 taint source)
    domain = request.args.get('domain', '')

    # Validate against an allowlist before using in a subprocess call.
    # The domain must match a strict hostname pattern (letters, digits, hyphens, dots only).
    # This is an allowlist check — not a sanitizer applied to a shell string.
    if not domain or not _VALID_DOMAIN_RE.match(domain):
        return jsonify({'error': 'Invalid domain'}), 400

    # Safe: pass arguments as a list with shell=False so no shell interpretation occurs.
    # The domain has already been validated to contain only safe hostname characters,
    # but using an argv list (shell=False) is the primary defence against command injection.
    result = subprocess.run(
        ['ping', '-c', '1', domain],
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    return jsonify({
        'domain': domain,
        'stdout': result.stdout,
        'returncode': result.returncode,
    })


if __name__ == '__main__':
    app.run()
