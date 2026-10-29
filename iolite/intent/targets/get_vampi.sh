#!/usr/bin/env bash
# Reproduce the INDEPENDENT-target evidence: fetch OWASP VAmPI (third-party,
# authored by erev0s — NOT by us), install deps compatible with Python 3.13,
# patch only its run line (localhost, no debug/reloader), and launch on :5000.
# Then, from the repo root:  python3 src/authz_engine.py targets/vampi.json
set -eu
DIR="${1:-/tmp/VAmPI}"
git clone --depth 1 https://github.com/erev0s/VAmPI.git "$DIR" 2>/dev/null || true
cd "$DIR"
python3 -m pip install --break-system-packages -q \
  "connexion[swagger-ui]==2.14.2" "flask>=2.2,<2.3" "werkzeug<2.3" \
  flask-sqlalchemy jsonschema sqlalchemy PyJWT markupsafe swagger-ui-bundle
python3 - <<'PY'
s = open('app.py').read()
s = s.replace("vuln_app.run(host='0.0.0.0', port=5000, debug=True)",
              "vuln_app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)")
open('app.py', 'w').write(s)
print("patched run line for local, non-reloader boot")
PY
echo "starting VAmPI on http://127.0.0.1:5000 (vulnerable=1) ..."
vulnerable=1 exec python3 app.py
