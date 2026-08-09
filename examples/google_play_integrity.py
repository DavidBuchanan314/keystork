import base64
import json
import os

import requests
import keystork

# hosted instance of https://github.com/1nikolas/play-integrity-checker-app
# (must be installed on the target device, via https://play.google.com/store/apps/details?id=gr.nikolasspyr.integritycheck )
PACKAGE = "gr.nikolasspyr.integritycheck"
VERDICT_URL = "https://integrity.1nikolas.dev/api/check"

# these are also the default device params if you don't specify any
device = keystork.Device(host="127.0.0.1", port=9432)

nonce = base64.urlsafe_b64encode(os.urandom(32)).decode()
print("nonce:")
print(nonce)

print()

print("token:")
with device.connect() as connection:
    with connection.open_integrity_session(package=PACKAGE) as integrity:
        token = integrity.classic(nonce)
        print(token)

print()

print("verdict:")
verdict = requests.get(VERDICT_URL, params={"token": token}, timeout=30)
verdict.raise_for_status()
decoded = verdict.json()
print(json.dumps(decoded, indent=4))
