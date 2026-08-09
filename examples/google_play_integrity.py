import base64
import json
import os

import requests
import keystork

PACKAGE = "gr.nikolasspyr.integritycheck"
VERDICT_URL = "https://integrity.1nikolas.dev/api/check"

# these are also the default device params if you don't specify any
device = keystork.Device(host="127.0.0.1", port=9432)

nonce = base64.urlsafe_b64encode(os.urandom(32)).decode()

with device.connect() as connection:
    with connection.open_integrity_session(package=PACKAGE) as integrity:
        print(f"{PACKAGE} is pid {integrity.pid}, uid {integrity.uid}")
        token = integrity.classic(nonce)

print("token:", token)
verdict = requests.get(VERDICT_URL, params={"token": token}, timeout=30)
verdict.raise_for_status()
decoded = verdict.json()
print(json.dumps(decoded, indent=4))
