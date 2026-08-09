"""Mint a Firebase App Check token as an installed app, via Play Integrity.

App Check is how a Firebase backend decides a request came from the real app on
a real device rather than from a script. The Play Integrity provider is a
three-step handshake, and the middle step is the one nothing off the device can
do:

    1. POST :generatePlayIntegrityChallenge  -> a challenge string
    2. a classic Play Integrity token, with that challenge as the nonce
    3. POST :exchangePlayIntegrityToken      -> the App Check token

Step 2 has to happen inside the app's own process, at its UID and under its
signing certificate, because that is what Play attests to. `keystork.integrity`
is exactly that, so the whole handshake runs from here over one connection.

Steps 1 and 3 are ordinary HTTPS from this machine, but Firebase's API key is
Android-restricted: the calls carry the package name and the SHA-1 of its
signing certificate, and Google checks the pair. Both are read off the device
rather than hardcoded, so what goes out is what the app itself would send.

Nothing here is Firebase-specific beyond the two URLs -- `challenge` and
`exchange` are plain HTTP, and `token` is the two of them with an integrity
session in between.

    >>> from keystork.util import appcheck
    >>> app = appcheck.FirebaseApp(
    ...     project_number="34218106589",
    ...     app_id="1:34218106589:android:eac5e03da4a14be7030534",
    ...     api_key="AIzaSy...",
    ...     package="com.example.app",
    ... )
    >>> with keystork.Device().connect() as conn:
    ...     issued = appcheck.token(conn, app)
    >>> issued.token
    'eyJhbGciOi...'
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

from ..errors import KeystorkError
from .packages import package_cert_fingerprint, resolve_uid

if TYPE_CHECKING:
    from ..connection import Connection

# Where the App Check REST API lives. The app id and the method are appended
# with a colon, which is how Google's HTTP-mapped RPC names work.
APPCHECK_BASE = "https://firebaseappcheck.googleapis.com/v1"

# How long to wait on either HTTP call. Neither does real work -- one mints a
# challenge, the other verifies a token Play already signed.
HTTP_TIMEOUT = 30.0


class AppCheckError(KeystorkError):
    """Firebase refused, or could not be reached.

    `status` is the HTTP status where there was one, and `body` is whatever the
    server said -- which for this API is a JSON error object naming the actual
    problem, and is worth far more than the status alone.
    """

    def __init__(self, message: str, status: Optional[int] = None, body: str = "") -> None:
        detail = message
        if status is not None:
            detail = f"HTTP {status}: {detail}"
        if body:
            detail = f"{detail}\n{body}"
        super().__init__(detail)
        self.status = status
        self.body = body


@dataclass(frozen=True)
class FirebaseApp:
    """Which Firebase app to act as, and the identity Google will check.

    Everything here is public: it ships inside the APK, in
    `res/values/strings.xml` and the Firebase config. The API key being
    Android-restricted is what is supposed to make that safe -- it is only
    accepted alongside the package name and signing certificate below, which is
    why those have to be the app's real ones.
    """

    # The Firebase project number, which is also the GCP project number.
    project_number: str

    # The per-app Firebase id, like `1:123456789:android:abcdef0123456789`.
    app_id: str

    # The Android-restricted Web API key, `AIzaSy...`.
    api_key: str

    # The app whose process mints the integrity token, and whose name and
    # certificate the API key is restricted to.
    package: str

    @property
    def _app_url(self) -> str:
        return f"{APPCHECK_BASE}/projects/{self.project_number}/apps/{self.app_id}"


@dataclass(frozen=True)
class AppCheckToken:
    """An App Check token and how long it is good for.

    Send it as the `X-Firebase-AppCheck` header. It is a bearer token: anything
    holding it is the app as far as the backend is concerned, for as long as it
    lasts.
    """

    token: str

    # Seconds from issue, as Firebase reported it. None if it said nothing.
    ttl_seconds: Optional[int] = None

    # When this client received it, from `time.time()`.
    issued_at: float = 0.0

    @property
    def expires_at(self) -> Optional[float]:
        """Wall-clock expiry, or None if Firebase gave no TTL."""
        if self.ttl_seconds is None:
            return None
        return self.issued_at + self.ttl_seconds

    def expired(self, *, margin: float = 60.0) -> bool:
        """Whether it is spent, treating the last `margin` seconds as spent.

        A token with no TTL is never called expired -- there is nothing to go
        on, and guessing would throw away one that still works.
        """
        expiry = self.expires_at
        if expiry is None:
            return False
        return time.time() + margin >= expiry

    def __str__(self) -> str:
        return self.token


def _post(url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    """One JSON POST, with the server's error body kept rather than dropped."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise AppCheckError(
            f"{url} refused the request",
            status=exc.code,
            body=exc.read().decode(errors="replace").strip(),
        ) from exc
    except urllib.error.URLError as exc:
        raise AppCheckError(f"could not reach {url}: {exc.reason}") from exc

    try:
        return json.loads(raw)
    except ValueError as exc:
        raise AppCheckError(f"{url} did not answer with JSON: {exc}") from exc


def _ttl_seconds(ttl: Optional[str]) -> Optional[int]:
    """Google's duration strings are seconds with an `s` on the end."""
    if not ttl:
        return None
    try:
        return int(float(ttl.rstrip("s")))
    except ValueError:
        return None


def _headers(app: FirebaseApp, fingerprint: str) -> Dict[str, str]:
    """What an Android-restricted API key is checked against."""
    return {"X-Android-Package": app.package, "X-Android-Cert": fingerprint}


def challenge(app: FirebaseApp, fingerprint: str) -> str:
    """Ask Firebase for a challenge to bind the integrity token to.

    The challenge is the nonce, used exactly as given. It is short-lived, so
    fetch it immediately before minting the token rather than holding one.

    `fingerprint` is the app's signing certificate as uppercase hex SHA-1 --
    `keystork.util.packages.package_cert_fingerprint` reads it off the device.
    """
    response = _post(
        f"{app._app_url}:generatePlayIntegrityChallenge?key={app.api_key}",
        {},
        _headers(app, fingerprint),
    )
    issued = response.get("challenge")
    if not issued:
        raise AppCheckError(f"no challenge in the response: {response!r}")
    return issued


def exchange(app: FirebaseApp, fingerprint: str, integrity_token: str) -> AppCheckToken:
    """Trade a classic Play Integrity token for an App Check token.

    Firebase verifies the token with Play and checks that the nonce inside it
    is the challenge it issued, that the package is `app.package`, and that the
    signing certificate matches -- so all of this only works with a token
    minted inside the real app.
    """
    response = _post(
        f"{app._app_url}:exchangePlayIntegrityToken?key={app.api_key}",
        {"playIntegrityToken": integrity_token},
        _headers(app, fingerprint),
    )
    issued = response.get("token")
    if not issued:
        raise AppCheckError(f"no token in the exchange response: {response!r}")
    return AppCheckToken(
        token=issued,
        ttl_seconds=_ttl_seconds(response.get("ttl")),
        issued_at=time.time(),
    )


def token(
    conn: "Connection",
    app: FirebaseApp,
    *,
    uid: Optional[int] = None,
    fingerprint: Optional[str] = None,
    cloud_project_number: Optional[int] = None,
    timeout_ms: Optional[int] = None,
) -> AppCheckToken:
    """The whole handshake, over one connection. Takes seconds.

    The order is forced and worth knowing, because a connection can only be
    handed over once. Both device reads happen first, while `conn` is still
    root and can still run commands; then the challenge is fetched, because it
    is the nonce and has to exist before the token is minted; then the
    integrity session takes the connection over for good.

    So this consumes `conn`. It comes back closed, along with the app it
    launched. For several tokens, dial again -- or drive the three steps
    yourself, holding the session open and re-running `challenge`, `classic`
    and `exchange` on it.

    `uid` and `fingerprint` are read from the device when not given. Pass them
    to skip the reads, or to mint a token for a package that is not installed
    here.
    """
    if fingerprint is None:
        fingerprint = package_cert_fingerprint(conn, app.package)
    if uid is None:
        uid = resolve_uid(conn, app.package)

    # Before the session: the challenge is the nonce, and the session exists to
    # mint a token for it.
    nonce = challenge(app, fingerprint)

    with conn.open_integrity_session(app.package, uid, timeout_ms=timeout_ms) as session:
        integrity_token = session.classic(nonce, cloud_project_number=cloud_project_number)
    return exchange(app, fingerprint, integrity_token)
