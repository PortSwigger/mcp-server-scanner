from __future__ import annotations

import hmac
import html
import secrets
import threading

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

FIXTURE_USERNAME = "test-user"
FIXTURE_PASSWORD = "test-user-password"
SESSION_COOKIE = "mcp_test_session"


class SignedInSessions:
    def __init__(self) -> None:
        self._users_by_session: dict[str, str] = {}
        self._lock = threading.Lock()

    def sign_in(self, username: str, password: str) -> str | None:
        if not (hmac.compare_digest(username, FIXTURE_USERNAME) and hmac.compare_digest(password, FIXTURE_PASSWORD)):
            return None
        session = secrets.token_urlsafe(24)
        with self._lock:
            self._users_by_session[session] = username
        return session

    def user(self, request: Request) -> str | None:
        with self._lock:
            return self._users_by_session.get(request.cookies.get(SESSION_COOKIE, ""))


class LoginPage:
    @staticmethod
    def render(next_path: str, status_code: int = 200) -> Response:
        return HTMLResponse(
            "<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1>"
            '<form method="post" action="/login">'
            f'<input type="hidden" name="next" value="{html.escape(next_path, quote=True)}">'
            '<input name="username"><input name="password" type="password">'
            "<button>Sign in</button></form></body></html>",
            status_code=status_code,
        )

    @staticmethod
    def returning_to(request: Request, status_code: int = 200) -> Response:
        query = f"?{request.url.query}" if request.url.query else ""
        return LoginPage.render(request.url.path + query, status_code)


class LoginEndpoint:
    def __init__(self, sessions: SignedInSessions) -> None:
        self._sessions = sessions

    async def show(self, request: Request) -> Response:
        return LoginPage.render(request.query_params.get("next", ""))

    async def sign_in(self, request: Request) -> Response:
        form = {key: str(value) for key, value in (await request.form()).items()}
        session = self._sessions.sign_in(form.get("username", ""), form.get("password", ""))
        if session is None:
            return LoginPage.render(form.get("next", ""), status_code=401)
        next_path = form.get("next", "")
        response: Response = (RedirectResponse(next_path, status_code=303) if _is_local_path(next_path)
                              else HTMLResponse("<p>Signed in</p>"))
        response.set_cookie(SESSION_COOKIE, session, httponly=True, samesite="lax", path="/")
        return response


def _is_local_path(path: str) -> bool:
    return path.startswith("/") and not path.startswith("//") and "\\" not in path
