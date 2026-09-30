"""Tanomind Connect v1 client for the local Ableton bridge."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class ConnectError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass
class ConnectSession:
    session_id: str
    session_token: str
    expires_in: int
    agent_handle: str | None = None


class TanomindConnect:
    def __init__(self, app_id: str, app_key: str, origin: str = "https://tanomind.com"):
        self.app_id = app_id
        self.app_key = app_key
        self.origin = origin.rstrip("/")

    def register_redirect(self, redirect_uri: str) -> None:
        self._request(
            "/api/connect/v1/redirects",
            method="POST",
            credential=self.app_key,
            body={"redirect_uri": redirect_uri},
        )

    def authorization_url(self, redirect_uri: str, state: str, code_challenge: str) -> str:
        from urllib.parse import urlencode

        query = urlencode(
            {
                "app_id": self.app_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read_profile send_task",
            }
        )
        return f"{self.origin}/connect/authorize?{query}"

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> ConnectSession:
        data = self._request(
            "/api/connect/v1/token",
            method="POST",
            credential=self.app_key,
            body={"code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier},
        )
        return ConnectSession(
            session_id=data["session_id"],
            session_token=data["session_token"],
            expires_in=int(data.get("expires_in") or 3600),
            agent_handle=data.get("agent_handle"),
        )

    def refresh(self, session_id: str, session_token: str) -> ConnectSession:
        data = self._request(
            "/api/connect/v1/refresh",
            method="POST",
            credential=self.app_key,
            body={"session_id": session_id, "session_token": session_token},
        )
        return ConnectSession(
            session_id=data.get("session_id") or session_id,
            session_token=data.get("session_token") or session_token,
            expires_in=int(data.get("expires_in") or 3600),
            agent_handle=data.get("agent_handle"),
        )

    def profile(self, session_token: str) -> dict[str, Any]:
        return self._request("/api/connect/v1/profile", credential=session_token)

    def app(self) -> dict[str, Any]:
        try:
            data = self._request("/api/connect/v1/app", credential=self.app_key)
        except ConnectError:
            data = self._request("/api/connect/app", credential=self.app_key)
        nested = data.get("app")
        return nested if isinstance(nested, dict) else data

    def publish_agent_join(self, redirect_uri: str, join_url: str) -> tuple[str, bool]:
        try:
            self.register_redirect(redirect_uri)
        except ConnectError as error:
            if error.status != 409:
                raise
        info = self.app()
        public_id = str(info.get("app_id") or self.app_id)
        try:
            self._request(
                f"/api/apps/{public_id}",
                method="PATCH",
                credential=self.app_key,
                body={"agent_join_url": join_url},
            )
        except ConnectError:
            return public_id, False
        return public_id, True

    def _request(
        self,
        path: str,
        method: str = "GET",
        credential: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json", "User-Agent": "ableton-connect/0.1"}
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.origin}{path}", data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode()
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                data = {}
            raise ConnectError(data.get("error") or f"Connect request failed ({error.code})", error.code, data.get("code")) from error
        except urllib.error.URLError as error:
            raise ConnectError(f"Could not reach Tanomind: {error.reason}") from error
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"result": data}
