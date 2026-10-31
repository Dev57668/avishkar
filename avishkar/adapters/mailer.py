"""Transactional email through the Resend HTTPS API (verification and password-reset links only).

Environment: RESEND_API_KEY, AVISHKAR_EMAIL_FROM (a sender Resend has verified), AVISHKAR_PUBLIC_URL (origin used to build
links, e.g. https://your-site.vercel.app). Without all three the mailer is disabled and sign-up is not offered.
The message body is built from fixed templates plus a one-time link; links and API keys are never logged.
"""
from __future__ import annotations

import os

import httpx

API = "https://api.resend.com/emails"


class MailError(Exception):
    pass


class Mailer:
    def __init__(self, api_key: str, sender: str, public_url: str, transport: httpx.BaseTransport | None = None):
        self.api_key, self.sender, self.public_url = api_key, sender, public_url.rstrip("/")
        self._http = httpx.Client(transport=transport, timeout=15)

    @classmethod
    def from_env(cls) -> "Mailer | None":
        key, sender, url = (os.environ.get(k, "") for k in ("RESEND_API_KEY", "AVISHKAR_EMAIL_FROM", "AVISHKAR_PUBLIC_URL"))
        if not (key and sender and url.startswith(("https://", "http://localhost", "http://127.0.0.1"))):
            return None
        return cls(key, sender, url)

    def link(self, route: str, token: str) -> str:
        return f"{self.public_url}/#/{route}?token={token}"  # fragment: never sent to a server or logged by a proxy

    def send(self, to: str, subject: str, text: str) -> None:
        try:
            r = self._http.post(API, headers={"Authorization": f"Bearer {self.api_key}"},
                                json={"from": self.sender, "to": [to], "subject": subject, "text": text})
        except httpx.HTTPError:
            raise MailError("email provider unreachable") from None
        if r.status_code >= 300:
            raise MailError(f"email provider returned {r.status_code}")

    def send_verification(self, to: str, token: str) -> None:
        self.send(to, "Confirm your Second Read account",
                  f"Confirm your email to finish creating your Second Read account (valid 24 hours):\n\n{self.link('verify', token)}\n\n"
                  "If you did not sign up, ignore this email.")

    def send_reset(self, to: str, token: str) -> None:
        self.send(to, "Reset your Second Read password",
                  f"Use this link to choose a new password (valid 1 hour):\n\n{self.link('reset', token)}\n\n"
                  "If you did not ask for this, ignore this email; your password is unchanged.")
