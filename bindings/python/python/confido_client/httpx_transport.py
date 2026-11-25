"""Adapt an authenticated Confido session to a synchronous httpx client."""

import httpx

from ._native import Session


class ScopedTransport(httpx.BaseTransport):
    """Forward requests through a peer-checked session.

    The application decides which requests and credentials to send. The native
    session enforces the appraised HTTPS origin and rejects redirects.
    """

    def __init__(self, session: Session):
        if not isinstance(session, Session):
            raise TypeError("ScopedTransport requires an authenticated Session")
        self._session = session

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        status, headers, body = self._session.request(
            request.method,
            str(request.url),
            list(request.headers.multi_items()),
            request.read(),
        )
        return httpx.Response(status, headers=headers, content=body, request=request)
