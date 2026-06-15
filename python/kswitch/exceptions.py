"""KSwitch SDK exceptions.

Hierarchy:
    KSwitchError
    +-- AuthError           (401)
    +-- ForbiddenError      (403)
    +-- NotFoundError       (404)
    +-- ConflictError       (409)
    +-- ValidationError     (422)
    +-- RateLimitError      (429)
    +-- ServerError         (500+)
"""

from __future__ import annotations


class KSwitchError(Exception):
    """Base exception for all KSwitch SDK errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self.status_code}, message={str(self)!r})"


class AuthError(KSwitchError):
    """Authentication failed (401)."""


class ForbiddenError(KSwitchError):
    """Insufficient permissions (403)."""


class NotFoundError(KSwitchError):
    """Resource not found (404)."""


class ConflictError(KSwitchError):
    """Resource conflict (409)."""


class ValidationError(KSwitchError):
    """Request validation failed (422 or 400)."""


class RateLimitError(KSwitchError):
    """Rate limit exceeded (429)."""

    def __init__(
        self,
        message: str,
        status_code: int | None = 429,
        response_body: dict | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code, response_body)
        self.retry_after = retry_after


class ServerError(KSwitchError):
    """Server-side error (5xx)."""


# Mapping from HTTP status code to exception class
STATUS_EXCEPTION_MAP: dict[int, type[KSwitchError]] = {
    400: ValidationError,
    401: AuthError,
    403: ForbiddenError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError,
    429: RateLimitError,
}


def raise_for_status(status_code: int, body: dict) -> None:
    """Raise an appropriate KSwitchError for non-2xx status codes."""
    if 200 <= status_code < 300:
        return

    message = body.get("error") or body.get("message") or body.get("detail") or f"HTTP {status_code}"

    exc_cls = STATUS_EXCEPTION_MAP.get(status_code)
    if exc_cls is None:
        if status_code >= 500:
            exc_cls = ServerError
        else:
            exc_cls = KSwitchError

    if exc_cls is RateLimitError:
        retry_after = body.get("retry_after")
        raise RateLimitError(message, status_code, body, retry_after=retry_after)

    raise exc_cls(message, status_code, body)
