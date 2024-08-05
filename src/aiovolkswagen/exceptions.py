"""Asynchronous Python client for Volkswagen."""


class VolkswagenError(Exception):
    """Generic exception."""


class VolkswagenConnectionError(VolkswagenError):
    """Volkswagen connection exception."""


class VolkswagenAuthenticationError(VolkswagenError):
    """Volkswagen authentication exception."""


class VolkswagenValidationError(VolkswagenError):
    """Volkswagen validation exception."""


class VolkswagenNotFoundError(VolkswagenError):
    """Volkswagen not found exception."""


class VolkswagenBadRequestError(VolkswagenError):
    """Volkswagen bad request exception."""
