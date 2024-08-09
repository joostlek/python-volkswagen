"""Asynchronous Python client for Volkswagen."""


class VolkswagenError(Exception):
    """Generic exception."""


class VolkswagenConnectionError(VolkswagenError):
    """Volkswagen connection exception."""


class VolkswagenAccountLockedError(VolkswagenConnectionError):
    """Volkswagen account locked exception."""


class VolkswagenAuthenticationError(VolkswagenError):
    """Volkswagen authentication exception."""


class VolkswagenEULAError(VolkswagenAuthenticationError):
    """Volkswagen EULA exception."""


class VolkswagenValidationError(VolkswagenError):
    """Volkswagen validation exception."""


class VolkswagenNotFoundError(VolkswagenError):
    """Volkswagen not found exception."""


class VolkswagenBadRequestError(VolkswagenError):
    """Volkswagen bad request exception."""
