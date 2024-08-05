"""Models for Volkswagen."""
from dataclasses import dataclass

from mashumaro.mixins.orjson import DataClassORJSONMixin


@dataclass
class OpenIDConfiguration(DataClassORJSONMixin):

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    scopes_supported: list[str]
    response_types_supported: list[str]
    grant_types_supported: list[str]
    acr_values_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_supported: list[str]
    ui_locales_supported: list[str]
    revocation_endpoint: str
    code_challenge_methods_supported: list[str]
    end_session_endpoint: str

