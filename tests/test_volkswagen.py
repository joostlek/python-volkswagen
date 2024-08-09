"""Asynchronous Python client for Volkswagen."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, AsyncGenerator
from unittest.mock import patch

import aiohttp
from aiohttp.hdrs import METH_GET, METH_POST
from aioresponses import CallbackResult, aioresponses
import pytest
from yarl import URL

from aiovolkswagen.volkswagen import Volkswagen

from aiovolkswagen.exceptions import (
    VolkswagenError,
    VolkswagenConnectionError,
    VolkswagenAuthenticationError,
    VolkswagenAccountLockedError,
    VolkswagenEULAError,
)
from aiovolkswagen.const import X_APP_NAME, USER_AGENT
from tests import load_fixture


if TYPE_CHECKING:
    from syrupy import SnapshotAssertion


async def test_putting_in_own_session(
    responses: aioresponses,
) -> None:
    """Test putting in own session."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    async with aiohttp.ClientSession() as session:
        vw = Volkswagen(session=session)
        await vw.get_openid_configuration()
        assert vw.session is not None
        assert not vw.session.closed
        await vw.close()
        assert not vw.session.closed


async def test_creating_own_session(
    responses: aioresponses,
) -> None:
    """Test creating own session."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    vw = Volkswagen()
    await vw.get_openid_configuration()
    assert vw.session is not None
    assert not vw.session.closed
    await vw.close()
    assert vw.session.closed


async def test_unexpected_server_response(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test handling unexpected response."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=400,
        headers={"Content-Type": "plain/text"},
        body="Yes",
    )
    with pytest.raises(VolkswagenError):
        assert await volkswagen_client.get_openid_configuration()


async def test_timeout(
    responses: aioresponses,
) -> None:
    """Test request timeout."""

    # Faking a timeout by sleeping
    async def response_handler(_: str, **_kwargs: Any) -> CallbackResult:
        """Response handler for this test."""
        await asyncio.sleep(2)
        return CallbackResult(body="Goodmorning!")

    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        callback=response_handler,
    )
    async with Volkswagen(request_timeout=1) as volkswagen_client:
        with pytest.raises(VolkswagenConnectionError):
            assert await volkswagen_client.get_openid_configuration()


async def test_openid_configuration(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    snapshot: SnapshotAssertion,
) -> None:
    """Test retrieving openid configuration."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    assert await volkswagen_client.get_openid_configuration() == snapshot


@pytest.fixture
async def _mock_random_string() -> AsyncGenerator[None, None]:
    """Mock get_random_string."""
    with patch("aiovolkswagen.volkswagen.get_random_string", return_value="abcd"):
        yield


@pytest.mark.usefixtures("_mock_random_string")
async def test_login(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the login flow."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf",
        status=301,
        headers={
            "Location": "cupraconnect://identity-kit/login#state=bjPCDALBYCXvLf8th9QrsyA5dhfe3o6g4audGhZYQ9k&code=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmY2NDYyZC00ZjM2LTQ4ODAtOTIzNi1lNDBjOTFmY2JhYmEiLCJhdWQiOiIzMGUzMzczNi1jNTM3LTRjNzItYWI2MC03NGE3YjkyY2ZlODNAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoib3BlbmlkIHByb2ZpbGUgYWRkcmVzcyBwaG9uZSBlbWFpbCBiaXJ0aGRhdGUgbmF0aW9uYWxJZGVudGlmaWVyIGNhcnMgbWJiIGRlYWxlcnMgYmFkZ2UgbmF0aW9uYWxpdHkiLCJhYXQiOiJpZGVudGl0eWtpdCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImF1dGhvcml6YXRpb25fY29kZSIsImV4cCI6MTcyMzIxMDA2OCwiaWF0IjoxNzIzMjA5NzY4LCJub25jZSI6ImhHWDMzL2lwd3pNdmhuNnRqOHJvNmNVN253RklqNzZKQTZqQUkvSEJsTjgiLCJqdGkiOiI0OTJjNTYyZS1lMjc0LTRhMjAtOGZmNC0xM2JiMzBmNDFhNWUifQ.AiRHFh1UDeaWsqdtD9nW5J3ZnCtIPa6UGhQhALNLuka6ip24xFQoVTYpOhvi8y607hSxTpSlEPncjkHS_cCbFn0iGmdImLSm7R-GQn7EbmUlpRFLMjvXGXzs4dmDsxHR9DuZ3zT9wPMs8W81eYR5BO8vqFzC0V-6edgvA8l8MgjdDa6WzUCuNXbhGaYW4IPbEExzo6relu9kV-SL7L0_8XVdGDqA2R0ZTSVUsBZexr3KJJrkquFXX_b00r3XCtE8xwKqYJ4xAUXHlREol941Gczaay69ZM_kSgrhaFDonr-G0zsVZ7rRPiwQChqN3lQpLuaPg90Fx-333nHnAR5GX_QLAoFVrsmkBfBDx1yOJbpHWgJFffYbz2CSaNjQAFyuA4DtBhyDccLjMPfWUQrpF0x00Lh2eHLyrw4CyfSA4CgE89UOfmInDK2wEpQfH8yj1joaYg2dmTddhtljwRz-UWmts1D66IzjkLGco__4OkGY_DVlxfyX7yQiJICh9J_IjTXpcO--vK3IiyN5XrUSSlrNOrQvIpMMA5U4_K49KHOLQIGX6N3kVw7YanEMB6TivIgnjRitVogx2V2MtO_I5_-m2vkJ4CasILEESnACkik1w_8r53LtSrxdgtUFLeNFCjKKNq5szFs_1eHnvstodH0gn6lDPuYY20s0krQjBTw&access_token=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmY2NDYyZC00ZjM2LTQ4ODAtOTIzNi1lNDBjOTFmY2JhYmEiLCJhdWQiOiIzMGUzMzczNi1jNTM3LTRjNzItYWI2MC03NGE3YjkyY2ZlODNAYXBwc192dy1kaWxhYl9jb20iLCJzY3AiOiJvcGVuaWQgcHJvZmlsZSBhZGRyZXNzIHBob25lIGVtYWlsIGJpcnRoZGF0ZSBuYXRpb25hbElkZW50aWZpZXIgY2FycyBtYmIgZGVhbGVycyBiYWRnZSBuYXRpb25hbGl0eSIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzIzMjEzMzY4LCJpYXQiOjE3MjMyMDk3NjgsImxlZSI6WyJTRUFUIl0sImp0aSI6IjU5NTUwMWI4LTQ5MTQtNGRjNy04YmQ2LTMyNDUwMTVkN2JkNyJ9.Hjy_v9Q7AEzxMKTyg052Av1X6NVjs1ckfH-Gr3an7YZGQBuMm8x-qD_0MR9C03CGN6VD_ymMbFbeFAwetgQecpDrlJwtS8LpSw3sowNoPwDbjKIfSsX8NsnTlLYreo0qeilIzbiDOyKQYAFyFcAOI6HmGrdbAdYWuHCPKNAfv2Hu9qQYM_fcjEAjlm8-HeAE95VvRNEb9SDXrHCxIhkSoPqmo2fXJ61gdFfX8ujO9BHnGK4yCb-FevroO_6TIav2f7FP1jMtz6rdiu6osSdYZBV-6A-Q8ZtOliLVHn3EMUoFxd-l52aGei8jh102ZAbempymLGgKYLGtdY_qEeFAf_twUZQnHNXTBIMe5KPNbkMuoz-vWEPY7v2U6-15aJBWLJhZf0Ura8kctaUBE4lh3Bkgz2siOPSdFJrnulBT_nyhyCHbaPjaeo2QT5Qvsf4WFRMSJPAqfHUo2X889XstwcR5CNr3xBw7AZ-Bn7J6INNlgYn61RtF2BpJ5TYtUxZcyKhdxDo-xSOAxCtPeJF0uAVf-Wc_mD59-ZtSxxA0ImZwruO9zrAVMsJxZGexB9gbpkKZuzXE_abOvK4M2AMTNTUvtT_z95rw9jntp-OAZo1IGr_k83gx0ZuCwV9p9G9U-_prt9ToCv3JX1GlNb7Z5KYHVZf1zXw5yrz6wgmS-hk&expires_in=3600&token_type=bearer&id_token=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiN21rNEhsTHVfM3BJT21tNmZVb2JXUSIsInN1YiI6ImNiZjY0NjJkLTRmMzYtNDg4MC05MjM2LWU0MGM5MWZjYmFiYSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb3IiOiJOTCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImlkX3Rva2VuIiwidHlwZSI6ImlkZW50aXR5Iiwibm9uY2UiOiJoR1gzMy9pcHd6TXZobjZ0ajhybzZjVTdud0ZJajc2SkE2akFJL0hCbE44IiwibGVlIjpbIlNFQVQiXSwiYXVkIjpbIjMwZTMzNzM2LWM1MzctNGM3Mi1hYjYwLTc0YTdiOTJjZmU4M0BhcHBzX3Z3LWRpbGFiX2NvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS5kcDE1LnZ3Zy1jb25uZWN0LmNvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS53Y2FyZHAuaW8iLCJodHRwczovL3Byb2QuZWNlLmdhdXRoLXZ3YWMuY29tIiwiVldHTUJCMDFDTkFQUDEiLCJWV0dNQkIwMURFTElWMSJdLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwiY19oYXNoIjoiVWk4c2hVeXEzWGpRdmxoby1FdWV4dyIsInVwZGF0ZWRfYXQiOjE3MjAxNjMwMjkwMTMsImFhdCI6ImlkZW50aXR5a2l0IiwiZXhwIjoxNzIzMjEzMzY4LCJpYXQiOjE3MjMyMDk3NjgsImp0aSI6IjE5ZTA4MTEyLWE0NzktNGVmYi1hMGQzLWRmMWE1YWU1NjMwNyIsImVtYWlsIjoibS50aWpzc2VuQG1lLmNvbSJ9.n9jDJhQYtaeIp5TDPzLfpwuK6kk-f2H8tgVO-g-tgXbrtkNvyjQUJe-tEE02UEkhvFLNY8qCHskq0_MpErqStrtQFEXglr6OuWS0qihTJwMW42oaqoDx4ElyPFf9sgfZ7iF7GSEKJviByY2SmfdYWZ7YqVkzqzTv0wIxV3nkHsChUzTccLvsiVTndcSvZhK1kSKAiLIKrpHoaMoeunLP3Qs8gEHuWoW4lEdkkvhIH46-Ib5WD-391tYehpDFIGqZlBtR_waugX2hV-Jy_t_O_Q2NXaNKo2u8tHg93fIsjNGMjVXt4johQWcVeeAsrXYVIgvyo0A4hiKInPHD2z5tUJh6wsb8B8495GTb7SwKyElKJp_U1oBUKo3jbhznux-WvYY6LqKVJrlJ_FGygLIWbjf7WC_gQdEnyVm75hGGF7gXQeuwZjEy4SRSHYE8Ah8S50WAVpzWGahzs1TXN-TGaPaUmxEB8tbLleBNv-Vne4I60QFt7R6-KRWFkNSXL7nr9HN0Autht3iNY7mP8NANTiwhaqFrFmSOD3-K3Lr2OLgXxziafO2rMoC4_3MqWGypIEBpeAJ9UQG6gpj3YGdISh2FvF1cMGkC77W_S5BLs8cA5Eau9zAGFwAEEj9iQ4osYcwYIe-jwVB6GEPy7EJd7j_2P0NgT6001lZRJdgWxAQ"
        },
    )
    responses.post(
        "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode",
        status=200,
        body=load_fixture("tokens.json"),
    )
    assert snapshot == await volkswagen_client.login("test", "test")
    responses.assert_called_with(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        METH_GET,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        },
        allow_redirects=False,
    )
    responses.assert_called_with(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        METH_GET,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        },
        allow_redirects=False,
    )
    responses.assert_called_with(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        METH_POST,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": "https://identity.vwgroup.io/oidc/v1/authorize",
            "Origin": "https://identity.vwgroup.io",
        },
        data={
            "_csrf": "IBbkJahuAMzoAilHhdHEU6uuyyo9VbMw1IyxFb2NlSGyX6OVRHeBHJtcZfrFMxlw4_zwZJ_K5ksEZYodtb2HItvvphGLapKt",
            "relayState": "85b9b612b1b1012291478066ec8acb3987a6d9a1",
            "hmac": "0b85d60ce123cbc18d5a3d0bd62d1ce0fdb4d795b6814c958f719992642e8d8c",
            "email": "test",
        },
    )
    responses.assert_called_with(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        METH_POST,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
            "Origin": "https://identity.vwgroup.io",
        },
        data={
            "_csrf": "IBbkJahuAMzoAilHhdHEU6uuyyo9VbMw1IyxFb2NlSGyX6OVRHeBHJtcZfrFMxlw4_zwZJ_K5ksEZYodtb2HItvvphGLapKt",
            "relayState": "85b9b612b1b1012291478066ec8acb3987a6d9a1",
            "hmac": "21b7c194e63694b8571fafcad8f5edd162e33697b58cb4fb003ef8d987b2d2b9",
            "email": "test",
            "password": "test",
        },
        allow_redirects=False,
    )
    responses.assert_called_with(
        "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf",
        METH_GET,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
            "Origin": "https://identity.vwgroup.io",
        },
        allow_redirects=False,
    )
    responses.assert_called_with(
        "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode",
        METH_POST,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "x-requested-with": X_APP_NAME,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        },
        data={
            "auth_code": "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmY2NDYyZC00ZjM2LTQ4ODAtOTIzNi1lNDBjOTFmY2JhYmEiLCJhdWQiOiIzMGUzMzczNi1jNTM3LTRjNzItYWI2MC03NGE3YjkyY2ZlODNAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoib3BlbmlkIHByb2ZpbGUgYWRkcmVzcyBwaG9uZSBlbWFpbCBiaXJ0aGRhdGUgbmF0aW9uYWxJZGVudGlmaWVyIGNhcnMgbWJiIGRlYWxlcnMgYmFkZ2UgbmF0aW9uYWxpdHkiLCJhYXQiOiJpZGVudGl0eWtpdCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImF1dGhvcml6YXRpb25fY29kZSIsImV4cCI6MTcyMzIxMDA2OCwiaWF0IjoxNzIzMjA5NzY4LCJub25jZSI6ImhHWDMzL2lwd3pNdmhuNnRqOHJvNmNVN253RklqNzZKQTZqQUkvSEJsTjgiLCJqdGkiOiI0OTJjNTYyZS1lMjc0LTRhMjAtOGZmNC0xM2JiMzBmNDFhNWUifQ.AiRHFh1UDeaWsqdtD9nW5J3ZnCtIPa6UGhQhALNLuka6ip24xFQoVTYpOhvi8y607hSxTpSlEPncjkHS_cCbFn0iGmdImLSm7R-GQn7EbmUlpRFLMjvXGXzs4dmDsxHR9DuZ3zT9wPMs8W81eYR5BO8vqFzC0V-6edgvA8l8MgjdDa6WzUCuNXbhGaYW4IPbEExzo6relu9kV-SL7L0_8XVdGDqA2R0ZTSVUsBZexr3KJJrkquFXX_b00r3XCtE8xwKqYJ4xAUXHlREol941Gczaay69ZM_kSgrhaFDonr-G0zsVZ7rRPiwQChqN3lQpLuaPg90Fx-333nHnAR5GX_QLAoFVrsmkBfBDx1yOJbpHWgJFffYbz2CSaNjQAFyuA4DtBhyDccLjMPfWUQrpF0x00Lh2eHLyrw4CyfSA4CgE89UOfmInDK2wEpQfH8yj1joaYg2dmTddhtljwRz-UWmts1D66IzjkLGco__4OkGY_DVlxfyX7yQiJICh9J_IjTXpcO--vK3IiyN5XrUSSlrNOrQvIpMMA5U4_K49KHOLQIGX6N3kVw7YanEMB6TivIgnjRitVogx2V2MtO_I5_-m2vkJ4CasILEESnACkik1w_8r53LtSrxdgtUFLeNFCjKKNq5szFs_1eHnvstodH0gn6lDPuYY20s0krQjBTw",
            "id_token": "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiN21rNEhsTHVfM3BJT21tNmZVb2JXUSIsInN1YiI6ImNiZjY0NjJkLTRmMzYtNDg4MC05MjM2LWU0MGM5MWZjYmFiYSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb3IiOiJOTCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImlkX3Rva2VuIiwidHlwZSI6ImlkZW50aXR5Iiwibm9uY2UiOiJoR1gzMy9pcHd6TXZobjZ0ajhybzZjVTdud0ZJajc2SkE2akFJL0hCbE44IiwibGVlIjpbIlNFQVQiXSwiYXVkIjpbIjMwZTMzNzM2LWM1MzctNGM3Mi1hYjYwLTc0YTdiOTJjZmU4M0BhcHBzX3Z3LWRpbGFiX2NvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS5kcDE1LnZ3Zy1jb25uZWN0LmNvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS53Y2FyZHAuaW8iLCJodHRwczovL3Byb2QuZWNlLmdhdXRoLXZ3YWMuY29tIiwiVldHTUJCMDFDTkFQUDEiLCJWV0dNQkIwMURFTElWMSJdLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwiY19oYXNoIjoiVWk4c2hVeXEzWGpRdmxoby1FdWV4dyIsInVwZGF0ZWRfYXQiOjE3MjAxNjMwMjkwMTMsImFhdCI6ImlkZW50aXR5a2l0IiwiZXhwIjoxNzIzMjEzMzY4LCJpYXQiOjE3MjMyMDk3NjgsImp0aSI6IjE5ZTA4MTEyLWE0NzktNGVmYi1hMGQzLWRmMWE1YWU1NjMwNyIsImVtYWlsIjoibS50aWpzc2VuQG1lLmNvbSJ9.n9jDJhQYtaeIp5TDPzLfpwuK6kk-f2H8tgVO-g-tgXbrtkNvyjQUJe-tEE02UEkhvFLNY8qCHskq0_MpErqStrtQFEXglr6OuWS0qihTJwMW42oaqoDx4ElyPFf9sgfZ7iF7GSEKJviByY2SmfdYWZ7YqVkzqzTv0wIxV3nkHsChUzTccLvsiVTndcSvZhK1kSKAiLIKrpHoaMoeunLP3Qs8gEHuWoW4lEdkkvhIH46-Ib5WD-391tYehpDFIGqZlBtR_waugX2hV-Jy_t_O_Q2NXaNKo2u8tHg93fIsjNGMjVXt4johQWcVeeAsrXYVIgvyo0A4hiKInPHD2z5tUJh6wsb8B8495GTb7SwKyElKJp_U1oBUKo3jbhznux-WvYY6LqKVJrlJ_FGygLIWbjf7WC_gQdEnyVm75hGGF7gXQeuwZjEy4SRSHYE8Ah8S50WAVpzWGahzs1TXN-TGaPaUmxEB8tbLleBNv-Vne4I60QFt7R6-KRWFkNSXL7nr9HN0Autht3iNY7mP8NANTiwhaqFrFmSOD3-K3Lr2OLgXxziafO2rMoC4_3MqWGypIEBpeAJ9UQG6gpj3YGdISh2FvF1cMGkC77W_S5BLs8cA5Eau9zAGFwAEEj9iQ4osYcwYIe-jwVB6GEPy7EJd7j_2P0NgT6001lZRJdgWxAQ",
            "brand": "cupra",
        },
    )


@pytest.mark.usefixtures("_mock_random_string")
async def test_authorization_no_location(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test login with missing location header."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=400,
    )
    with pytest.raises(
        VolkswagenAuthenticationError, match="Missing `location` header"
    ):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
@pytest.mark.parametrize(
    ("query"),
    [({"error": "invalid_request"}), ({"error_description": "invalid_request"})],
)
async def test_authorization_error(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    query: dict[str, Any],
) -> None:
    """Test login with authorization error."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    url = URL("https://identity.vwgroup.io/oidc/v1/authorize").with_query(query)
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={"Location": str(url)},
    )
    with pytest.raises(VolkswagenAuthenticationError, match="invalid_request"):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
@pytest.mark.parametrize(
    ("query", "exception", "message"),
    [
        (
            {"error": "login.error.throttled", "enableNextButtonAfterSeconds": 50},
            VolkswagenAccountLockedError,
            "Account locked for 50 seconds",
        ),
        (
            {"error": "login.errors.password_invalid"},
            VolkswagenAuthenticationError,
            "Invalid password",
        ),
        ({"error": "something.else"}, VolkswagenAuthenticationError, "something.else"),
        (
            {"terms-and-conditions": "true"},
            VolkswagenEULAError,
            "Accept terms and conditions",
        ),
    ],
)
async def test_redirect_validation(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    query: dict[str, Any],
    exception: type[Exception],
    message: str,
) -> None:
    """Test we raise the right exceptions."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf"
        },
    )
    url = URL(
        "https://identity.vwgroup.io/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
    ).with_query(query)
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf",
        status=301,
        headers={"Location": str(url)},
    )
    with pytest.raises(exception, match=message):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_no_redirect(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test we handle no redirect."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf",
        status=400,
    )
    with pytest.raises(
        VolkswagenAuthenticationError, match="Missing `location` header"
    ):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_max_loop(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test we handle max loop."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=301,
        headers={"Location": "https://identity.vwgroup.io/oidc/v1/"},
    )
    for i in range(0, 11):
        responses.get(
            f"https://identity.vwgroup.io/oidc/v{i}/",
            status=301,
            headers={"Location": f"https://identity.vwgroup.io/oidc/v{i + 1}/"},
        )
    with pytest.raises(
        VolkswagenAuthenticationError, match="Max redirect depth reached"
    ):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_exchange_auth_code_failure(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test exchange auth code failure."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/oauth/sso?clientId=30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com&relayState=4b91fadb9ccbde9ae3593dbef397a310fbdc3afb&userId=cbf6462d-4f36-4880-9236-e40c91fcbaba&HMAC=273474c9a27dc73ec7a5389f83102ccae5f40918dd26191204741708b2ddb4cf",
        status=301,
        headers={
            "Location": "cupraconnect://identity-kit/login#state=bjPCDALBYCXvLf8th9QrsyA5dhfe3o6g4audGhZYQ9k&code=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmY2NDYyZC00ZjM2LTQ4ODAtOTIzNi1lNDBjOTFmY2JhYmEiLCJhdWQiOiIzMGUzMzczNi1jNTM3LTRjNzItYWI2MC03NGE3YjkyY2ZlODNAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoib3BlbmlkIHByb2ZpbGUgYWRkcmVzcyBwaG9uZSBlbWFpbCBiaXJ0aGRhdGUgbmF0aW9uYWxJZGVudGlmaWVyIGNhcnMgbWJiIGRlYWxlcnMgYmFkZ2UgbmF0aW9uYWxpdHkiLCJhYXQiOiJpZGVudGl0eWtpdCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImF1dGhvcml6YXRpb25fY29kZSIsImV4cCI6MTcyMzIxMDA2OCwiaWF0IjoxNzIzMjA5NzY4LCJub25jZSI6ImhHWDMzL2lwd3pNdmhuNnRqOHJvNmNVN253RklqNzZKQTZqQUkvSEJsTjgiLCJqdGkiOiI0OTJjNTYyZS1lMjc0LTRhMjAtOGZmNC0xM2JiMzBmNDFhNWUifQ.AiRHFh1UDeaWsqdtD9nW5J3ZnCtIPa6UGhQhALNLuka6ip24xFQoVTYpOhvi8y607hSxTpSlEPncjkHS_cCbFn0iGmdImLSm7R-GQn7EbmUlpRFLMjvXGXzs4dmDsxHR9DuZ3zT9wPMs8W81eYR5BO8vqFzC0V-6edgvA8l8MgjdDa6WzUCuNXbhGaYW4IPbEExzo6relu9kV-SL7L0_8XVdGDqA2R0ZTSVUsBZexr3KJJrkquFXX_b00r3XCtE8xwKqYJ4xAUXHlREol941Gczaay69ZM_kSgrhaFDonr-G0zsVZ7rRPiwQChqN3lQpLuaPg90Fx-333nHnAR5GX_QLAoFVrsmkBfBDx1yOJbpHWgJFffYbz2CSaNjQAFyuA4DtBhyDccLjMPfWUQrpF0x00Lh2eHLyrw4CyfSA4CgE89UOfmInDK2wEpQfH8yj1joaYg2dmTddhtljwRz-UWmts1D66IzjkLGco__4OkGY_DVlxfyX7yQiJICh9J_IjTXpcO--vK3IiyN5XrUSSlrNOrQvIpMMA5U4_K49KHOLQIGX6N3kVw7YanEMB6TivIgnjRitVogx2V2MtO_I5_-m2vkJ4CasILEESnACkik1w_8r53LtSrxdgtUFLeNFCjKKNq5szFs_1eHnvstodH0gn6lDPuYY20s0krQjBTw&access_token=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYmY2NDYyZC00ZjM2LTQ4ODAtOTIzNi1lNDBjOTFmY2JhYmEiLCJhdWQiOiIzMGUzMzczNi1jNTM3LTRjNzItYWI2MC03NGE3YjkyY2ZlODNAYXBwc192dy1kaWxhYl9jb20iLCJzY3AiOiJvcGVuaWQgcHJvZmlsZSBhZGRyZXNzIHBob25lIGVtYWlsIGJpcnRoZGF0ZSBuYXRpb25hbElkZW50aWZpZXIgY2FycyBtYmIgZGVhbGVycyBiYWRnZSBuYXRpb25hbGl0eSIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzIzMjEzMzY4LCJpYXQiOjE3MjMyMDk3NjgsImxlZSI6WyJTRUFUIl0sImp0aSI6IjU5NTUwMWI4LTQ5MTQtNGRjNy04YmQ2LTMyNDUwMTVkN2JkNyJ9.Hjy_v9Q7AEzxMKTyg052Av1X6NVjs1ckfH-Gr3an7YZGQBuMm8x-qD_0MR9C03CGN6VD_ymMbFbeFAwetgQecpDrlJwtS8LpSw3sowNoPwDbjKIfSsX8NsnTlLYreo0qeilIzbiDOyKQYAFyFcAOI6HmGrdbAdYWuHCPKNAfv2Hu9qQYM_fcjEAjlm8-HeAE95VvRNEb9SDXrHCxIhkSoPqmo2fXJ61gdFfX8ujO9BHnGK4yCb-FevroO_6TIav2f7FP1jMtz6rdiu6osSdYZBV-6A-Q8ZtOliLVHn3EMUoFxd-l52aGei8jh102ZAbempymLGgKYLGtdY_qEeFAf_twUZQnHNXTBIMe5KPNbkMuoz-vWEPY7v2U6-15aJBWLJhZf0Ura8kctaUBE4lh3Bkgz2siOPSdFJrnulBT_nyhyCHbaPjaeo2QT5Qvsf4WFRMSJPAqfHUo2X889XstwcR5CNr3xBw7AZ-Bn7J6INNlgYn61RtF2BpJ5TYtUxZcyKhdxDo-xSOAxCtPeJF0uAVf-Wc_mD59-ZtSxxA0ImZwruO9zrAVMsJxZGexB9gbpkKZuzXE_abOvK4M2AMTNTUvtT_z95rw9jntp-OAZo1IGr_k83gx0ZuCwV9p9G9U-_prt9ToCv3JX1GlNb7Z5KYHVZf1zXw5yrz6wgmS-hk&expires_in=3600&token_type=bearer&id_token=eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiN21rNEhsTHVfM3BJT21tNmZVb2JXUSIsInN1YiI6ImNiZjY0NjJkLTRmMzYtNDg4MC05MjM2LWU0MGM5MWZjYmFiYSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb3IiOiJOTCIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImlkX3Rva2VuIiwidHlwZSI6ImlkZW50aXR5Iiwibm9uY2UiOiJoR1gzMy9pcHd6TXZobjZ0ajhybzZjVTdud0ZJajc2SkE2akFJL0hCbE44IiwibGVlIjpbIlNFQVQiXSwiYXVkIjpbIjMwZTMzNzM2LWM1MzctNGM3Mi1hYjYwLTc0YTdiOTJjZmU4M0BhcHBzX3Z3LWRpbGFiX2NvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS5kcDE1LnZ3Zy1jb25uZWN0LmNvbSIsImh0dHBzOi8vYXBpLnZhcy5ldS53Y2FyZHAuaW8iLCJodHRwczovL3Byb2QuZWNlLmdhdXRoLXZ3YWMuY29tIiwiVldHTUJCMDFDTkFQUDEiLCJWV0dNQkIwMURFTElWMSJdLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwiY19oYXNoIjoiVWk4c2hVeXEzWGpRdmxoby1FdWV4dyIsInVwZGF0ZWRfYXQiOjE3MjAxNjMwMjkwMTMsImFhdCI6ImlkZW50aXR5a2l0IiwiZXhwIjoxNzIzMjEzMzY4LCJpYXQiOjE3MjMyMDk3NjgsImp0aSI6IjE5ZTA4MTEyLWE0NzktNGVmYi1hMGQzLWRmMWE1YWU1NjMwNyIsImVtYWlsIjoibS50aWpzc2VuQG1lLmNvbSJ9.n9jDJhQYtaeIp5TDPzLfpwuK6kk-f2H8tgVO-g-tgXbrtkNvyjQUJe-tEE02UEkhvFLNY8qCHskq0_MpErqStrtQFEXglr6OuWS0qihTJwMW42oaqoDx4ElyPFf9sgfZ7iF7GSEKJviByY2SmfdYWZ7YqVkzqzTv0wIxV3nkHsChUzTccLvsiVTndcSvZhK1kSKAiLIKrpHoaMoeunLP3Qs8gEHuWoW4lEdkkvhIH46-Ib5WD-391tYehpDFIGqZlBtR_waugX2hV-Jy_t_O_Q2NXaNKo2u8tHg93fIsjNGMjVXt4johQWcVeeAsrXYVIgvyo0A4hiKInPHD2z5tUJh6wsb8B8495GTb7SwKyElKJp_U1oBUKo3jbhznux-WvYY6LqKVJrlJ_FGygLIWbjf7WC_gQdEnyVm75hGGF7gXQeuwZjEy4SRSHYE8Ah8S50WAVpzWGahzs1TXN-TGaPaUmxEB8tbLleBNv-Vne4I60QFt7R6-KRWFkNSXL7nr9HN0Autht3iNY7mP8NANTiwhaqFrFmSOD3-K3Lr2OLgXxziafO2rMoC4_3MqWGypIEBpeAJ9UQG6gpj3YGdISh2FvF1cMGkC77W_S5BLs8cA5Eau9zAGFwAEEj9iQ4osYcwYIe-jwVB6GEPy7EJd7j_2P0NgT6001lZRJdgWxAQ"
        },
    )
    responses.post(
        "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode",
        status=400,
    )
    with pytest.raises(VolkswagenAuthenticationError, match="Invalid request"):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_no_action_found_in_username_form(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test no action found in username form."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page_without_action.html"),
    )
    with pytest.raises(VolkswagenAuthenticationError, match="No action found in form"):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_username_form_incorrect_response(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test username form incorrect response."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=400,
    )
    with pytest.raises(VolkswagenAuthenticationError, match="Invalid request"):
        await volkswagen_client.login("test", "test")


@pytest.mark.usefixtures("_mock_random_string")
async def test_password_invalid(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    snapshot: SnapshotAssertion,
) -> None:
    """Test password invalid."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    responses.get(
        "https://identity.vwgroup.io/oidc/v1/authorize?client_id=30e33736-c537-4c72-ab60-74a7b92cfe83%2540apps_vw-dilab_com&nonce=abcd&redirect_uri=cupraconnect%253A%252F%252Fidentity-kit%252Flogin&response_type=code+id_token+token&scope=openid+profile+address+phone+email+birthdate+nationalIdentifier+cars+mbb+dealers+badge+nationality&state=abcd",
        status=301,
        headers={
            "Location": "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate"
        },
    )
    responses.get(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=200,
        body=load_fixture("login_page.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier",
        status=200,
        body=load_fixture("password_form.html"),
    )
    responses.post(
        "https://identity.vwgroup.io/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/authenticate",
        status=400,
    )
    with pytest.raises(
        VolkswagenAuthenticationError, match="Missing `location` header"
    ):
        assert snapshot == await volkswagen_client.login("test", "test")
