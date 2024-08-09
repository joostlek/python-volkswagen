"""Test auth module."""

from aiovolkswagen.auth.login import EmailFormParser, DynamicPasswordFormParser
from tests import load_fixture


async def test_mail_form_parser() -> None:
    """Test mail form parser."""

    html_body = load_fixture("login_page.html")
    parser = EmailFormParser()
    parser.feed(html_body)
    assert (
        parser.action
        == "/signin-service/v1/30e33736-c537-4c72-ab60-74a7b92cfe83@apps_vw-dilab_com/login/identifier"
    )
    assert parser.form_data == {
        "_csrf": "IBbkJahuAMzoAilHhdHEU6uuyyo9VbMw1IyxFb2NlSGyX6OVRHeBHJtcZfrFMxlw4_zwZJ_K5ksEZYodtb2HItvvphGLapKt",
        "hmac": "0b85d60ce123cbc18d5a3d0bd62d1ce0fdb4d795b6814c958f719992642e8d8c",
        "relayState": "85b9b612b1b1012291478066ec8acb3987a6d9a1",
    }


async def test_dynamic_form_parser() -> None:
    """Test dynamic form parser."""
    html_body = load_fixture("password_form.html")
    parser = DynamicPasswordFormParser()
    parser.feed(html_body)
    assert parser.action == "login/authenticate"
    assert parser.form_data == {
        "hmac": "21b7c194e63694b8571fafcad8f5edd162e33697b58cb4fb003ef8d987b2d2b9"
    }
