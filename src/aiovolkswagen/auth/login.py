"""Login form parsers."""

import re
from html.parser import HTMLParser
from typing import Any

import orjson

from aiovolkswagen.exceptions import VolkswagenAuthenticationError


def _get_attribute(attrs: list[tuple[str, str | None]], name: str) -> str | None:
    for attr in attrs:
        if attr[0] == name:
            return attr[1]
    return None


class ClassicFormParser(HTMLParser):
    """Parser for classic form."""

    _form_id: str

    def __init__(self) -> None:
        """Initialize the parser."""
        super().__init__()
        self.form_data: dict[str, Any] = {}
        self.action: str | None = None
        self._is_in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Handle start tag."""
        if tag == "form" and _get_attribute(attrs, "id") == self._form_id:
            self.action = _get_attribute(attrs, "action")
            self._is_in_form = True
        if (
            self._is_in_form
            and tag == "input"
            and _get_attribute(attrs, "type") == "hidden"
        ):
            name = _get_attribute(attrs, "name")
            value = _get_attribute(attrs, "value")
            if name and value:
                self.form_data[name] = value

    def handle_endtag(self, tag: str) -> None:
        """Handle end tag."""
        if tag == "form" and self._is_in_form:
            self._is_in_form = False


class EmailFormParser(ClassicFormParser):
    """Parser for email form."""

    _form_id = "emailPasswordForm"


class ClassicPasswordFormParser(ClassicFormParser):
    """Parser for password form."""

    _form_id = "credentialsForm"


class DynamicPasswordFormParser(HTMLParser):
    """Parser for dynamic password form."""

    _regexp = re.compile("templateModel: (.*?),\n")

    def __init__(self) -> None:
        """Initialize the parser."""
        super().__init__()
        self.form_data: dict[str, Any] = {}
        self.action: str | None = None
        self._is_in_data = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Handle start tag."""
        if (
            tag == "script"
            and _get_attribute(attrs, "type") is None
            and _get_attribute(attrs, "src") is None
        ):
            self._is_in_data = True

    def handle_data(self, data: str) -> None:
        """Handle data."""
        if self._is_in_data:
            found_data = self._regexp.search(data)
            if not found_data:
                return
            json_data = orjson.loads(found_data.groups()[0])
            if (error := json_data.get("error")) is not None:
                raise VolkswagenAuthenticationError(error)
            if "hmac" not in json_data:
                raise VolkswagenAuthenticationError("No HMAC found in form")
            if "postAction" not in json_data:
                raise VolkswagenAuthenticationError("No postAction found in form")
            self.form_data["hmac"] = json_data["hmac"]
            self.action = json_data["postAction"]

    def handle_endtag(self, tag: str) -> None:
        """Handle end tag."""
        if tag == "script" and self._is_in_data:
            self._is_in_data = False
