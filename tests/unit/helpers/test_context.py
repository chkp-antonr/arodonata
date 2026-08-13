"""Unit tests for arodonata.helpers._context.UserContext."""

from arodonata.helpers._context import UserContext


class TestUserContextDataclass:
    """Direct construction of the dataclass."""

    def test_fields_roundtrip(self):
        context = UserContext(username="jdoe", source="cli")
        assert context.username == "jdoe"
        assert context.source == "cli"


class TestFromFastapiUser:
    """Tests for UserContext.from_fastapi_user()."""

    def test_webui_source_when_not_api_call(self):
        user = {"username": "john", "is_api_call": False}
        context = UserContext.from_fastapi_user(user)

        assert context.username == "john"
        assert context.source == "webui"

    def test_api_source_when_api_call_true(self):
        user = {"username": "admin", "is_api_call": True}
        context = UserContext.from_fastapi_user(user)

        assert context.username == "admin"
        assert context.source == "api"

    def test_missing_username_defaults_to_unknown(self):
        user = {}
        context = UserContext.from_fastapi_user(user)

        assert context.username == "unknown"
        assert context.source == "webui"

    def test_missing_is_api_call_defaults_to_webui(self):
        user = {"username": "jane"}
        context = UserContext.from_fastapi_user(user)

        assert context.username == "jane"
        assert context.source == "webui"


class TestFromCli:
    """Tests for UserContext.from_cli()."""

    def test_uses_os_username(self, monkeypatch):
        monkeypatch.setattr("getpass.getuser", lambda: "os-user")
        context = UserContext.from_cli()

        assert context.username == "os-user"
        assert context.source == "cli"
