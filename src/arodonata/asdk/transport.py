"""API transport layer - wraps sync Check Point SDK with async execution.

Handles the actual communication with Check Point management servers
using asyncio.to_thread to run sync SDK operations in an async context.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from arlogi.otel.decorator import traced
from cpapi import APIClient, APIClientArgs
from pydantic import SecretStr

from ..config.constants import DEFAULT_LOGIN_TIMEOUT
from ..logger import lazy_logger
from ..telemetry import span_attrs
from .task_waiter import TaskStatus, TaskWaiter, extract_task_ids

log = lazy_logger("arodonata.asdk.transport")


# Type alias for raw API response
RawApiResponse = dict[str, Any]


class ApiTransport:
    """Thin wrapper around sync SDK calls with async execution.

    Uses asyncio.to_thread to run sync SDK operations in an async context,
    allowing concurrent API operations without blocking the event loop.

    Example:
        transport = ApiTransport()
        response = await transport.api_call(
            server_ip="192.168.1.10",
            sid="session123",
            command="show-hosts"
        )
    """

    def __init__(self, task_waiter: TaskWaiter | None = None) -> None:
        """Initialize API transport.

        Args:
            task_waiter: Optional TaskWaiter for polling async tasks. If None,
                a default TaskWaiter will be instantiated.
        """
        self._task_waiter = task_waiter or TaskWaiter()

    @asynccontextmanager
    async def _client(self, server_ip: str, port: int | None, sid: str | None = None) -> AsyncGenerator[APIClient]:
        """Create an APIClient, yield it, then close the connection on exit."""
        client_args = APIClientArgs(server=server_ip, port=port, sid=sid, unsafe=True)
        client = APIClient(client_args)
        try:
            yield client
        finally:
            await asyncio.to_thread(client.close_connection)

    @classmethod
    def _build_login_response(cls, response: Any) -> RawApiResponse:
        """Normalize a login SDK response into a standardized dict."""
        if response.success and response.data and response.data.get("sid"):
            return {
                "success": True,
                "data": response.data,
                "sid": response.data.get("sid"),
                "message": "",
                "code": "",
            }

        code, message = cls._extract_data_code_and_message(response.data)

        # Fallback to response attributes
        if not message:
            message = getattr(response, "message", "") or getattr(response, "error_message", "")
        if not code:
            status_code = getattr(response, "status_code", "")
            if status_code:
                code = str(status_code)

        if not message:
            message = f"HTTP {code}" if code else "Unknown login error"

        return {
            "success": False,
            "data": response.data,
            "message": message,
            "code": code,
        }

    @staticmethod
    def _parse_html_error(err_msg: str) -> tuple[str, str]:
        """Extract HTTP status code and clean summary from an HTML error page.

        Returns (code, message), or ("", "") if err_msg does not appear to be HTML.
        """
        lower = err_msg.lower()
        if "<html" not in lower and "<!doctype" not in lower and "<title" not in lower and "<body" not in lower:
            return "", ""

        code = ""
        title = ""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", err_msg, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = re.sub(r"\s+", " ", title_match.group(1)).strip()
            code_match = re.search(r"\b([45]\d\d)\b", title)
            if code_match:
                code = code_match.group(1)

        # Look for <p> paragraph explanation
        p_match = re.search(r"<p[^>]*>(.*?)</p>", err_msg, re.IGNORECASE | re.DOTALL)
        detail = ""
        if p_match:
            detail = re.sub(r"<[^>]+>", " ", p_match.group(1))
            detail = re.sub(r"\s+", " ", detail).strip()

        if title and detail:
            message = f"{title}: {detail}"
        elif title:
            message = title
        elif detail:
            message = detail
        else:
            stripped = re.sub(r"<[^>]+>", " ", err_msg)
            message = re.sub(r"\s+", " ", stripped).strip()

        if not code:
            code_match = re.search(r"\b([45]\d\d)\b", message)
            if code_match:
                code = code_match.group(1)

        return code, message

    @staticmethod
    def _parse_code_and_message_from_error(err_msg: str) -> tuple[str, str]:
        """Parse the nonstandard "code: X\\nmessage: Y" embedded error string format.

        Check Point often formats nested errors as "code: <CODE>\\nmessage: <MSG>"
        inside a single error message string. Returns ("", "") if no "code: " line
        is present.

        Args:
            err_msg: The raw nested error message string.

        Returns:
            Tuple of (code, message), either of which may be empty.
        """
        code = ""
        message = ""
        if "code: " not in err_msg:
            return code, message

        for line in err_msg.split("\n"):
            if line.startswith("code: "):
                code = line.replace("code: ", "").strip()
            elif line.startswith("message: ") and not message:
                message = line.replace("message: ", "").strip()
        return code, message

    @classmethod
    def _parse_single_error_entry(cls, err: Any) -> tuple[str, str]:
        """Extract (code, message) from a single entry in errors list."""
        if not isinstance(err, dict) or "message" not in err:
            return "", ""
        err_raw = err["message"]
        if not isinstance(err_raw, str):
            return "", ""
        parsed_code, parsed_message = cls._parse_code_and_message_from_error(err_raw)
        if not parsed_message:
            html_code, html_msg = cls._parse_html_error(err_raw)
            parsed_message = html_msg or err_raw.strip()
            parsed_code = parsed_code or html_code
        return parsed_code, parsed_message

    @classmethod
    def _extract_code_and_message_from_errors(cls, data: dict) -> tuple[str, str]:
        """Extract code/message from the first parseable entry in data["errors"].

        Args:
            data: The response data dict, expected to hold an "errors" list.

        Returns:
            Tuple of (code, message), either of which may be empty.
        """
        errors = data.get("errors")
        if not isinstance(errors, list):
            return "", ""

        code = ""
        message = ""
        for err in errors:
            entry_code, entry_msg = cls._parse_single_error_entry(err)
            if entry_msg and not message:
                message = entry_msg
            if entry_code and not code:
                code = entry_code
            if code and message:
                break
        return code, message

    @classmethod
    def _extract_data_code_and_message(cls, data: Any) -> tuple[str, str]:
        """Extract (code, message) from response.data (dict, str, or other)."""
        if isinstance(data, dict):
            message = data.get("message", "")
            code = data.get("code", "")
            if not code or not message:
                err_code, err_msg = cls._extract_code_and_message_from_errors(data)
                code = code or err_code
                message = message or err_msg
            return code, message
        if isinstance(data, str):
            html_code, html_msg = cls._parse_html_error(data)
            if html_msg:
                return html_code, html_msg
            return "", data
        return "", ""

    def _convert_response_to_dict(self, response: Any) -> RawApiResponse:
        """Convert APIResponse object to standardized dictionary format.

        Args:
            response: APIResponse object from SDK.

        Returns:
            Standardized response dictionary.
        """
        code, message = self._extract_data_code_and_message(response.data)

        # Fallback to response attributes
        if not message:
            message = getattr(response, "message", "") or getattr(response, "error_message", "")
        if not code:
            status_code = getattr(response, "status_code", "")
            if status_code:
                code = str(status_code)
            elif not response.success:
                code = "error"

        if not message and not response.success:
            message = f"HTTP {code}" if code and code != "error" else "Unknown error"

        return {
            "success": response.success,
            "data": response.data,
            "message": message,
            "code": code,
        }

    @traced
    async def api_call(
        self,
        server_ip: str,
        sid: str,
        command: str,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
        port: int | None = None,
    ) -> RawApiResponse:
        """Execute API call using sync SDK in async context.

        Args:
            server_ip: Management server IP address.
            sid: Session identifier.
            command: API command to execute.
            payload: Request payload.
            wait_for_task: Whether to wait for task completion. The wait is done
                here, by `TaskWaiter`, never by cpapi -- see `_await_tasks`.
            timeout: Budget in seconds for the WHOLE operation: the initial call
                plus, when it returns a task, the polling until that task ends.
                <= 0 means unbounded.
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response dictionary. For a task-returning command with
            `wait_for_task=True`, the final `show-task` response, with `success`
            False if any task ended other than `succeeded`.

        Raises:
            TaskTimeoutError: The task did not finish within `timeout`. A
                `TimeoutError` subclass, so `except TimeoutError` still catches it.
            TimeoutError: The initial call itself did not return within `timeout`.
            TaskPollError: `show-task` kept failing past the tolerated count.
        """
        if payload is None:
            payload = {}

        span_attrs(command=command, server_ip=server_ip, port=port)
        started = asyncio.get_running_loop().time()

        try:
            log().trace(f"API CALL: {command}")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        client.api_call,
                        command,
                        payload,
                        client.sid,
                        # Never let cpapi run its own blocking show-task loop: it
                        # bypasses this transport entirely (no rate limit, no span,
                        # no log line) and times out into a bare, detail-free
                        # TimeoutError. The waiting is done below, where we can
                        # see it.
                        False,
                        timeout,
                    ),
                    timeout=timeout if timeout > 0 else None,
                )
            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"API CALL SUCCESS: {command}")
            else:
                log().trace(f"API CALL FAILED: {command} - {result.get('message', 'Unknown error')}")
                span_attrs(response_code=result.get("code"))

            if wait_for_task and command != "show-task":
                result = await self._await_tasks(
                    result,
                    server_ip=server_ip,
                    sid=sid,
                    port=port,
                    command=command,
                    timeout=timeout,
                    elapsed=asyncio.get_running_loop().time() - started,
                )
            return result
        except TimeoutError:
            log().error(f"API CALL TIMEOUT: {command} (timeout={timeout}s)")
            raise
        except Exception as e:
            log().error(f"API CALL ERROR: {command} - {e}")
            raise

    async def _await_tasks(
        self,
        result: RawApiResponse,
        *,
        server_ip: str,
        sid: str,
        port: int | None,
        command: str,
        timeout: int,
        elapsed: float,
    ) -> RawApiResponse:
        """Wait out any task the response announced; return the final show-task result.

        Mirrors cpapi's own guards exactly: an unsuccessful call is never waited on,
        and a response carrying neither `task-id` nor `tasks` is returned untouched
        (the overwhelmingly common path). `timeout` is the budget for the WHOLE
        operation, so the initial call's `elapsed` is charged against it -- which is
        why `REVERT_TIMEOUT_SECONDS` keeps meaning what it meant.
        """
        if not result.get("success"):
            return result

        task_ids = extract_task_ids(result.get("data"))
        if not task_ids:
            return result

        # The waiter returns statuses, not responses, so keep the last raw
        # show-task response here: returning it verbatim (minus the recomputed
        # success flag) is what makes `.data`, `.message` and `.code` identical to
        # what cpapi's `check_tasks_status` path produced.
        last_response: RawApiResponse = {}

        async def show_task(task_payload: dict[str, Any]) -> RawApiResponse:
            nonlocal last_response
            # Straight back into this transport, never through the client path: we
            # are already inside the enclosing call's rate-limiter slot and its
            # session, so the client path would re-run login resolution,
            # re-acquire the limiter and spawn a keepalive sweep ~70 times per
            # revert. Holding the one slot for the whole task is the intended
            # throttle. `timeout=-1` because the waiter owns the budget.
            last_response = await self.api_call(
                server_ip=server_ip,
                sid=sid,
                command="show-task",
                payload=task_payload,
                wait_for_task=False,
                timeout=-1,
                port=port,
            )
            return last_response

        remaining = timeout - elapsed if timeout > 0 else -1.0
        statuses: list[TaskStatus] = await self._task_waiter.wait(
            show_task, task_ids, timeout=remaining, context=f"{command} on {server_ip}"
        )

        final = dict(last_response)
        # Reproduces cpapi's check_tasks_status: failed / partially succeeded /
        # still in progress all yield success=False on the returned response, and
        # nothing is raised. Stricter in one respect -- an unrecognized status is
        # not a success either (allowlist, where cpapi's was a denylist).
        final["success"] = bool(statuses) and all(status.is_success for status in statuses)
        if not final["success"]:
            span_attrs(response_code=final.get("code"))
        return final

    @traced
    async def api_query(
        self,
        server_ip: str,
        sid: str,
        command: str,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        port: int | None = None,
    ) -> RawApiResponse:
        """Execute API query using sync SDK in async context.

        Args:
            server_ip: Management server IP address.
            sid: Session identifier.
            command: API query command to execute.
            details_level: Detail level for response.
            payload: Request payload.
            container_key: Key to extract objects from response.
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response dictionary.

        Raises:
            ValueError: If response is None or invalid.
        """
        if payload is None:
            payload = {}

        span_attrs(command=command, server_ip=server_ip, port=port)

        try:
            log().trace(f"API QUERY: {command} (level={details_level})")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.to_thread(
                    client.api_query,
                    command,
                    details_level,
                    container_key,
                    False,  # json_export
                    payload,
                )

            if response is None:
                raise ValueError(f"API query returned None response: {command}")

            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"API QUERY SUCCESS: {command}")
            else:
                log().trace(f"API QUERY FAILED: {command} - {result.get('message', 'Unknown error')}")
                span_attrs(response_code=result.get("code"))

            # Ensure proper error message if data is missing
            if not result["success"] and not result["message"]:
                result["message"] = getattr(response, "error_message", "Unknown query error")

            return result
        except Exception as e:
            log().error(f"API QUERY ERROR: {command} - {e}")
            raise

    @traced
    async def login_with_apikey(
        self,
        server_ip: str,
        api_key: str,
        domain: str | None = None,
        timeout: int = DEFAULT_LOGIN_TIMEOUT,
        port: int | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        session_timeout: int | None = None,
    ) -> RawApiResponse:
        """Perform login using an API key.

        Args:
            server_ip: Management server IP address.
            api_key: API key for authentication.
            domain: Optional domain name.
            timeout: Per-attempt login timeout in seconds (default:
                DEFAULT_LOGIN_TIMEOUT). A login is one round trip; it does not
                inherit the much larger API/task budget.
            port: Optional port number (defaults to 443 if not specified).
            session_name: Optional session name visible in SmartConsole.
            session_description: Optional session description.
            session_timeout: Session timeout in seconds (default: 600).

        Returns:
            Login response dictionary.

        Raises:
            asyncio.TimeoutError: If login times out.
        """
        login_payload: dict[str, Any] = {}
        if domain:
            login_payload["domain"] = domain
        if session_name:
            login_payload["session-name"] = session_name
        if session_description:
            login_payload["session-description"] = session_description
        if session_timeout is not None:
            login_payload["session-timeout"] = session_timeout

        domain_context = f" domain={domain}" if domain else " (system domain)"
        masked_key = f"{api_key[:4]}...{api_key[-4:]}" if api_key and len(api_key) > 8 else "****"
        log().trace(f"LOGIN (apikey) request: {server_ip}{domain_context}, API_KEY={masked_key}")

        span_attrs(server_ip=server_ip, domain=domain or "system", port=port)

        try:
            async with self._client(server_ip, port) as client:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        client.login_with_api_key,
                        api_key,
                        False,  # continue_last_session
                        domain,
                        False,  # read_only
                        login_payload,
                    ),
                    timeout=timeout if timeout > 0 else None,
                )

            if response is None:
                raise ValueError("API login returned None response")

            result = self._build_login_response(response)
            if result["success"]:
                log().debug(f"LOGIN (apikey) SUCCESS: {server_ip}{domain_context} -> SID={result['sid'][:8]}...")
            else:
                log().error(
                    f"LOGIN (apikey) FAILED: {server_ip}{domain_context}\n"
                    f"  error_msg: {result['message']}\n"
                    f"  response.success: {response.success}\n"
                    f"  response.data keys: {list(response.data.keys()) if response.data else 'None'}\n"
                    f"  response.data: {response.data}\n"
                    f"  response.error_message: {getattr(response, 'error_message', 'N/A')}\n"
                )
            return result
        except TimeoutError as e:
            # `e` is asyncio.wait_for's bare TimeoutError and stringifies to "";
            # say how long we waited instead (int-4, 2026-09-13, logged an empty reason).
            log().error(f"LOGIN (apikey) TIMEOUT: {server_ip}{domain_context} (timeout={timeout}s)")
            raise TimeoutError(f"Login timed out after {timeout}s") from e
        except Exception as e:
            log().error(f"LOGIN (apikey) ERROR: {server_ip}{domain_context} - {e}")
            raise

    @traced
    async def login_with_credentials(
        self,
        server_ip: str,
        username: str,
        password: SecretStr | str,
        domain: str | None = None,
        timeout: int = DEFAULT_LOGIN_TIMEOUT,
        port: int | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        session_timeout: int | None = None,
    ) -> RawApiResponse:
        """Perform login with username/password credentials.

        Args:
            server_ip: Management server IP address.
            username: Username for authentication.
            password: Password for authentication (SecretStr or str).
            domain: Optional domain name.
            timeout: Per-attempt login timeout in seconds (default:
                DEFAULT_LOGIN_TIMEOUT). A login is one round trip; it does not
                inherit the much larger API/task budget.
            port: Optional port number (defaults to 443 if not specified).
            session_name: Optional session name visible in SmartConsole.
            session_description: Optional session description.
            session_timeout: Session timeout in seconds (default: 600).

        Returns:
            Login response dictionary.

        Raises:
            asyncio.TimeoutError: If login times out.
        """
        # Hide this function from tracebacks to prevent leaking credentials
        __tracebackhide__ = True
        secret_pw = password if isinstance(password, SecretStr) else SecretStr(password)

        login_payload: dict[str, Any] = {}
        if domain:
            login_payload["domain"] = domain
        if session_name:
            login_payload["session-name"] = session_name
        if session_description:
            login_payload["session-description"] = session_description
        if session_timeout is not None:
            login_payload["session-timeout"] = session_timeout

        domain_context = f" domain={domain}" if domain else " (system domain)"
        log().trace(f"LOGIN (credentials) request: {server_ip}{domain_context}, user={username}")

        span_attrs(server_ip=server_ip, domain=domain or "system", port=port)

        try:
            async with self._client(server_ip, port) as client:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        client.login,
                        username,
                        secret_pw.get_secret_value(),
                        False,  # continue_last_session
                        domain,
                        False,  # read_only
                        login_payload,
                    ),
                    timeout=timeout if timeout > 0 else None,
                )

            if response is None:
                raise ValueError("API credential login returned None response")

            result = self._build_login_response(response)
            if result["success"]:
                log().debug(f"LOGIN (credentials) SUCCESS: {server_ip}{domain_context}")
            else:
                log().warning(f"LOGIN (credentials) FAILED: {server_ip}{domain_context} - {result['message']}")
            return result
        except TimeoutError as e:
            log().error(f"LOGIN (credentials) TIMEOUT: {server_ip}{domain_context} (timeout={timeout}s)")
            raise TimeoutError(f"Credential login timed out after {timeout}s") from e
        except Exception as e:
            log().error(f"LOGIN (credentials) ERROR: {server_ip}{domain_context} - {e}")
            raise

    @traced
    async def logout(
        self,
        server_ip: str,
        sid: str,
        port: int | None = None,
    ) -> RawApiResponse:
        """Perform logout for a session.

        Args:
            server_ip: Management server IP address.
            sid: Session ID to logout.
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response dictionary.
        """
        span_attrs(server_ip=server_ip, port=port)
        try:
            log().trace(f"LOGOUT from {server_ip}")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.to_thread(client.api_call, "logout")
            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"LOGOUT SUCCESS: {server_ip}")
            else:
                log().trace(f"LOGOUT FAILED: {server_ip} - {result.get('message', 'Unknown error')}")
            return result
        except Exception as e:
            log().error(f"LOGOUT ERROR: {server_ip} - {e}")
            return {"success": False, "message": str(e)}

    @traced
    async def keepalive(
        self,
        server_ip: str,
        sid: str,
        port: int | None = None,
    ) -> RawApiResponse:
        """Send keepalive ping to keep a session active.

        Args:
            server_ip: Management server IP address.
            sid: Session identifier to keep alive.
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response dictionary.
        """
        span_attrs(server_ip=server_ip, port=port)
        try:
            log().trace(f"KEEPALIVE: {server_ip}")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.to_thread(client.api_call, "keepalive", {}, client.sid)
            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"KEEPALIVE SUCCESS: {server_ip}")
            else:
                log().trace(f"KEEPALIVE FAILED: {server_ip} - {result.get('message', '')}")
            return result
        except Exception as e:
            log().error(f"KEEPALIVE ERROR: {server_ip} - {e}")
            raise

    @traced
    async def show_sessions(
        self,
        server_ip: str,
        sid: str,
        port: int | None = None,
    ) -> RawApiResponse:
        """Retrieve all active sessions for the current admin.

        Args:
            server_ip: Management server IP address.
            sid: Session identifier with sufficient privileges.
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response with 'objects' list of session dictionaries.
        """
        span_attrs(server_ip=server_ip, port=port)
        try:
            log().trace(f"SHOW-SESSIONS: {server_ip}")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.to_thread(
                    client.api_call,
                    "show-sessions",
                    {"details-level": "full", "limit": 500},
                    client.sid,
                )
            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"SHOW-SESSIONS SUCCESS: {server_ip}")
            else:
                log().trace(f"SHOW-SESSIONS FAILED: {server_ip} - {result.get('message', '')}")
            return result
        except Exception as e:
            log().error(f"SHOW-SESSIONS ERROR: {server_ip} - {e}")
            raise

    @traced
    async def discard_session(
        self,
        server_ip: str,
        sid: str,
        target_uid: str,
        port: int | None = None,
    ) -> RawApiResponse:
        """Discard a specific session by its UID.

        Args:
            server_ip: Management server IP address.
            sid: Session identifier used to issue the discard command.
            target_uid: UID of the session to discard (from show-sessions).
            port: Optional port number (defaults to 443 if not specified).

        Returns:
            API response dictionary.
        """
        span_attrs(server_ip=server_ip, port=port)
        try:
            log().trace(f"DISCARD-SESSION: {server_ip} uid={target_uid}")
            async with self._client(server_ip, port, sid) as client:
                response = await asyncio.to_thread(
                    client.api_call,
                    "discard",
                    {"uid": target_uid},
                    client.sid,
                )
            result = self._convert_response_to_dict(response)
            if result["success"]:
                log().trace(f"DISCARD-SESSION SUCCESS: {server_ip} uid={target_uid}")
            else:
                log().trace(f"DISCARD-SESSION FAILED: {server_ip} uid={target_uid} - {result.get('message', '')}")
            return result
        except Exception as e:
            log().error(f"DISCARD-SESSION ERROR: {server_ip} uid={target_uid} - {e}")
            raise


__all__ = ["ApiTransport", "RawApiResponse"]
