"""HTTP client for the daemon API, shared by the CLI (sync) and the TUI (async).

Clients never import Django, never open SQLite and never run discovery: the
daemon is the single source of truth.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from portregistry.config import Config, load_config, read_token
from portregistry.daemon.lock import read_state, state_process_alive
from portregistry.exceptions import ApiError, DaemonNotRunningError
from portregistry.paths import AppPaths, get_paths

API_PREFIX = "/api/v1"
USER_AGENT = "portregistry-client"


@dataclass(frozen=True)
class ClientSettings:
    base_url: str
    token: str | None


def resolve_settings(paths: AppPaths | None = None, config: Config | None = None) -> ClientSettings:
    paths = paths or get_paths()
    config = config or load_config(paths)
    base_url = config.base_url
    state = read_state(paths.state_file)
    if state_process_alive(state):
        assert state is not None
        host = str(state.get("host") or "127.0.0.1")
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host:
            host = f"[{host}]"
        base_url = f"http://{host}:{state.get('port')}"
    return ClientSettings(base_url=base_url, token=read_token(paths))


def _not_running(base_url: str) -> DaemonNotRunningError:
    return DaemonNotRunningError(
        f"Cannot reach the PortRegistry daemon at {base_url}. "
        "Start it with: portregistry daemon start"
    )


def _api_error(response: httpx.Response) -> ApiError:
    code, message = "http_error", f"HTTP {response.status_code}"
    details: dict[str, Any] = {}
    try:
        payload = response.json()
        err = payload.get("error", {}) if isinstance(payload, dict) else {}
        code = err.get("code", code)
        message = err.get("message", message)
        details = err.get("details", {}) or {}
    except ValueError:
        pass
    if response.status_code == 401 and code in ("not_authenticated", "authentication_failed"):
        message += " (the local API token is in the PortRegistry config directory; see `portregistry paths`)"
    return ApiError(response.status_code, code, message, details)


def _headers(token: str | None) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class ApiClient:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url, timeout=timeout, headers=_headers(token), transport=transport
        )

    @classmethod
    def from_environment(cls, **kwargs: Any) -> ApiClient:
        settings = resolve_settings()
        return cls(settings.base_url, settings.token, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json_body: Any = None
    ) -> Any:
        url = path if path.startswith("/") else f"{API_PREFIX}/{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            response = self._client.request(method, url, params=clean_params, json=json_body)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
            raise _not_running(self.base_url) from exc
        except httpx.TimeoutException as exc:
            raise ApiError(0, "timeout", f"Request to the daemon timed out: {exc}") from exc
        if response.status_code >= 400:
            raise _api_error(response)
        if not response.content:
            return None
        return response.json()

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, json_body=body if body is not None else {})

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, json_body=body)

    def put(self, path: str, body: Any) -> Any:
        return self.request("PUT", path, json_body=body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def list_all(self, path: str, *, max_items: int = 5000, **params: Any) -> list[Any]:
        """Fetch every page of a paginated list endpoint (bounded)."""
        items: list[Any] = []
        offset = 0
        page_size = 500
        while len(items) < max_items:
            page = self.get(path, limit=page_size, offset=offset, **params)
            results = page.get("results", []) if isinstance(page, dict) else page
            items.extend(results)
            if not isinstance(page, dict) or not page.get("next") or not results:
                break
            offset += len(results)
        return items[:max_items]

    def health(self) -> dict[str, Any]:
        return self.get("health/")


class AsyncApiClient:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport
        self._client = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, headers=_headers(token), transport=transport
        )

    @classmethod
    def from_environment(cls, **kwargs: Any) -> AsyncApiClient:
        settings = resolve_settings()
        return cls(settings.base_url, settings.token, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json_body: Any = None
    ) -> Any:
        url = path if path.startswith("/") else f"{API_PREFIX}/{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            response = await self._client.request(method, url, params=clean_params, json=json_body)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
            raise _not_running(self.base_url) from exc
        except httpx.TimeoutException as exc:
            raise ApiError(0, "timeout", f"Request to the daemon timed out: {exc}") from exc
        if response.status_code >= 400:
            raise _api_error(response)
        if not response.content:
            return None
        return response.json()

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, body: Any = None) -> Any:
        return await self.request("POST", path, json_body=body if body is not None else {})

    async def patch(self, path: str, body: Any) -> Any:
        return await self.request("PATCH", path, json_body=body)

    async def delete(self, path: str) -> Any:
        return await self.request("DELETE", path)

    async def results(self, path: str, **params: Any) -> list[Any]:
        page = await self.get(path, **params)
        return page.get("results", []) if isinstance(page, dict) else page

    async def stream_events(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """Yield ``(event, data)`` pairs from the SSE stream until it closes."""
        url = f"{API_PREFIX}/events/stream/"
        try:
            async with self._client.stream(
                "GET", url, timeout=httpx.Timeout(10.0, read=60.0)
            ) as response:
                if response.status_code >= 400:
                    await response.aread()
                    raise _api_error(response)
                event = "message"
                data_lines: list[str] = []
                async for line in response.aiter_lines():
                    if line == "":
                        if data_lines:
                            try:
                                payload = json.loads("\n".join(data_lines))
                            except ValueError:
                                payload = {"raw": "\n".join(data_lines)}
                            yield event, payload
                        event, data_lines = "message", []  # reset after dispatch
                    elif line.startswith(":"):
                        continue
                    elif line.startswith("event:"):
                        event = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise _not_running(self.base_url) from exc
