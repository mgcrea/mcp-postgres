"""The wiring that makes the guard actually apply.

Everything asserted here is invisible in review and fails silently in production:

* A route list that mounts SSE after the catch-all `Mount("/")` never serves SSE at all,
  because Starlette returns on the first `Match.FULL`. That was this repo's shape until the
  SDK 2.x port, and `/` advertised the transport regardless.
* `/healthz` behind the guarded mount means the kubelet is asked for a bearer token it does
  not have, and the pod never goes Ready — across eleven deployments at once.
* A decorator that dropped `functools.wraps` would publish a tool taking `(*args, **kwargs)`,
  and the model would simply stop being able to call it, with nothing else failing.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from mcp_policy_guard import GuardConfig, is_guarded
from mcp_policy_guard import routes as guard_routes
from starlette.routing import Route

import mcp_postgres.server as server


def _config(*, require_auth: bool) -> GuardConfig:
    return replace(server.guard.config, require_auth=require_auth, issuer="https://idp.test/realms/ai-hub")


def _paths(*, require_auth: bool, extra: list[Route] | None = None) -> list[str | None]:
    built = guard_routes(
        server.mcp,
        _config(require_auth=require_auth),
        extra_routes=extra if extra is not None else [],
        app_kwargs={"transport_security": server.security_settings, "streamable_http_path": "/mcp"},
        sse_app_kwargs={"transport_security": server.security_settings},
    )
    return [getattr(route, "path", None) for route in built]


class TestRouteOrdering:
    def test_sse_is_reachable_when_it_is_mounted_at_all(self):
        paths = _paths(require_auth=False)
        # SSE must come *before* the catch-all. Mounted after it, `Mount("/")` matches every
        # path first and the SSE mount is unreachable dead code.
        assert paths.index("/sse") < paths.index("")

    def test_no_sse_mount_while_authentication_is_required(self):
        # Under SSE the connection carrying the Authorization header is not the request
        # carrying the tool call, so a call cannot be attributed to a caller. Mounting it
        # anyway is a second, unauthenticated door onto the same tools.
        assert "/sse" not in _paths(require_auth=True)

    def test_health_and_root_stay_ahead_of_the_guarded_mount(self):
        extra = [Route("/healthz", lambda r: None), Route("/", lambda r: None)]
        paths = _paths(require_auth=True, extra=extra)
        # Knative's readiness probe must not be asked for a bearer token by the kubelet.
        assert paths.index("/healthz") < paths.index("")
        assert paths.index("/") < paths.index("")


class TestTransportSecurityIsForwarded:
    def test_dns_rebinding_protection_stays_off(self):
        """Left to default, SDK 2.x answers every request `421 Invalid Host header`.

        `streamable_http_app()` defaults `host` to 127.0.0.1 and on that default auto-enables
        rebinding protection with a localhost-only allow-list — so every request arriving under
        the pod's real service hostname is refused. In Kubernetes that is all of them.
        """
        assert server.security_settings.enable_dns_rebinding_protection is False


class TestEveryRegisteredToolIsGuarded:
    def _tool_fns(self) -> dict[str, object]:
        names = [tool.name for tool in asyncio.run(server.mcp.list_tools())]
        return {name: server.mcp._tool_manager.get_tool(name).fn for name in names}

    def test_there_are_tools_to_check(self):
        # Guards the guard: if registration ever moved, the assertion below would pass
        # vacuously over an empty set.
        assert set(self._tool_fns()) == {
            "postgres_query",
            "postgres_list_tables",
            "postgres_describe_table",
        }

    def test_all_registered_tools_carry_the_per_message_binding(self):
        unguarded = [name for name, fn in self._tool_fns().items() if not is_guarded(fn)]
        assert unguarded == [], f"tools registered without @guarded: {unguarded}"

    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("postgres_query", {"query"}),
            ("postgres_list_tables", {"schema"}),
            ("postgres_describe_table", {"table_name", "schema"}),
        ],
    )
    def test_the_decorator_does_not_flatten_the_published_schema(self, tool, expected):
        published = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == tool)
        assert set(published.input_schema["properties"]) == expected
