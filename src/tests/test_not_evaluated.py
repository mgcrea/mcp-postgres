"""Failures that happen before policy could decide anything.

The distinction under test is the one that is easy to lose: a call refused because the database
would not answer is **not** a denial, and must not be recorded, reported or worded as one.
Equally, the identical database failure *after* a decision was reached is an execution failure
and must not be reported at all — reporting it would file a second row for a call the PDP
already ruled on.

Until `report_not_evaluated` was wired in, a call failing this way reached the platform as
nothing whatsoever: no `/evaluate`, so no audit row, so a tool failing on every call looked
exactly like a tool nobody had called. That is open item 6 in the mail archive.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import psycopg
import pytest
from mcp_policy_guard import Decision, PolicyDenied

from mcp_postgres.tools import postgres as tools

from .test_tool_authorization import StubMCP

ALLOWED = Decision(decision="allow", effect="allow", enforcing=True, reason="granted")


@pytest.fixture(autouse=True)
def _clean_schema_cache():
    tools._schema_cache.clear()
    tools._default_schema = None
    yield
    tools._schema_cache.clear()
    tools._default_schema = None


@pytest.fixture(autouse=True)
def _allow_by_default(monkeypatch):
    monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: ALLOWED)
    monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, values, **_kw: list(values))


@pytest.fixture
def reports(monkeypatch):
    """Capture what the tool reports to the PDP."""
    calls: list[tuple] = []
    monkeypatch.setattr(
        tools.guard,
        "report_not_evaluated",
        lambda function_name, reason, resources=(), **_kw: calls.append((function_name, reason, resources)),
    )
    return calls


@pytest.fixture
def governed(monkeypatch):
    """A tool with a PDP configured, which is the only shape that connects before deciding.

    Without this the pre-decision connection never happens: `_resolve_default_schema` is
    bypassed and `_column_resources` returns `[]` when `policy_enabled` is false, so an
    ungoverned tool opens its first connection at execution and there is no precondition step
    to fail. That is correct — an ungoverned tool has no PDP to report to either — and it is
    why these tests must enable policy explicitly.
    """

    def _governed():
        monkeypatch.setattr(tools.guard, "config", SimpleNamespace(policy_enabled=True))
        monkeypatch.setattr(tools.guard, "snapshot", lambda *_a, **_k: SimpleNamespace(allows=lambda *_: True))

    return _governed


@pytest.fixture
def call_with(monkeypatch):
    def _call(tool_name: str, connect, **kwargs):
        monkeypatch.setattr(tools.psycopg, "connect", connect)
        stub = StubMCP()
        tools.register_postgres_tools(stub)
        return asyncio.run(stub.tools[tool_name](**kwargs))

    return _call


class TestPreDecisionFailureReports:
    def test_a_login_failure_while_resolving_the_search_path_is_reported(self, call_with, reports, governed):
        # The `search_path` probe is the first connection a governed query opens, and it opens
        # before any decision. Degrading it to an undetermined read set would let the PDP
        # record a denial for a call it never saw.
        governed()
        connect = MagicMock(side_effect=psycopg.OperationalError("FATAL: password authentication failed"))

        result = call_with("postgres_query", connect, query="SELECT id FROM orders")

        assert len(reports) == 1
        function_name, reason, _resources = reports[0]
        assert function_name == "postgres_query"
        assert "password authentication failed" in reason
        assert "Error" in result

    def test_a_catalogue_failure_while_reading_columns_is_reported(self, call_with, reports, governed):
        # Fully qualified, so `search_path` is never probed and the *only* pre-decision
        # connection is the `information_schema` read the column pass needs.
        governed()
        connect = MagicMock(side_effect=psycopg.OperationalError("connection refused"))

        result = call_with("postgres_query", connect, query="SELECT id FROM public.orders")

        assert len(reports) == 1
        assert reports[0][0] == "postgres_query"
        assert "Error" in result

    def test_the_message_says_it_was_not_an_access_decision(self, call_with, reports, governed):
        # The whole point: the user must be able to tell "the database is down" from "policy
        # said no". Worded as a denial, it sends them to raise an access request for a
        # permission they already hold.
        governed()
        connect = MagicMock(side_effect=psycopg.OperationalError("connection refused"))

        result = call_with("postgres_query", connect, query="SELECT id FROM public.orders")

        assert "not an access decision" in result
        assert "access to" not in result

    def test_list_tables_reports_too(self, call_with, reports):
        # Unambiguously pre-decision: the listing *is* the input to the decision.
        connect = MagicMock(side_effect=psycopg.OperationalError("connection refused"))

        result = call_with("postgres_list_tables", connect, schema="public")

        assert len(reports) == 1
        assert reports[0][0] == "postgres_list_tables"
        assert "not an access decision" in result


class TestPostDecisionFailureDoesNotReport:
    def test_a_failure_at_execution_is_not_reported(self, call_with, reports, monkeypatch, governed):
        """The asymmetry that is easy to lose.

        With a warm schema cache the first connection opens at EXECUTION — after
        `guard.require` passed and after the PDP already wrote an allow row. Reporting there
        would file a second row for a call that was decided.
        """
        governed()
        tools._default_schema = "public"
        monkeypatch.setitem(tools._schema_cache, "public.orders", (float("inf"), frozenset({"id"})))
        connect = MagicMock(side_effect=psycopg.OperationalError("connection dropped mid-query"))

        with pytest.raises(psycopg.Error):
            call_with("postgres_query", connect, query="SELECT id FROM public.orders")

        assert reports == []


class TestParseFailuresDoNotReport:
    def test_an_unparseable_query_is_not_reported(self, call_with, reports, governed, monkeypatch):
        # Routine model noise. Reporting each malformed query would fill the platform's audit
        # log and bury the infrastructure failures this endpoint exists to surface.
        #
        # `require` denies here because that is what an enforcing PDP does with `UNDETERMINED`
        # — and the denial is itself an `/evaluate` round trip, so the platform already has a
        # row for this call. A second one from `report_not_evaluated` would be a duplicate.
        governed()
        monkeypatch.setattr(
            tools.guard,
            "require",
            MagicMock(side_effect=PolicyDenied("the read set could not be determined")),
        )
        never = MagicMock(side_effect=AssertionError("should not connect"))

        result = call_with("postgres_query", never, query="SELECT FROM WHERE ((")

        assert reports == []
        assert "Error" in result
