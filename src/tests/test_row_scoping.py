"""The governed query path, end to end: columns submitted, predicates applied, scoping said.

**The failure this file exists to catch is the silent one.** Until this change `mcp-postgres`
accepted a row filter from the PDP and ran `cur.execute(query)` verbatim — every district's
rows, in a response indistinguishable from a correctly scoped one. The guard's own `RowFilter`
docstring names it: *"A tool that receives these and ignores them returns unscoped rows."*

So the assertions here are about the SQL that actually reached the cursor, never about the
decision object. A test that checks the tool was *told* to scope proves nothing.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import psycopg
import pytest
from mcp_policy_guard import Decision, Resource
from mcp_policy_guard.policy import RowFilter

from mcp_postgres.tools import postgres as tools

from .test_tool_authorization import StubMCP

PERFEVENTS = "public.perfevents"
DISTRICT_FILTER = RowFilter(
    resource=Resource("sql_table", PERFEVENTS),
    column="district",
    operator="in_",
    values=("D775",),
)


def allowed(*filters: RowFilter) -> Decision:
    return Decision(decision="allow", effect="allow", enforcing=True, reason="granted", filters=tuple(filters))


@pytest.fixture(autouse=True)
def _clean_schema_cache():
    tools._schema_cache.clear()
    tools._default_schema = None
    yield
    tools._schema_cache.clear()
    tools._default_schema = None


@pytest.fixture
def governed(monkeypatch):
    """A tool with a PDP configured and a snapshot that permits every table.

    Both are needed for the column pass to run at all: `_column_resources` returns `[]` when
    policy is disabled, and short-circuits again when the cached snapshot already denies a
    table. Enabling them explicitly is what makes these tests about the rewrite rather than
    about the short-circuits.
    """
    monkeypatch.setattr(tools.guard, "config", SimpleNamespace(policy_enabled=True))
    monkeypatch.setattr(tools.guard, "snapshot", lambda *_a, **_k: SimpleNamespace(allows=lambda *_: True))
    monkeypatch.setattr(tools.guard, "report_not_evaluated", lambda *_a, **_k: None)
    # The catalogue read is what `_load_schema_map` would otherwise open a connection for.
    monkeypatch.setitem(
        tools._schema_cache,
        PERFEVENTS,
        (time.monotonic() + 3600, frozenset({"id", "pph", "district"})),
    )
    tools._default_schema = "public"


@pytest.fixture
def executed(monkeypatch):
    """Run a query and return (result text, the SQL the cursor actually received)."""
    seen: list[str] = []

    class Cursor:
        description = (("pph",),)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, sql, params=None):
            seen.append(sql)

        def fetchall(self):
            return [(42,)]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(tools.psycopg, "connect", lambda *_a, **_k: Conn())

    def _run(query: str) -> tuple[str, str]:
        stub = StubMCP()
        tools.register_postgres_tools(stub)
        result = asyncio.run(stub.tools["postgres_query"](query=query))
        return result, seen[-1]

    return _run


class TestThePredicateReachesTheDatabase:
    def test_the_executed_sql_carries_the_predicate(self, governed, executed, monkeypatch):
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed(DISTRICT_FILTER))

        _result, sql = executed("SELECT pph FROM public.perfevents")

        assert "\"district\" IN ('D775')" in sql
        # The original, unscoped statement must not be what ran.
        assert sql != "SELECT pph FROM public.perfevents"

    def test_an_or_in_the_callers_query_cannot_widen_it_back_out(self, governed, executed, monkeypatch):
        # The reason the predicate is applied by *rewriting the table node* rather than by
        # appending to the outer WHERE: an outer `OR` would defeat the latter entirely.
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed(DISTRICT_FILTER))

        _result, sql = executed("SELECT pph FROM public.perfevents WHERE district = 'D999' OR 1=1")

        assert sql.index('"district" IN') < sql.index("OR")

    def test_a_decision_with_no_filters_runs_the_query_untouched(self, governed, executed, monkeypatch):
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed())

        _result, sql = executed("SELECT pph FROM public.perfevents")

        assert sql == "SELECT pph FROM public.perfevents"


class TestScopingIsSaid:
    def test_the_notice_is_appended_after_the_rows(self, governed, executed, monkeypatch):
        # After, not before: it matters most when the row set is empty, and that is exactly
        # when there is otherwise no output to hang the explanation on.
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed(DISTRICT_FILTER))

        result, _sql = executed("SELECT pph FROM public.perfevents")

        assert "Scoped by access policy" in result
        assert result.index("Scoped by access policy") > result.index("pph")

    def test_an_unscoped_query_says_nothing(self, governed, executed, monkeypatch):
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed())

        result, _sql = executed("SELECT pph FROM public.perfevents")

        assert "Scoped by access policy" not in result


class TestFailsClosed:
    def test_a_predicate_that_cannot_be_applied_refuses_the_call(self, governed, monkeypatch):
        # A column the table does not have. The query must not run — returning extra rows is
        # the one outcome worse than an error.
        never = MagicMock(side_effect=AssertionError("executed a query whose predicate failed"))
        monkeypatch.setattr(tools.psycopg, "connect", never)
        monkeypatch.setattr(
            tools.guard,
            "require",
            lambda *_a, **_k: allowed(RowFilter(Resource("sql_table", PERFEVENTS), "nosuchcolumn", "in_", ("D775",))),
        )

        stub = StubMCP()
        tools.register_postgres_tools(stub)
        result = asyncio.run(stub.tools["postgres_query"](query="SELECT pph FROM public.perfevents"))

        assert result.startswith("Error: ")
        assert "not a column" in result

    def test_a_filter_on_a_column_resource_is_refused_not_ignored(self, governed, monkeypatch):
        # A `sql_column` predicate narrows a thing that yields no rows of its own. Skipping it
        # would be the fail-open the whole module exists to avoid.
        never = MagicMock(side_effect=AssertionError("executed a query whose predicate was ignored"))
        monkeypatch.setattr(tools.psycopg, "connect", never)
        monkeypatch.setattr(
            tools.guard,
            "require",
            lambda *_a, **_k: allowed(
                RowFilter(Resource("sql_column", "public.perfevents.district"), "district", "in_", ("D775",))
            ),
        )

        stub = StubMCP()
        tools.register_postgres_tools(stub)
        result = asyncio.run(stub.tools["postgres_query"](query="SELECT pph FROM public.perfevents"))

        assert "sql_column" in result

    def test_a_catalogue_failure_during_the_rewrite_does_not_report_twice(self, governed, monkeypatch):
        """Post-decision: the PDP already wrote its allow row, so a report here files a second.

        Reaching this needs the one shape where the rewrite reads a catalogue the column pass
        did not already warm: a **stale snapshot that denies** while the live PDP allows with a
        filter. `_column_resources` short-circuits on the snapshot and loads nothing, so
        `_apply_policy_filters` is the first thing to want a schema — after the decision.
        """
        reports: list[tuple] = []
        monkeypatch.setattr(tools.guard, "report_not_evaluated", lambda *a, **_k: reports.append(a))
        monkeypatch.setattr(tools.guard, "snapshot", lambda *_a, **_k: SimpleNamespace(allows=lambda *_: False))
        tools._schema_cache.clear()
        monkeypatch.setattr(
            tools.psycopg, "connect", MagicMock(side_effect=psycopg.OperationalError("connection refused"))
        )
        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: allowed(DISTRICT_FILTER))

        stub = StubMCP()
        tools.register_postgres_tools(stub)
        result = asyncio.run(stub.tools["postgres_query"](query="SELECT pph FROM public.perfevents"))

        assert result.startswith("Error: ")
        assert "not run" in result
        assert reports == []


class TestColumnResources:
    def test_columns_are_submitted_beside_the_tables(self, governed, executed, monkeypatch):
        require = MagicMock(return_value=allowed())
        monkeypatch.setattr(tools.guard, "require", require)

        executed("SELECT pph FROM public.perfevents")

        _, resources = require.call_args.args
        assert list(resources) == [
            Resource("sql_table", PERFEVENTS),
            Resource("sql_column", "public.perfevents.pph"),
        ]

    def test_an_unconfigured_guard_submits_no_columns_and_reads_no_catalogue(self, executed, monkeypatch):
        # The constraint protecting the eleven deployments running this image, none of which
        # sets a single `MCP_*` variable: the column pass must cost them nothing at all.
        require = MagicMock(return_value=allowed())
        monkeypatch.setattr(tools.guard, "require", require)
        monkeypatch.setattr(
            tools.guard,
            "snapshot",
            MagicMock(side_effect=AssertionError("consulted the snapshot on an unconfigured tool")),
        )

        executed("SELECT pph FROM public.perfevents")

        _, resources = require.call_args.args
        assert all(resource.kind == "sql_table" for resource in resources)
