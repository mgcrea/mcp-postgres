"""How the three Postgres tools behave once the guard is wired in.

The call *ordering* is under test here, not the policy semantics — those live in
mcp-policy-guard's own suite. Specifically: no query may reach the database before the
decision has been made, the resources submitted must be the ones intended, and a tool nobody
has configured must behave exactly as it did before the guard was a dependency.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import structlog
from mcp_policy_guard import Decision, PolicyDenied, PolicyUnavailable, Resource, is_guarded
from mcp_policy_guard.policy import _Undetermined

import mcp_postgres.tools.postgres as tools

ALLOWED = Decision(decision="allow", effect="allow", enforcing=True, reason="ok")

GUARD_VARS = (
    "MCP_REQUIRE_AUTH",
    "MCP_AUTH_ISSUER",
    "MCP_TOOL_ID",
    "MCP_POLICY_URL",
    "MCP_POLICY_FAIL_MODE",
)


class StubMCP:
    """Captures the tool functions `register_postgres_tools` decorates."""

    def __init__(self):
        self.tools: dict[str, object] = {}

    def tool(self, *_args, **_kwargs):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeCursor:
    def __init__(self, rows, description):
        self._rows = rows
        self.description = description
        self.executed: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def cursor(self):
        return self._cursor


@pytest.fixture(autouse=True)
def _reset_resolved_schema():
    """The resolved `search_path` is cached for the life of the process."""
    tools._default_schema = None
    yield
    tools._default_schema = None


@pytest.fixture(autouse=True)
def _unconfigured(monkeypatch):
    """Default every test to an unconfigured guard — the state of all eleven deployments."""
    for var in GUARD_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("POSTGRES_DB", "mydb")
    monkeypatch.setenv("POSTGRES_READONLY", "true")


@pytest.fixture
def db(monkeypatch):
    """Stub the driver, returning the cursor so a test can assert what actually ran."""

    def _install(rows=((1, "a"),), description=(("id",), ("name",))):
        cursor = FakeCursor(list(rows), description)
        monkeypatch.setattr(tools.psycopg, "connect", lambda *_a, **_k: FakeConn(cursor))
        return cursor

    return _install


@pytest.fixture
def no_column_resources(monkeypatch):
    """Take the column read set out of a test that is about something else.

    `_column_resources` consults the caller's cached snapshot first and returns nothing when it
    already denies a table — a real, documented short-circuit, and the cheapest way to hold the
    column pass still. Without it every enforcing test would also have to stub an
    `information_schema` read, and would be asserting two read sets while claiming to test one.
    """
    snapshot = MagicMock()
    snapshot.allows.return_value = False
    monkeypatch.setattr(tools.guard, "snapshot", MagicMock(return_value=snapshot))


@pytest.fixture
def never_connects(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("opened a database connection on a denied call")

    monkeypatch.setattr(tools.psycopg, "connect", _boom)


@pytest.fixture
def captured():
    """Every structlog event emitted during the test."""
    with structlog.testing.capture_logs() as records:
        yield records


@pytest.fixture
def call():
    """Invoke a registered tool by name."""

    def _call(name, **kwargs):
        stub = StubMCP()
        tools.register_postgres_tools(stub)
        return stub.tools[name](**kwargs)

    return _call


class TestUnconfiguredGuardIsANoOp:
    """The constraint protecting all eleven deployments, eight of them in production.

    Not one of them sets a single `MCP_*` variable, so adding this dependency must be
    invisible to every one. The failure mode is not hypothetical: mcp-policy-guard's own suite
    carries a regression test for an outage where a tool picked the guard up through a
    dependency update and started answering `401 Guard has no issuer configured`.
    """

    async def test_a_query_still_runs_with_no_policy_configured(self, call, db):
        cursor = db()
        # The real `Guard`, not a stub: the point is that the unconfigured path allows.
        result = await call("postgres_query", query="SELECT * FROM users")
        assert "id | name" in result
        assert cursor.executed[-1][0] == "SELECT * FROM users"

    async def test_a_query_the_parser_cannot_read_still_runs_when_unconfigured(self, call, db):
        """The single most important assertion in this repo.

        `SELECT TOP 10` is Redshift syntax that the postgres dialect cannot parse, and two
        production deployments point at Redshift. Because the tool submits `UNDETERMINED`
        rather than returning early, `Guard.evaluate` short-circuits on `policy_enabled`
        before it ever inspects the sentinel — so the query runs exactly as it did before.

        Had this been written as an early `return`, merging would have broken those two
        deployments the moment the pipeline published `:latest`.
        """
        cursor = db()
        result = await call("postgres_query", query="SELECT TOP 10 * FROM sales")
        assert "id | name" in result
        assert cursor.executed[-1][0] == "SELECT TOP 10 * FROM sales"

    async def test_explain_still_runs_when_unconfigured(self, call, db):
        cursor = db()
        result = await call("postgres_query", query="EXPLAIN SELECT * FROM payroll")
        assert "id | name" in result
        assert cursor.executed[-1][0] == "EXPLAIN SELECT * FROM payroll"

    async def test_no_search_path_probe_when_unconfigured(self, call, db):
        """An unconfigured deployment must not pay a round trip for a schema nobody uses."""
        cursor = db()
        await call("postgres_query", query="SELECT * FROM users")
        assert not any("current_schemas" in sql for sql, _ in cursor.executed)

    async def test_listing_and_describing_still_work(self, call, db):
        db(rows=[("orders",), ("payroll",)], description=(("table_name",),))
        listed = await call("postgres_list_tables", schema="public")
        assert "orders" in listed and "payroll" in listed

        db(rows=[("id", "integer", None, "NO", None)], description=(("column_name",),))
        described = await call("postgres_describe_table", table_name="orders", schema="public")
        assert "Table: public.orders" in described

    def test_the_guard_reports_itself_inert(self):
        from mcp_policy_guard import GuardConfig

        config = GuardConfig.from_env()
        # No bearer demanded, no PDP consulted. `sse_allowed` stays True, so these eleven
        # deployments keep the transport list they advertise today.
        assert config.require_auth is False
        assert config.policy_enabled is False
        assert config.sse_allowed is True


class TestTheDecisionComesBeforeTheQuery:
    async def test_a_denied_query_never_reaches_the_database(self, call, monkeypatch, never_connects):
        """A check that ran after the query has already read the data it exists to protect."""
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("no rule matched")))
        result = await call("postgres_query", query="SELECT * FROM payroll")
        assert result.startswith("Error:")

    async def test_a_denied_describe_never_reaches_the_database(self, call, monkeypatch, never_connects):
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("no rule matched")))
        result = await call("postgres_describe_table", table_name="payroll", schema="public")
        assert result == "Table 'public.payroll' not found"

    async def test_an_outage_is_not_reported_as_a_permissions_problem(self, call, monkeypatch, never_connects):
        """`PolicyUnavailable` subclasses `PolicyDenied`, so it fails closed — but saying "you
        lack permission" sends the user to request access they already hold."""
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyUnavailable("PDP unreachable")))
        result = await call("postgres_query", query="SELECT * FROM payroll")
        assert "temporarily unavailable" in result
        assert "do not have access" not in result


class TestTheResourcesSubmitted:
    """What a rule about this tool gets written about: `sql_table`, as `schema.table`."""

    async def test_a_query_submits_its_tables(self, call, db, monkeypatch):
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db()
        await call("postgres_query", query="SELECT * FROM orders o JOIN hr.payroll p ON o.id = p.id")

        function_name, resources = require.call_args.args
        assert function_name == "postgres_query"
        # Both sides of the join, independently — this is what stops a join laundering access.
        assert list(resources) == [
            Resource("sql_table", "hr.payroll"),
            Resource("sql_table", "public.orders"),
        ]

    async def test_a_describe_submits_the_named_table(self, call, db, monkeypatch):
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db(rows=[("id", "integer", None, "NO", None)], description=(("column_name",),))
        await call("postgres_describe_table", table_name="Orders", schema="Public")

        _, resources = require.call_args.args
        # Normalized the way a rule author writes it, and identically to the query path.
        assert list(resources) == [Resource("sql_table", "public.orders")]

    @pytest.mark.parametrize(
        "query",
        [
            "EXPLAIN SELECT * FROM payroll",
            "SHOW search_path",
            "SELECT TOP 10 * FROM sales",
            "SELECT dblink('host=x', 'SELECT * FROM secret')",
            "SELECT * FROM generate_series(1, 10)",
        ],
    )
    async def test_an_unreadable_query_submits_undetermined_not_an_empty_list(self, call, db, monkeypatch, query):
        """`[]` would mean "touches nothing" and be decided on the function-level match alone.

        Every query here yields zero tables from a naive walk, so `[]` would convert the
        parser's failure into an allow for any caller permitted to use the tool at all.
        """
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db()
        await call("postgres_query", query=query)

        _, resources = require.call_args.args
        assert isinstance(resources, _Undetermined), f"{query!r} submitted {resources!r}"

    async def test_a_query_touching_nothing_submits_an_empty_list(self, call, db, monkeypatch):
        """`SELECT 1` genuinely touches no table, so `[]` is the honest claim here.

        This is the one place an empty list is correct rather than a swallowed failure, and it
        is still not a free pass: under deny-by-default a caller no rule names is refused.
        """
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db()
        await call("postgres_query", query="SELECT 1")

        _, resources = require.call_args.args
        assert list(resources) == []


class TestSearchPathResolution:
    def _enforce(self, monkeypatch):
        monkeypatch.setattr(type(tools.guard.config), "policy_enabled", property(lambda _self: True))

    async def test_the_resolved_schema_qualifies_unqualified_names(self, call, db, monkeypatch, no_column_resources):
        """`public` is not assumed: the value comes from the live connection."""
        self._enforce(monkeypatch)
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db(rows=[(["reporting"],)], description=(("current_schemas",),))
        await call("postgres_query", query="SELECT * FROM orders")

        _, resources = require.call_args.args
        assert list(resources) == [Resource("sql_table", "reporting.orders")]

    async def test_an_ambiguous_search_path_is_undetermined(self, call, db, monkeypatch, no_column_resources):
        """With two schemas on the path, PostgreSQL picks whichever *contains* the table.

        That is not knowable without a catalogue lookup per name, so the read set is genuinely
        not established.
        """
        self._enforce(monkeypatch)
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db(rows=[(["svc_user", "public"],)], description=(("current_schemas",),))
        await call("postgres_query", query="SELECT * FROM orders")

        _, resources = require.call_args.args
        assert isinstance(resources, _Undetermined)

    async def test_a_qualified_name_is_unaffected_by_an_ambiguous_path(
        self, call, db, monkeypatch, no_column_resources
    ):
        self._enforce(monkeypatch)
        require = MagicMock(return_value=ALLOWED)
        monkeypatch.setattr(tools.guard, "require", require)
        db(rows=[(["svc_user", "public"],)], description=(("current_schemas",),))
        await call("postgres_query", query="SELECT * FROM hr.payroll")

        _, resources = require.call_args.args
        assert list(resources) == [Resource("sql_table", "hr.payroll")]


class TestDiscoveryHidesRatherThanRefuses:
    async def test_a_scoped_caller_simply_sees_fewer_tables(self, call, db, monkeypatch):
        """ "3 tables hidden" would teach the caller the names it cannot reach."""
        db(rows=[("orders",), ("payroll",)], description=(("table_name",),))
        monkeypatch.setattr(
            tools.guard,
            "filter_resources",
            lambda _kind, values, **_kw: [v for v in values if v != "payroll"],
        )
        result = await call("postgres_list_tables", schema="public")
        assert "orders" in result
        assert "payroll" not in result

    async def test_everything_hidden_is_byte_identical_to_an_empty_schema(self, call, db, monkeypatch):
        db(rows=[("payroll",)], description=(("table_name",),))
        monkeypatch.setattr(tools.guard, "filter_resources", lambda *_a, **_k: [])
        hidden = await call("postgres_list_tables", schema="public")

        db(rows=[], description=(("table_name",),))
        monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, values, **_kw: list(values))
        genuinely_empty = await call("postgres_list_tables", schema="public")

        assert hidden == genuinely_empty == "No tables found in schema 'public'"

    async def test_a_denied_describe_is_byte_identical_to_an_absent_table(self, call, db, monkeypatch):
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("nope")))
        denied = await call("postgres_describe_table", table_name="payroll", schema="public")

        monkeypatch.setattr(tools.guard, "require", MagicMock(return_value=ALLOWED))
        db(rows=[], description=(("column_name",),))
        absent = await call("postgres_describe_table", table_name="payroll", schema="public")

        assert denied == absent == "Table 'public.payroll' not found"

    async def test_a_function_level_denial_on_listing_says_so_plainly(self, call, db, monkeypatch):
        # Denied the function, not particular tables — naming no table is not an oracle, and
        # it stops the model retrying a listing it will never be allowed to make.
        db(rows=[("orders",)], description=(("table_name",),))
        monkeypatch.setattr(tools.guard, "filter_resources", MagicMock(side_effect=PolicyDenied("no rule matched")))
        result = await call("postgres_list_tables", schema="public")
        assert result.startswith("Error:")


class TestEveryToolCarriesTheBinding:
    def test_all_registered_tools_are_guarded(self):
        """The test that catches the fourth tool somebody adds later.

        Forgetting `@guarded` reviews cleanly and passes every single-user test. It only
        misbehaves when two callers share a session, at which point the second one is
        authorized against the first one's grants and the audit row names the wrong person.
        """
        stub = StubMCP()
        tools.register_postgres_tools(stub)
        assert set(stub.tools) == {
            "postgres_query",
            "postgres_list_tables",
            "postgres_describe_table",
        }
        assert [name for name, fn in stub.tools.items() if not is_guarded(fn)] == []


class TestAuditRecordsTheDecision:
    async def test_a_denial_is_audited_as_a_completed_call(self, call, monkeypatch, captured, never_connects):
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("no rule matched")))
        await call("postgres_query", query="SELECT * FROM payroll")

        entry = _last_record(captured)
        assert entry["decision"] == "deny"
        assert entry["reason"] == "no rule matched"
        # A denied call is a call that COMPLETED. Folding it into `success` would file every
        # policy refusal alongside genuine breakage and make both harder to find.
        assert entry["success"] is True

    async def test_an_allowed_query_records_its_resources(self, call, db, monkeypatch, captured):
        monkeypatch.setattr(tools.guard, "require", MagicMock(return_value=ALLOWED))
        db()
        await call("postgres_query", query="SELECT * FROM hr.payroll")

        entry = _last_record(captured)
        assert entry["decision"] == "allow"
        assert entry["resources"] == ["sql_table:hr.payroll"]

    async def test_a_case_merge_is_recorded_rather_than_silent(self, call, db, monkeypatch, captured):
        """Lower-casing `"Payroll"` to `public.payroll` merges two distinct PostgreSQL tables.

        The platform's matcher is case-insensitive so no rule could separate them anyway, but
        the merge must be visible in the record rather than happening quietly.
        """
        monkeypatch.setattr(tools.guard, "require", MagicMock(return_value=ALLOWED))
        db()
        await call("postgres_query", query='SELECT * FROM "Payroll"')

        merged = [r for r in captured if r.get("event") == "policy_value_case_merged"]
        assert merged and merged[-1]["names"] == ["public.Payroll"]
        # The submitted value is still the lower-cased one a rule author would write.
        assert _last_record(captured)["resources"] == ["sql_table:public.payroll"]

    async def test_an_undetermined_read_set_records_why(self, call, db, monkeypatch, captured):
        monkeypatch.setattr(tools.guard, "require", MagicMock(return_value=ALLOWED))
        db()
        await call("postgres_query", query="EXPLAIN SELECT * FROM payroll")

        assert _last_record(captured)["resources"] == ["<undetermined>"]
        undetermined = [r for r in captured if r.get("event") == "read_set_undetermined"]
        assert undetermined and "cannot be analyzed" in undetermined[-1]["reason"]

    async def test_a_query_the_database_rejects_is_a_failure_not_a_denial(self, call, monkeypatch, captured):
        """`decision: allow` with `success: false` — the two fields answer different questions."""
        monkeypatch.setattr(tools.guard, "require", MagicMock(return_value=ALLOWED))

        def _boom(*_a, **_k):
            raise RuntimeError("relation does not exist")

        monkeypatch.setattr(tools.psycopg, "connect", _boom)
        with pytest.raises(RuntimeError):
            await call("postgres_query", query="SELECT * FROM nope")

        entry = _last_record(captured)
        assert entry["decision"] == "allow"
        assert entry["success"] is False


def _last_record(records: list[dict]) -> dict:
    """The audit record for the call, whatever renderer structlog happens to be using.

    Captured at the structlog level rather than off stdout: this package configures a stdlib
    logger factory in `server.py`, so whether a record reaches stdout depends on logging
    handlers that are not this suite's business.
    """
    audit = [r for r in records if r.get("event") in ("tool_call", "tool_call_failed")]
    assert audit, f"no audit record emitted; saw {[r.get('event') for r in records]}"
    return audit[-1]
