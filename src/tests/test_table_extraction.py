"""What the query parser must enumerate, and what it must refuse to guess at.

A false negative here is a breach: a table missed is a table the PDP never decided on, and
the query runs anyway. So the cases below are weighted towards the shapes that *look*
harmless — the ones producing an empty table set, which does not mean "unknown" but
"this call touches nothing" and is decided on the function-level match alone.
"""

from __future__ import annotations

import pytest

from mcp_postgres.table_extraction import (
    TableExtractionError,
    extract_referenced_tables,
    normalize_table_name,
)


def tables(query: str, *, default_schema: str = "public", database: str | None = "mydb") -> set[str]:
    return set(extract_referenced_tables(query, default_schema=default_schema, database=database).tables)


class TestOrdinaryQueriesAreEnumerated:
    def test_simple_select(self):
        assert tables("SELECT * FROM users") == {"public.users"}

    def test_qualified_name_keeps_its_own_schema(self):
        assert tables("SELECT * FROM reporting.orders") == {"reporting.orders"}

    def test_join_names_both_sides(self):
        # The point of evaluating resources independently: a join must not launder access to
        # the more sensitive side.
        assert tables("SELECT * FROM orders o JOIN payroll p ON o.id = p.id") == {
            "public.orders",
            "public.payroll",
        }

    def test_subquery_and_union_arms(self):
        assert tables("SELECT * FROM (SELECT * FROM a) x UNION SELECT * FROM b") == {"public.a", "public.b"}

    def test_a_cte_alias_is_not_a_table_but_its_source_is(self):
        assert tables("WITH t AS (SELECT * FROM orders) SELECT * FROM t") == {"public.orders"}

    def test_a_qualified_name_matching_a_cte_is_still_a_real_table(self):
        # `WITH x AS (…) SELECT * FROM public.x` names a real table; only an unqualified
        # reference is the CTE.
        assert tables("WITH x AS (SELECT 1) SELECT * FROM public.x") == {"public.x"}

    def test_write_targets_are_enumerated_too(self):
        # Read-write deployments skip `validate_readonly_query` entirely, so the write target
        # has to appear as a resource of its own.
        assert tables("INSERT INTO audit_t SELECT * FROM src_t") == {"public.audit_t", "public.src_t"}

    def test_a_query_touching_no_table_is_an_honest_empty_set(self):
        # `[]` here is correct: `SELECT 1` really does touch nothing, and the PDP decides it
        # on the function-level match. This is the one place an empty set is not a failure.
        assert tables("SELECT 1") == set()


class TestTheSearchPathIsNotAssumed:
    def test_the_default_schema_is_supplied_not_hardcoded(self):
        """`public` is not a constant in PostgreSQL the way `dbo` is in SQL Server.

        A role with `search_path = reporting` reads `reporting.orders` from
        `SELECT * FROM orders`. Assuming `public` would let a rule allowing `public.orders`
        authorize that read.
        """
        assert tables("SELECT * FROM orders", default_schema="reporting") == {"reporting.orders"}


class TestConstructsThatWouldOtherwiseLookLikeTouchingNothing:
    """Every case here yields zero tables from a naive `find_all(exp.Table)` walk.

    That is the dangerous shape: an empty resource list is not "unknown", it is a positive
    claim that the call touches nothing, and it is decided on the function-level match alone.
    """

    @pytest.mark.parametrize(
        "query",
        [
            "EXPLAIN SELECT * FROM payroll",
            "EXPLAIN ANALYZE SELECT * FROM payroll",
            "SHOW search_path",
        ],
    )
    def test_explain_and_show_are_refused(self, query):
        # sqlglot models neither, falling back to an opaque `Command` whose body is an
        # uninterpreted string — and `validate_readonly_query` lets both through. A Postgres
        # plan carries row counts and filter values, so this is a real read.
        with pytest.raises(TableExtractionError, match="cannot be analyzed"):
            tables(query)

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM generate_series(1, 10)",
            "SELECT * FROM my_schema.my_func(1)",
            "SELECT * FROM t1, LATERAL my_func(t1.id) f",
            "SELECT * FROM ROWS FROM (generate_series(1, 3))",
        ],
    )
    def test_set_returning_functions_are_refused(self, query):
        # A set-returning function can wrap an arbitrary query and never becomes a table node.
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables(query)

    def test_dblink_in_the_projection_is_refused(self):
        """The sources allow-list cannot see this one: it reads from the SELECT list.

        `SELECT dblink('…', 'SELECT * FROM secret')` passes `validate_readonly_query` — its
        opening keyword is SELECT and the inner statement is a string literal, stripped before
        the semicolon check — and yields no tables at all, while reaching another server.
        """
        with pytest.raises(TableExtractionError, match="cannot be enumerated"):
            tables("SELECT dblink('host=x', 'SELECT * FROM secret')")


class TestNamesThatCannotBeExpressedAsAPolicyValue:
    def test_cross_database_is_refused(self):
        # PostgreSQL rejects this outright, but Redshift genuinely supports cross-database
        # reads — where a grant on `public.orders` must not also unlock another database's.
        with pytest.raises(TableExtractionError, match="Cross-database"):
            tables("SELECT * FROM otherdb.public.orders")

    def test_the_connections_own_database_is_reduced_not_refused(self):
        assert tables("SELECT * FROM mydb.public.orders") == {"public.orders"}

    def test_multi_statement_is_refused(self):
        # `validate_readonly_query` catches these first, but read-write deployments never run
        # that gate.
        with pytest.raises(TableExtractionError, match="Multi-statement"):
            tables("SELECT * FROM a; SELECT * FROM b")


class TestPostgresCaseFolding:
    def test_an_unquoted_name_folds_to_lower(self):
        # `FROM Payroll` reads the table `payroll`.
        assert tables("SELECT * FROM Payroll") == {"public.payroll"}

    def test_a_quoted_name_is_reported_as_merged(self):
        """`"Payroll"` and `payroll` are two different tables, and the emitted value is one.

        The platform's matcher is a case-insensitive glob, so no rule could tell them apart
        whatever this module emitted — lower-casing at least makes the value match the rule as
        a human would author it. What must not happen is the merge going unrecorded.
        """
        read_set = extract_referenced_tables('SELECT * FROM "Payroll"', default_schema="public")
        assert set(read_set.tables) == {"public.payroll"}
        assert set(read_set.case_merged) == {"public.Payroll"}

    def test_an_all_lowercase_quoted_name_is_not_flagged(self):
        read_set = extract_referenced_tables('SELECT * FROM "payroll"', default_schema="public")
        assert set(read_set.tables) == {"public.payroll"}
        assert set(read_set.case_merged) == set()


class TestRedshiftDialectIsRefusedNotGuessed:
    def test_redshift_only_syntax_does_not_parse_and_is_not_retried(self):
        """Two of the eleven deployments are Redshift, and `SELECT TOP n` is its common shape.

        Refusing here is deliberate — see trap 4 in the module docstring. It costs nothing
        today because both Redshift deployments are unconfigured, where the caller's
        `UNDETERMINED` is a no-op; had the tool returned early instead, this exact query would
        start failing in production on merge day.
        """
        with pytest.raises(TableExtractionError, match="Could not parse"):
            tables("SELECT TOP 10 * FROM sales")


class TestNormalizationMatchesBetweenPaths:
    def test_discovery_and_query_paths_agree(self):
        """A table listed under one spelling and authorized under another is a silent hole."""
        assert normalize_table_name("Public", "Orders") == "public.orders"
        assert normalize_table_name("public", "orders") in tables("SELECT * FROM public.orders")
