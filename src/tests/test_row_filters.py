"""Adversarial tests for row-predicate rewriting.

**A security artifact, like the two extraction suites.** The failure mode here is quieter than
theirs: a predicate that is dropped, mangled or applied to the wrong table does not raise — it
returns rows the caller was never entitled to, in a response that looks exactly like a
correctly scoped one.

So the bar for every case is: does the rewritten SQL still constrain every reference to the
governed table, and does anything that cannot be done exactly refuse instead?

The `TestPostgresDialect` class is the half that does not exist in the mssql original. T-SQL is
case-insensitive and forgives an unquoted identifier; PostgreSQL folds it, which turns three of
these from cosmetic into the difference between reading the right column and reading none.
"""

from __future__ import annotations

import pytest
import sqlglot

from mcp_postgres.row_filters import RowFilterError, RowPredicate, apply_row_filters

#: Keyed as `normalize_table_name` emits — always lower-cased — with the *values* keeping the
#: catalogue's own spelling, which is what the rewrite quotes.
SCHEMA = {
    "public.perfevents": {"id", "userid", "pph", "district"},
    "public.perfusers": {"id", "fullname", "DateOfBirth"},
}

DISTRICTS = (RowPredicate("public.perfevents", "district", "in_", ("D775",)),)


def rewrite(query: str, predicates=DISTRICTS, schema=None) -> str:
    return apply_row_filters(
        query,
        predicates,
        schema_map=schema or SCHEMA,
        default_schema="public",
        database="rgis",
    )


def wrappers(sql: str) -> int:
    """How many times the governed table was wrapped in a filtering subquery."""
    return sql.upper().count('WHERE "DISTRICT" IN')


class TestEveryReferenceIsConstrained:
    def test_a_simple_select(self):
        assert wrappers(rewrite("SELECT pph FROM public.perfevents")) == 1

    def test_an_unqualified_name_resolves_through_the_default_schema(self):
        # The predicate names `public.perfevents`; the query says `perfevents`. Without the
        # search_path resolution the two would never meet and the query would run unscoped.
        assert wrappers(rewrite("SELECT pph FROM perfevents")) == 1

    def test_preserves_the_alias_so_outer_references_still_resolve(self):
        out = rewrite("SELECT e.pph FROM public.perfevents e WHERE e.pph > 1")
        assert ") AS e" in out
        # The inner reference must NOT keep the alias, or it shadows the wrapper's.
        assert "public.perfevents AS e" not in out

    def test_each_arm_of_a_union_is_wrapped_independently(self):
        # One wrapper would leave the other arm reading every district.
        assert wrappers(rewrite("SELECT pph FROM public.perfevents UNION ALL SELECT pph FROM public.perfevents")) == 2

    def test_a_join_wraps_only_the_governed_table(self):
        out = rewrite("SELECT u.fullname, e.pph FROM public.perfusers u JOIN public.perfevents e ON e.userid = u.id")
        assert wrappers(out) == 1
        assert "public.perfusers AS u" in out

    def test_a_cte_body_is_wrapped(self):
        # The predicate has to reach inside the CTE: wrapping only the outer reference would
        # filter a result set that was already computed over every district.
        assert wrappers(rewrite("WITH x AS (SELECT pph FROM public.perfevents) SELECT * FROM x")) == 1

    def test_a_correlated_subquery_is_wrapped(self):
        out = rewrite(
            "SELECT u.fullname FROM public.perfusers u "
            "WHERE EXISTS (SELECT 1 FROM public.perfevents e WHERE e.userid = u.id)"
        )
        assert wrappers(out) == 1

    def test_a_lateral_join_is_wrapped(self):
        # PostgreSQL-only shape, and the one an mssql port would not think to try.
        out = rewrite(
            "SELECT u.fullname, e.pph FROM public.perfusers u, "
            "LATERAL (SELECT pph FROM public.perfevents WHERE userid = u.id) e"
        )
        assert wrappers(out) == 1

    def test_the_result_still_parses(self):
        out = rewrite("SELECT u.fullname, e.pph FROM public.perfusers u JOIN public.perfevents e ON e.userid = u.id")
        assert sqlglot.parse_one(out, dialect="postgres") is not None


class TestPostgresDialect:
    def test_the_predicate_column_is_quoted_with_the_catalogue_spelling(self):
        # `DateOfBirth` unquoted folds to `dateofbirth`, which is a different column — or no
        # column at all. The catalogue's spelling, quoted, is what PostgreSQL actually matches.
        out = rewrite(
            "SELECT fullname FROM public.perfusers",
            (RowPredicate("public.perfusers", "dateofbirth", "eq", ("1980-01-01",)),),
        )
        assert '"DateOfBirth" = ' in out

    def test_a_quoted_table_keeps_its_quoting_on_the_wrapper_alias(self):
        # `FROM "PerfEvents"` wrapped as `AS PerfEvents` folds to `perfevents`, and every
        # `"PerfEvents".col` in the outer query silently stops resolving.
        schema = {"public.perfevents": {"pph", "district"}}
        out = apply_row_filters(
            'SELECT * FROM "PerfEvents"',
            (RowPredicate("public.perfevents", "district", "in_", ("D775",)),),
            schema_map=schema,
            default_schema="public",
            database="rgis",
        )
        assert 'AS "PerfEvents"' in out

    def test_only_is_carried_into_the_wrapper(self):
        # Dropping `ONLY` would start reading every inheritance child the original excluded —
        # a widening, invisible in the result.
        out = rewrite("SELECT pph FROM ONLY public.perfevents")
        assert "FROM ONLY public.perfevents" in out

    def test_the_rewrite_reads_the_same_tables_it_started_with(self):
        # The structural check: a wrapper built from the wrong node would otherwise read as a
        # successful scope.
        out = rewrite("SELECT u.fullname, e.pph FROM public.perfusers u JOIN public.perfevents e ON e.userid = u.id")
        parsed = sqlglot.parse_one(out, dialect="postgres")
        names = {t.sql(dialect="postgres").lower() for t in parsed.find_all(sqlglot.exp.Table)}
        assert names == {"public.perfusers as u", "public.perfevents"}


class TestValueHandling:
    def test_quotes_are_escaped_not_interpolated(self):
        out = rewrite(
            "SELECT pph FROM public.perfevents",
            (RowPredicate("public.perfevents", "district", "in_", ("D'775",)),),
        )
        assert "'D''775'" in out
        assert sqlglot.parse_one(out, dialect="postgres") is not None

    def test_a_value_that_looks_like_sql_stays_a_literal(self):
        hostile = "') OR 1=1 --"
        out = rewrite(
            "SELECT pph FROM public.perfevents",
            (RowPredicate("public.perfevents", "district", "in_", (hostile,)),),
        )
        # It must appear as one escaped string literal, never as syntax.
        assert "OR 1=1" not in out.replace("''", "'").split("IN (")[0]
        assert sqlglot.parse_one(out, dialect="postgres") is not None

    def test_not_in_negates(self):
        out = rewrite(
            "SELECT pph FROM public.perfevents",
            (RowPredicate("public.perfevents", "district", "not_in", ("D775",)),),
        )
        assert "NOT" in out.upper()

    def test_eq_renders_an_equality(self):
        out = rewrite(
            "SELECT pph FROM public.perfevents",
            (RowPredicate("public.perfevents", "district", "eq", ("D775",)),),
        )
        assert "\"district\" = 'D775'" in out

    def test_two_predicates_on_one_table_both_apply(self):
        out = rewrite(
            "SELECT pph FROM public.perfevents",
            (
                RowPredicate("public.perfevents", "district", "in_", ("D775",)),
                RowPredicate("public.perfevents", "userid", "eq", ("7",)),
            ),
        )
        assert '"district" IN' in out
        assert '"userid" = ' in out


class TestFailsClosed:
    def test_a_column_the_table_does_not_have(self):
        with pytest.raises(RowFilterError, match="not a column"):
            rewrite(
                "SELECT pph FROM public.perfevents",
                (RowPredicate("public.perfevents", "nope", "in_", ("a",)),),
            )

    def test_a_table_whose_columns_are_unknown(self):
        with pytest.raises(RowFilterError, match="unavailable"):
            rewrite("SELECT pph FROM public.perfevents", schema={"public.perfevents": set()})

    def test_eq_with_more_than_one_value(self):
        with pytest.raises(RowFilterError, match="eq"):
            rewrite(
                "SELECT pph FROM public.perfevents",
                (RowPredicate("public.perfevents", "district", "eq", ("a", "b")),),
            )

    def test_an_empty_predicate(self):
        # The PDP denies rather than sending one, so reaching here means the two sides
        # disagree — and relying on `IN ()` being a syntax error is not a policy.
        with pytest.raises(RowFilterError, match="no values"):
            rewrite(
                "SELECT pph FROM public.perfevents",
                (RowPredicate("public.perfevents", "district", "in_", ()),),
            )

    def test_an_unknown_operator(self):
        with pytest.raises(RowFilterError, match="operator"):
            rewrite(
                "SELECT pph FROM public.perfevents",
                (RowPredicate("public.perfevents", "district", "like", ("a",)),),
            )

    def test_a_predicate_for_a_table_the_query_does_not_read(self):
        # The read set and the decision disagree; one of them is wrong, and running unscoped
        # is the wrong way to resolve it.
        with pytest.raises(RowFilterError, match="does not read"):
            rewrite("SELECT fullname FROM public.perfusers")


class TestNoPredicates:
    def test_returns_the_query_untouched(self):
        query = "SELECT pph FROM public.perfevents"
        assert apply_row_filters(query, (), schema_map=SCHEMA, default_schema="public", database="rgis") is query

    def test_never_resolves_the_search_path(self):
        # An ungoverned query must not pay a database round trip, nor be refused because the
        # role's search_path is ambiguous.
        def boom() -> str:
            raise AssertionError("resolved search_path for a query carrying no predicates")

        query = "SELECT pph FROM perfevents"
        assert apply_row_filters(query, (), schema_map=SCHEMA, default_schema=boom) is query
