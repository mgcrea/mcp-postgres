"""Adversarial tests for column enumeration.

**Reviewed as a security artifact, like `test_table_extraction.py`.** Every assertion is an
exact set rather than a membership check: `assert "public.perfusers.dateofbirth" in columns`
would pass for an extractor that returned every column in the database and would say nothing
about the property that matters — that nothing was missed.

A false negative is a breach. A query that reads `nationalinsurancenumber` but whose extracted
set omits it gets authorized against the columns it did admit to, and the personal data comes
back.

`TestPostgresFolding` has no counterpart in the mssql suite. T-SQL is case-insensitive, so the
question does not arise there; here an unquoted `District` and a quoted `"District"` can name
two different columns, and getting the fold wrong either refuses a legitimate query or reports
a column the query never read.
"""

from __future__ import annotations

import pytest

from mcp_postgres.column_extraction import ColumnExtractionError, extract_referenced_columns

#: The PerfTrack shape the feature exists for: personal fields sharing a join with performance
#: data a district manager may legitimately read.
SCHEMA = {
    "public.perfusers": {"id", "fullname", "dateofbirth", "nationalinsurancenumber", "homeaddress"},
    "public.perfevents": {"id", "userid", "pph", "district"},
}


def columns(query: str, schema=None, default_schema="public", **kwargs) -> set[str]:
    return set(
        extract_referenced_columns(query, schema_map=schema or SCHEMA, default_schema=default_schema, **kwargs).columns
    )


class TestBasicShapes:
    def test_qualified_columns_resolve_through_aliases(self):
        assert columns(
            "SELECT u.fullname, e.pph FROM public.perfusers u JOIN public.perfevents e ON e.userid = u.id"
        ) == {
            "public.perfusers.fullname",
            "public.perfusers.id",
            "public.perfevents.pph",
            "public.perfevents.userid",
        }

    def test_unqualified_column_resolves_to_its_only_table(self):
        assert columns("SELECT fullname FROM public.perfusers") == {"public.perfusers.fullname"}

    def test_an_unqualified_table_binds_through_the_default_schema(self):
        # The PostgreSQL-specific trap: without `qualify(db=…)` a bare `perfusers` never binds
        # to the schema map, contributes zero columns, and is authorized as touching nothing.
        assert columns("SELECT fullname FROM perfusers") == {"public.perfusers.fullname"}

    def test_predicate_columns_count_as_reads(self):
        # A WHERE clause reads the column it filters on, and filtering on a value is a way to
        # learn it — so a column named only in a predicate must still be authorized.
        assert columns("SELECT e.pph FROM public.perfevents e WHERE e.district = 'D775'") == {
            "public.perfevents.pph",
            "public.perfevents.district",
        }

    def test_star_expands_to_every_column_including_the_personal_ones(self):
        assert columns("SELECT * FROM public.perfusers") == {
            "public.perfusers.id",
            "public.perfusers.fullname",
            "public.perfusers.dateofbirth",
            "public.perfusers.nationalinsurancenumber",
            "public.perfusers.homeaddress",
        }

    def test_alias_star_expands_too(self):
        assert columns("SELECT u.* FROM public.perfusers u") == {
            "public.perfusers.id",
            "public.perfusers.fullname",
            "public.perfusers.dateofbirth",
            "public.perfusers.nationalinsurancenumber",
            "public.perfusers.homeaddress",
        }


class TestPostgresFolding:
    SCHEMA = {"public.perfusers": frozenset({"id", "DateOfBirth"})}

    def _read(self, query: str):
        return extract_referenced_columns(query, schema_map=self.SCHEMA, default_schema="public")

    def test_a_quoted_mixed_case_column_resolves(self):
        # Declaring the map's names unquoted folds them, after which this raises *Unknown
        # column* for a column that plainly exists — a legitimate query refused.
        assert self._read('SELECT u."DateOfBirth" FROM perfusers u').columns == {"public.perfusers.dateofbirth"}

    def test_the_merge_the_lower_casing_performs_is_reported(self):
        # The policy value is lower-cased because the platform matches case-insensitively, so
        # no rule could express the distinction. Reporting it is what keeps that from being
        # silent — see trap 2 in table_extraction.py.
        assert self._read('SELECT u."DateOfBirth" FROM perfusers u').case_merged == {"public.perfusers.DateOfBirth"}

    def test_an_unquoted_reference_to_a_quoted_column_is_refused(self):
        # PostgreSQL folds it to `dateofbirth`, which is not the stored name — the real server
        # would error, and reporting a column the query cannot read would be worse than that.
        with pytest.raises(ColumnExtractionError):
            self._read("SELECT u.DateOfBirth FROM perfusers u")

    def test_a_folded_column_still_answers_to_an_unquoted_reference(self):
        read = extract_referenced_columns(
            "SELECT district FROM perfevents",
            schema_map={"public.perfevents": frozenset({"district"})},
            default_schema="public",
        )
        assert read.columns == {"public.perfevents.district"}
        assert read.case_merged == frozenset()


class TestFailsClosed:
    def test_a_table_missing_from_the_schema_map_is_refused(self):
        # The trap this module exists to close: qualify() returns ZERO columns for a table it
        # has no schema for, which on an allow-list reads as "touches nothing" and is allowed.
        with pytest.raises(ColumnExtractionError, match="unavailable for"):
            columns("SELECT * FROM public.unknown", schema={"public.perfusers": {"id"}})

    def test_an_empty_schema_entry_counts_as_missing(self):
        # `_load_schema_map` returns an empty set for a table `information_schema` said nothing
        # about, so the key is present while the schema is unknown. Every real table has at
        # least one column, so an empty entry must fail closed exactly like an absent one.
        with pytest.raises(ColumnExtractionError, match="unavailable for"):
            columns("SELECT * FROM public.perfusers", schema={"public.perfusers": set()})

    def test_an_ambiguous_column_is_refused(self):
        with pytest.raises(ColumnExtractionError):
            columns("SELECT id FROM public.perfusers u JOIN public.perfevents e ON e.id = u.id")

    def test_a_column_that_does_not_exist_is_refused(self):
        with pytest.raises(ColumnExtractionError):
            columns("SELECT nope FROM public.perfusers")

    def test_an_unanalyzable_source_is_refused_by_the_table_pass(self):
        # Inherited from `extract_referenced_tables`, which runs first: a set-returning
        # function produces no table node and so no trustworthy column set either.
        with pytest.raises(ColumnExtractionError.__mro__[1]):
            columns("SELECT * FROM public.perfevents e, LATERAL fn_secret(e.id)")

    def test_unparseable_query_is_refused(self):
        with pytest.raises(ColumnExtractionError.__mro__[1]):
            columns("SELECT FROM WHERE")


class TestCommonTableExpressions:
    def test_columns_read_inside_a_cte_body_are_counted(self):
        # The outer `SELECT *` reads the CTE, but the personal column is read by the CTE body
        # against the real table — which is the read that must be authorized.
        assert columns("WITH x AS (SELECT dateofbirth FROM public.perfusers) SELECT * FROM x") == {
            "public.perfusers.dateofbirth"
        }

    def test_a_cte_alias_never_becomes_a_resource(self):
        # `x.dateofbirth` would be a resource no rule could be written against, and would deny
        # under an allow-list default for a read that was already counted above.
        assert all(
            not column.startswith("x.")
            for column in columns("WITH x AS (SELECT dateofbirth FROM public.perfusers) SELECT * FROM x")
        )


class TestAggregatesAndSubqueries:
    def test_count_star_reads_no_named_column(self):
        # Its star is an aggregate argument, not a projection: it reads rows, not fields, and
        # whether those rows may be read at all is the table-level decision.
        assert columns("SELECT COUNT(*) FROM public.perfevents") == set()

    def test_scalar_subquery_columns_are_counted(self):
        assert columns("SELECT (SELECT MAX(pph) FROM public.perfevents) AS m FROM public.perfusers") == {
            "public.perfevents.pph"
        }

    def test_union_arms_are_both_counted(self):
        assert columns("SELECT fullname FROM public.perfusers UNION ALL SELECT district FROM public.perfevents") == {
            "public.perfusers.fullname",
            "public.perfevents.district",
        }


class TestTheRequirement:
    """The shape from the D775 requirement, end to end."""

    def test_the_legitimate_join_reads_no_personal_column(self):
        assert columns(
            "SELECT u.fullname, e.pph, e.district FROM public.perfusers u "
            "JOIN public.perfevents e ON e.userid = u.id WHERE e.district = 'D775'"
        ) == {
            "public.perfusers.fullname",
            "public.perfusers.id",
            "public.perfevents.pph",
            "public.perfevents.district",
            "public.perfevents.userid",
        }

    def test_the_same_join_reaching_for_personal_data_surfaces_it(self):
        assert "public.perfusers.nationalinsurancenumber" in columns(
            "SELECT u.nationalinsurancenumber, e.pph FROM public.perfusers u "
            "JOIN public.perfevents e ON e.userid = u.id"
        )


class TestSelectAliases:
    """A name introduced by `AS` is a projection, not a base-table read.

    `qualify` rewrites `ORDER BY COUNT(*)` into `ORDER BY n` for `COUNT(*) AS n`. That arrives
    as an unqualified column belonging to no table, and the fail-closed path refused the whole
    query — denying every aggregate-with-alias query, which is most of what a reporting
    assistant writes. Found against the live Sheffield replica, on the mssql side; the same
    rewrite happens here.
    """

    SCHEMA = {"public.employees": frozenset({"id", "districtid", "lastname", "birthdate"})}

    def _columns(self, query: str) -> set[str]:
        return set(
            extract_referenced_columns(query, schema_map=self.SCHEMA, default_schema="public", database=None).columns
        )

    def test_order_by_an_aggregate_alias_is_not_a_column_read(self):
        assert self._columns(
            "SELECT districtid, COUNT(*) AS n FROM public.employees GROUP BY districtid ORDER BY COUNT(*) DESC LIMIT 5"
        ) == {"public.employees.districtid"}

    def test_an_alias_does_not_hide_the_column_it_names(self):
        # The safety property: aliasing a denied column must not launder it out of the read
        # set. `birthdate` is still reported, from the projection that defines the alias.
        assert self._columns("SELECT birthdate AS n FROM public.employees ORDER BY n") == {"public.employees.birthdate"}

    def test_several_aliases_in_one_query(self):
        assert self._columns(
            "SELECT districtid AS d, COUNT(*) AS c FROM public.employees GROUP BY districtid ORDER BY c DESC"
        ) == {"public.employees.districtid"}

    def test_a_genuinely_unresolvable_column_still_refuses(self):
        # The alias skip must not become a general escape hatch: a bare name that matches no
        # alias and no column is still the guess an allow-list cannot make.
        with pytest.raises(ColumnExtractionError):
            self._columns("SELECT nosuchcolumn FROM public.employees")


class TestLaziness:
    def test_a_fully_qualified_query_never_resolves_the_search_path(self):
        # A query that names every schema does not depend on `search_path`, so it must not pay
        # a round trip nor be refused because the role's path happens to be ambiguous.
        def boom() -> str:
            raise AssertionError("resolved search_path for a fully qualified query")

        assert columns("SELECT fullname FROM public.perfusers", default_schema=boom) == {"public.perfusers.fullname"}
