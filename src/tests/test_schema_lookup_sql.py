"""The literal SQL the column lookup sends.

Asserted as text, and in its own file, because every other test stubs the cursor — so the
statement is never run against a real server. On the mssql side that gap let a Postgres-shaped
row-value constructor ship green and break every table-referencing query in production while
`SELECT 1` kept working. The mirror-image mistake is available here: PostgreSQL *does* accept
`(a, b) IN ((…), (…))`, and **Redshift does not**, so the portable form is the one to keep.
"""

from __future__ import annotations

from mcp_postgres.tools.postgres import schema_lookup_sql


def test_uses_ord_pairs_not_a_row_value_constructor():
    sql, params = schema_lookup_sql(["public.perfevents", "public.perfusers"])
    assert "(lower(table_schema), lower(table_name))" not in sql
    assert "), (" not in sql
    assert sql.count("lower(table_schema) = %s AND lower(table_name) = %s") == 2
    assert " OR " in sql
    assert params == ["public", "perfevents", "public", "perfusers"]


def test_single_table_needs_no_or():
    sql, params = schema_lookup_sql(["public.perfevents"])
    assert " OR " not in sql
    assert params == ["public", "perfevents"]


def test_table_names_stay_bound_never_interpolated():
    # A table name comes out of the caller's own SQL, so it must ride as a bound parameter and
    # never appear in the statement text.
    sql, params = schema_lookup_sql(["public.perfevents"])
    assert "perfevents" not in sql
    assert "perfevents" in params
