"""Enumerate every column a PostgreSQL query reads.

The table allow-list in `table_extraction.py` cannot express the case this exists for: a table
that must stay *joinable* while some of its columns stay unreachable. The PerfTrack user table
is the live example — it carries national insurance number, date of birth, home address and
personal phone, and it sits on the same join as the performance data a district manager is
entitled to read. Denying the table breaks the legitimate query; allowing it exposes the
personal fields. Only a column-level read set separates the two.

**Same contract as the table extractor, for the same reason.** This feeds an allow-list, so a
false negative is a breach: a column we fail to enumerate is a column authorized against a
smaller read set than the query actually reads. Every uncertainty raises.

**The trap worth knowing about.** `qualify()` does not fail on a table it has no schema for —
`SELECT * FROM public.unknown` returns *zero* columns rather than raising, which on an
allow-list reads as "touches nothing" and is allowed. So the schema map is verified to cover
every referenced table *before* its output is trusted; that check, not qualify's own errors, is
what makes this safe.

## PostgreSQL differences from the mssql original

**Schemas are not a constant.** mssql resolves an unqualified name to `dbo`. Here it resolves
through `search_path`, so `default_schema` is threaded in and handed to `qualify` as its `db`
— without which a bare `orders` never binds to `public.orders` in the schema map, contributes
no columns, and lands in the "touches nothing" fail-open this module exists to close.

**Column names fold exactly as table names do.** An unquoted `District` reads `district`; a
quoted `"District"` reads a possibly different column. The emitted policy value is lower-cased
either way, for the reason trap 2 in `table_extraction.py` gives at length: the platform
matches resource values case-insensitively, so no rule could express the distinction whatever
this submitted. The merge is reported rather than hidden — see `ColumnReadSet.case_merged`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Set
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify

from .table_extraction import (
    DIALECT,
    TableExtractionError,
    extract_referenced_tables,
    resolve_table_reference,
)


class ColumnExtractionError(TableExtractionError):
    """The column read set could not be established with certainty.

    Subclasses `TableExtractionError` so every existing `except TableExtractionError` keeps
    failing closed on it — there is one fail-closed path through the tool, not two.
    """


@dataclass(frozen=True)
class ColumnReadSet:
    """What columns a query reads, plus what the normalization had to merge to say it.

    `columns` are normalized policy values, lower-cased `schema.table.column`. `case_merged`
    holds the correctly-folded names whose case that destroyed. Mirrors `ReadSet`, and for the
    same reason: the merge belongs in the audit record rather than in nobody's hands.
    """

    columns: frozenset[str]
    case_merged: frozenset[str]


def extract_referenced_columns(
    query: str,
    *,
    schema_map: Mapping[str, Set[str]],
    default_schema: str | Callable[[], str],
    database: str | None = None,
) -> ColumnReadSet:
    """Every column the query reads, as lower-cased `schema.table.column`.

    `schema_map` maps lower-cased `schema.table` to that table's column names, as
    `information_schema` reports them. It must cover every table the query references, or this
    raises — see the module docstring.

    Raises `ColumnExtractionError` whenever the answer is not certain.
    """
    resolve_schema = _schema_resolver(default_schema)
    referenced = extract_referenced_tables(query, default_schema=resolve_schema, database=database).tables

    # The load-bearing check. Without it an unknown table contributes no columns and the query
    # is authorized against an under-counted read set.
    #
    # An *empty* entry counts as missing, not as a table with no columns: every real table has
    # at least one, so an empty set means the catalogue read came back with nothing — a table
    # that does not exist, or one the tool's own credential cannot see. sqlglot happens to
    # raise on an empty column map today, but relying on that would leave this depending on an
    # internal error message for a fail-closed property.
    missing = sorted(table for table in referenced if not schema_map.get(table))
    if missing:
        raise ColumnExtractionError(
            "Column-level authorization needs the schema of every table read, and it is "
            f"unavailable for: {', '.join(missing)}"
        )

    try:
        statement = qualify(
            sqlglot.parse_one(query, dialect=DIALECT),
            schema=_nested_schema(schema_map, resolve_schema),
            # Without this a bare `orders` never binds to `public.orders` in the schema map:
            # qualify leaves it unqualified, the map lookup misses, and the query reports zero
            # columns — the "touches nothing" allow this module exists to prevent.
            db=resolve_schema() if _has_unqualified_table(query) else None,
            dialect=DIALECT,
        )
    except RecursionError as exc:
        raise ColumnExtractionError("Query is too deeply nested to analyze") from exc
    except SqlglotError as exc:
        # Includes the ambiguous-column and unknown-column cases, which qualify *does* raise
        # on. Both mean the same thing here: we cannot say which column was read.
        raise ColumnExtractionError(f"Could not resolve the columns this query reads: {exc}") from exc

    _assert_no_unexpanded_star(statement)

    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}
    sources = _source_map(statement, cte_names=cte_names, resolve_schema=resolve_schema, database=database)
    select_aliases = _select_aliases(statement)

    columns: set[str] = set()
    case_merged: set[str] = set()
    for column in statement.find_all(exp.Column):
        # A bare reference to a SELECT alias is a projection, not a read. `qualify` rewrites
        # `ORDER BY COUNT(*)` into `ORDER BY n` for `COUNT(*) AS n`, which arrives here as an
        # unqualified Column that belongs to no table — and `_table_for` would refuse the whole
        # query. Skipping it loses nothing: whatever the alias names was already counted where
        # it was defined, so `SELECT birthdate AS n ... ORDER BY n` still reports birthdate.
        if not column.table and column.name.lower() in select_aliases:
            continue
        table = _table_for(column, sources=sources, cte_names=cte_names)
        if table is None:
            continue
        name = _fold_column(column)
        qualified = f"{table}.{name}"
        columns.add(qualified.lower())
        if qualified != qualified.lower():
            case_merged.add(qualified)
    return ColumnReadSet(columns=frozenset(columns), case_merged=frozenset(case_merged))


def _schema_resolver(default_schema: str | Callable[[], str]) -> Callable[[], str]:
    """Normalize `default_schema` to a callable invoked at most once, and only if needed.

    One resolver is threaded through the table read, `qualify`'s `db` and the source map, so
    all three agree about what an unqualified name meant — and a `search_path` probe happens
    at most once per call rather than three times.
    """
    if not callable(default_schema):
        return lambda: default_schema

    cache: list[str] = []

    def resolve() -> str:
        if not cache:
            cache.append(default_schema())
        return cache[0]

    return resolve


def _has_unqualified_table(query: str) -> bool:
    """Whether any table reference in the query lacks a schema.

    Asked so a fully qualified query neither resolves nor pays for `search_path` — the same
    laziness `table_extraction` documents, kept here because `qualify`'s `db` argument is
    eager and would otherwise force the probe on every governed query.
    """
    try:
        statement = sqlglot.parse_one(query, dialect=DIALECT)
    except SqlglotError:  # pragma: no cover - the table extractor above already parsed it
        return True
    return any(len(table.parts) < 2 for table in statement.find_all(exp.Table))


def _fold_column(column: exp.Column) -> str:
    """One column name as PostgreSQL will resolve it: unquoted folds, quoted is preserved."""
    identifier = column.this
    if isinstance(identifier, exp.Identifier):
        return identifier.name if identifier.quoted else identifier.name.lower()
    return column.name.lower()


def _select_aliases(statement: exp.Expression) -> set[str]:
    """Every name introduced by `AS` in a projection, lowercased.

    Collected across all SELECTs rather than per-scope. That is deliberately loose in the safe
    direction only: the cost of over-collecting is skipping a bare column whose name matches an
    alias somewhere else in the query, and PostgreSQL resolves such a name in `ORDER BY` and
    `GROUP BY` to the alias anyway.
    """
    aliases: set[str] = set()
    for select in statement.find_all(exp.Select):
        for projection in select.expressions:
            if isinstance(projection, exp.Alias) and projection.alias:
                aliases.add(projection.alias.lower())
    return aliases


def _nested_schema(
    schema_map: Mapping[str, Set[str]],
    resolve_schema: Callable[[], str],
) -> dict[str, dict[str, dict[str, str]]]:
    """`{"public.orders": {"id"}}` to the nested shape sqlglot's optimizer expects.

    Types are irrelevant to us — only the column *names* decide anything — so every column is
    declared as the same placeholder type. A key with no schema component should not occur
    (`normalize_table_name` always emits both parts) but resolves through `search_path` rather
    than being dropped, because dropping it would silently shrink the map that the missing-table
    check above is measured against.

    **Every column name is quoted**, and that one character decides whether a mixed-case column
    can be read at all. sqlglot normalizes an unquoted map key by dialect, so declaring
    `DateOfBirth` bare folds it to `dateofbirth` — after which `SELECT u."DateOfBirth"` raises
    *Unknown column* and a legitimate query is refused for a column that plainly exists. Quoted,
    the catalogue's own spelling is preserved, and the resulting match is **exactly**
    PostgreSQL's: a column stored folded still answers to an unquoted reference, and one stored
    with case answers only to a quoted one. `information_schema` reports the stored spelling, so
    quoting it is right in both cases. Same reasoning as `_quoted_column` in `row_filters.py`.
    """
    nested: dict[str, dict[str, dict[str, str]]] = {}
    for qualified, column_names in schema_map.items():
        schema, _, table = qualified.rpartition(".")
        nested.setdefault(schema or resolve_schema(), {})[table] = {f'"{name}"': "UNKNOWN" for name in column_names}
    return nested


def _assert_no_unexpanded_star(statement: exp.Expression) -> None:
    """Refuse a `SELECT *` that qualify left in place.

    An unexpanded projection star means the read set is "whatever that table happens to
    contain", which is precisely what cannot be checked against an allow-list.

    `COUNT(*)` is deliberately *not* refused: its star is an argument to an aggregate and names
    no column, so it reads rows rather than fields. The table-level check already governs
    whether those rows may be read at all.
    """
    for select in statement.find_all(exp.Select):
        for projection in select.expressions:
            if isinstance(projection, exp.Star) or (
                isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star)
            ):
                raise ColumnExtractionError(
                    "Could not expand `SELECT *` into the columns it reads, so the query cannot be authorized"
                )


def _source_map(
    statement: exp.Expression,
    *,
    cte_names: set[str],
    resolve_schema: Callable[[], str],
    database: str | None,
) -> dict[str, str]:
    """Every table alias in the query, mapped to the real lower-cased `schema.table` it names.

    Keyed by `alias_or_name` because that is what `qualify` writes into each column's table
    component — an alias when the source has one, the bare table name when it does not.
    """
    sources: dict[str, str] = {}
    for table in statement.find_all(exp.Table):
        resolved = resolve_table_reference(
            table, cte_names=cte_names, resolve_default_schema=resolve_schema, database=database
        )
        if resolved is None:
            continue
        sources[table.alias_or_name.lower()] = resolved.lower()
    return sources


def _table_for(column: exp.Column, *, sources: dict[str, str], cte_names: set[str]) -> str | None:
    """The real table a qualified column belongs to, or None when it reads no base table.

    Returns None for a column qualified by a **CTE alias**. That is not a gap: qualify resolves
    the columns *inside* the CTE body against the real tables, so the underlying read is already
    counted, and emitting `x.dateofbirth` for a CTE named `x` would invent a resource no rule
    could ever be written against. Mirrors `resolve_table_reference` returning None for a CTE
    reference in the table extractor.
    """
    alias = (column.table or "").lower()
    if not alias:
        # qualify() qualifies every column it can resolve, so an unqualified one that survived
        # is one it could not attribute. Guessing which table it came from is exactly the guess
        # an allow-list must not authorize.
        raise ColumnExtractionError(f"Could not determine which table `{column.name}` is read from")

    if alias in sources:
        return sources[alias]
    if alias in cte_names:
        return None

    # An alias naming neither a known source nor a CTE. Should be unreachable after qualify, so
    # treat it as the extractor being wrong about the query rather than as a benign case.
    raise ColumnExtractionError(f"Could not resolve `{alias}.{column.name}` to a table")
