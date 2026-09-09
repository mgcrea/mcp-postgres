"""Apply a policy row predicate to a query, by rewriting it.

The PDP decides *which rows* a caller may see and hands back a predicate — "district IN
('D775')". Something has to make the query obey it. Two options, and only one of them works:

**Verify** — refuse unless the query already restricts the column. Brittle (the model would
have to guess the caller's districts), and it turns a scoping rule into a puzzle for the LLM.

**Rewrite** — wrap each governed table in a subquery carrying the predicate. The model writes
whatever it likes; the predicate is applied underneath. That is what this module does:

    FROM sales.perfevents e  ->  FROM (SELECT * FROM sales.perfevents WHERE "district" IN ('D775')) AS e

Wrapping the *table node* rather than appending to the outer `WHERE` is what makes joins,
subqueries, `UNION` arms and CTE bodies work without special cases: every reference to the
table gets its own wrapper, and an outer `OR` cannot widen it back out.

**Fails closed on anything it cannot do exactly.** A predicate that could not be applied is
not a query that returns extra rows — it is a query that does not run.

## What the PostgreSQL port changes, and why

Ported from `mcp-mssql`, where the same module has been in production since the row-filter
release. The rewrite strategy transfers unchanged; three things about the *dialect* do not,
and each was a way to fail open or to break a legitimate query.

**1. Identifiers fold.** T-SQL is case-insensitive, so mssql can emit the policy's spelling of
a column verbatim and let the server sort it out. PostgreSQL folds an unquoted identifier to
lower case and preserves a quoted one, so emitting `District` unquoted reads the column
`district` — a different column, when the table really holds `"District"`. Both the predicate
column and the wrapper's alias are therefore emitted with their real spelling **quoted**: the
column's from `information_schema`, the alias's from the source query's own identifier node,
carrying its `quoted` flag across the rewrite. See `_quoted_column` and `_alias_identifier`.

**2. The read set is a `ReadSet`, and it needs a schema.** `extract_referenced_tables` here
takes a `default_schema` (an unqualified name resolves through `search_path`, not through a
constant) and returns tables already folded. `apply_row_filters` therefore takes the same
argument and threads it through both the before and after reads — the same resolver, so the
two comparisons cannot disagree about what an unqualified name meant.

**3. `SELECT *` inside the wrapper does not carry system columns.** `ctid`, `xmin` and friends
are not expanded by a star, so an outer query naming one against a wrapped table fails. That
is a refusal, not a widening, and it is the correct trade: the alternative is not wrapping.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from .table_extraction import (
    DIALECT,
    TableExtractionError,
    extract_referenced_tables,
    resolve_table_reference,
)


class RowFilterError(TableExtractionError):
    """A predicate could not be applied exactly, so the query must not run.

    Subclasses `TableExtractionError` so the tool's existing fail-closed handler catches it —
    one path out, not two.
    """


@dataclass(frozen=True)
class RowPredicate:
    """One predicate to apply to one table, as the guard delivers it."""

    table: str
    column: str
    operator: str
    values: tuple[str, ...]


def apply_row_filters(
    query: str,
    predicates: Sequence[RowPredicate],
    *,
    schema_map: Mapping[str, Set[str]],
    default_schema: str | Callable[[], str],
    database: str | None = None,
) -> str:
    """The query, rewritten so every predicate holds. Returns it unchanged when there are none.

    `schema_map` maps lower-cased `schema.table` to that table's column names as
    `information_schema` reports them — the real spellings, which is what lets the rewrite
    quote a mixed-case column correctly rather than folding it away.

    Raises `RowFilterError` whenever a predicate cannot be applied exactly.
    """
    if not predicates:
        return query

    before = extract_referenced_tables(query, default_schema=default_schema, database=database).tables

    try:
        tree = sqlglot.parse_one(query, dialect=DIALECT)
    except SqlglotError as exc:  # pragma: no cover - the extractor above already parsed it
        raise RowFilterError(f"Could not parse the query: {exc}") from exc

    by_table: dict[str, list[RowPredicate]] = {}
    for predicate in predicates:
        _assert_applicable(predicate, schema_map)
        by_table.setdefault(predicate.table.lower(), []).append(predicate)

    cte_names = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    # The same resolver instance the read above used, so an unqualified name cannot mean one
    # schema when the read set is taken and another when the predicate is matched to a table.
    resolve_schema = _schema_resolver(default_schema)

    # Collected before mutating: replacing a node while walking the same iterator would have
    # the walk descend into the subquery just created and wrap its table again, forever.
    targets: list[tuple[exp.Table, list[RowPredicate]]] = []
    for table in tree.find_all(exp.Table):
        resolved = resolve_table_reference(
            table, cte_names=cte_names, resolve_default_schema=resolve_schema, database=database
        )
        if resolved is None:
            continue
        applicable = by_table.get(resolved.lower())
        if applicable:
            targets.append((table, applicable))

    if not targets:
        # Every predicate named a table this query does not read. Applying nothing would run
        # the query unscoped, so refuse: the mismatch means the read set and the decision
        # disagree, and one of them is wrong.
        raise RowFilterError("The policy predicate names a table this query does not read")

    for table, applicable in targets:
        table.replace(_wrap(table, applicable, schema_map))

    rewritten = tree.sql(dialect=DIALECT)

    # The rewrite must not have introduced a source. Cheap, and the one check that would catch
    # a wrapper built from the wrong node — which would otherwise read as a successful scope.
    after = extract_referenced_tables(rewritten, default_schema=default_schema, database=database).tables
    if after != before:
        raise RowFilterError("Applying the policy predicate changed which tables the query reads")

    return rewritten


def _schema_resolver(default_schema: str | Callable[[], str]) -> Callable[[], str]:
    """Normalize `default_schema` to a callable invoked at most once, and only if needed.

    Mirrors the helper in `table_extraction`; duplicated rather than imported-and-shared
    because the caching is per call, and a resolver shared across calls would freeze a
    `search_path` probe that is deliberately re-attempted after a failure.
    """
    if not callable(default_schema):
        return lambda: default_schema

    cache: list[str] = []

    def resolve() -> str:
        if not cache:
            cache.append(default_schema())
        return cache[0]

    return resolve


def _assert_applicable(predicate: RowPredicate, schema_map: Mapping[str, Set[str]]) -> None:
    """Refuse a predicate the table cannot satisfy.

    A filter column that does not exist would make the rewritten query fail at the database
    with a syntax-ish error the model would then try to work around. Worse, a *typo* in a
    column name is a predicate that silently matches nothing on some engines rather than
    erroring — the fail-open direction.
    """
    columns = {column.lower() for column in schema_map.get(predicate.table.lower(), set())}
    if not columns:
        raise RowFilterError(f"Cannot apply a row filter to `{predicate.table}`: its columns are unavailable")
    if predicate.column.lower() not in columns:
        raise RowFilterError(
            f"The policy filters `{predicate.table}` on `{predicate.column}`, which is not a column of that table"
        )
    if not predicate.values:
        # The PDP denies rather than sending an empty predicate, so reaching here means the
        # two sides disagree. Refuse instead of rendering `IN ()`, which PostgreSQL rejects
        # outright — but relying on a syntax error to enforce a policy is not a plan.
        raise RowFilterError(f"The policy filter on `{predicate.column}` carries no values")
    if predicate.operator == "eq" and len(predicate.values) != 1:
        raise RowFilterError(f"The policy filter on `{predicate.column}` uses `eq` with {len(predicate.values)} values")
    if predicate.operator not in _OPERATORS:
        raise RowFilterError(f"Unsupported policy filter operator `{predicate.operator}`")


def _wrap(
    table: exp.Table,
    predicates: Sequence[RowPredicate],
    schema_map: Mapping[str, Set[str]],
) -> exp.Subquery:
    """`sales.t AS e` -> `(SELECT * FROM sales.t WHERE "col" IN (…)) AS e`.

    The alias is carried onto the wrapper and dropped from the inner reference, so every
    qualified reference in the outer query keeps resolving. An unaliased table is wrapped
    under its own bare name, which is what an unqualified reference already used.

    `table.copy()` carries the source's own modifiers into the wrapper — `ONLY t` stays
    `ONLY t`, so a rewrite cannot quietly start reading an inheritance child the original
    query excluded.
    """
    alias = _alias_identifier(table)

    inner_source = table.copy()
    inner_source.set("alias", None)

    inner = exp.select(exp.Star()).from_(inner_source)
    for predicate in predicates:
        inner = inner.where(_condition(predicate, schema_map))

    return exp.Subquery(this=inner, alias=exp.TableAlias(this=alias))


def _alias_identifier(table: exp.Table) -> exp.Identifier:
    """The name the wrapper must answer to, with the source's own quoting preserved.

    Rebuilding this from a string would lose the `quoted` flag, and losing it is not cosmetic:
    `FROM "MyTable"` wrapped as `… AS MyTable` folds to `mytable`, and every `"MyTable".col`
    in the outer query stops resolving. Copying the identifier node keeps whatever the caller
    wrote, which is exactly what the rest of their query is already written against.
    """
    existing = table.args.get("alias")
    if isinstance(existing, exp.TableAlias) and isinstance(existing.this, exp.Identifier):
        return existing.this.copy()

    parts = table.parts
    if not parts or not isinstance(parts[-1], exp.Identifier):
        raise RowFilterError("Cannot apply a row filter to a table reference with no name to alias")
    return parts[-1].copy()


def _quoted_column(predicate: RowPredicate, schema_map: Mapping[str, Set[str]]) -> exp.Column:
    """The predicate's column, spelled as the catalogue spells it and always quoted.

    Quoting the *real* spelling is exact in every case PostgreSQL can produce: a column
    created unquoted is stored folded, so `"district"` matches it, and one created as
    `"District"` is stored with its case, so `"District"` matches that. Emitting the policy
    author's spelling unquoted matches neither reliably — it folds, so a rule written against
    `District` would read `district` and, on a table holding both, read the wrong one.

    `_assert_applicable` has already established the column exists, case-insensitively; this
    recovers which of the catalogue's spellings it was.
    """
    wanted = predicate.column.lower()
    for column in schema_map.get(predicate.table.lower(), set()):
        if column.lower() == wanted:
            return exp.column(exp.to_identifier(column, quoted=True))
    # Unreachable: `_assert_applicable` runs first and raises on exactly this.
    raise RowFilterError(f"The policy filters `{predicate.table}` on `{predicate.column}`, which does not exist")


def _condition(predicate: RowPredicate, schema_map: Mapping[str, Set[str]]) -> exp.Expression:
    """One predicate as a condition, with values as literals sqlglot escapes itself."""
    column = _quoted_column(predicate, schema_map)
    literals = [exp.Literal.string(value) for value in predicate.values]
    return _OPERATORS[predicate.operator](column, literals)


#: Deliberately a closed table rather than an if-chain: an operator the guard invents but this
#: does not implement must raise in `_assert_applicable`, never fall through to "no predicate".
_OPERATORS = {
    "in_": lambda column, literals: column.isin(*literals),
    "not_in": lambda column, literals: exp.Not(this=column.isin(*literals)),
    "eq": lambda column, literals: exp.EQ(this=column, expression=literals[0]),
}
