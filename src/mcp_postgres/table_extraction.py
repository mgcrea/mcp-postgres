"""Enumerate every table a PostgreSQL query reads.

**This is the security-critical half of the guard, and it is the exact dual of
`sql_validation.py`.** That module is a deny-list over tokens — "does `DELETE` appear?" —
where over-approximating is safe and a false positive is an annoyed user. A table allow-list
needs the opposite: a *complete over-approximation of the read set*, where a false negative is
a breach. Missing one table means a query is authorized against a smaller set than it reads.

**Why a regex cannot do this.** `_strip_literals_and_comments` in `sql_validation.py` replaces
double-quoted identifiers with spaces, so `SELECT * FROM "Payroll"."Salaries"` has its table
names *deleted* before any scan could see them. Beyond that, CTEs, correlated subqueries,
`LATERAL`, derived tables, `UNION` arms and three-part names each defeat a `FROM\\s+(\\w+)`
pattern independently. Real parsing is not gold-plating here; it is the minimum that can be
correct.

Both gates run, in order: `validate_readonly_query` first (sqlglot parses `INSERT` perfectly
happily — enumeration is not policy), then this.

## Four PostgreSQL-specific traps, each verified against sqlglot 30.x

**1. `EXPLAIN` and `SHOW` parse to an opaque `Command` node holding zero tables.**
`validate_readonly_query` *allows* both as opening keywords, and sqlglot models neither: it
logs "contains unsupported syntax, falling back to parsing as a 'Command'" and hands back a
node whose body is an uninterpreted string. Walking `exp.Table` over it finds nothing, so
`EXPLAIN SELECT * FROM payroll` would submit an empty resource list — which does not mean
"unknown", it means *"this call touches nothing"*, and is decided on the function-level match
alone. A caller allowed to run the tool at all would have been handed the query plan for a
table policy never approved, and a Postgres plan carries row counts and filter values. Every
`Command` is therefore refused.

**2. PostgreSQL folds unquoted identifiers to lower case and preserves quoted ones.**
`FROM Payroll` reads the table `payroll`; `FROM "Payroll"` reads a *different* table named
`Payroll`, and both may exist at once. sqlglot preserves the source spelling either way, so
the fold has to be applied here from the `quoted` flag — see `_fold`. The emitted policy value
is then lower-cased regardless, and that last step deliberately merges the two. The reasoning:
the platform matches resource values with a **case-insensitive** glob, so no rule can express
the distinction no matter what this module emits. Emitting `public.Payroll` would only produce
a string no rule author would ever write — which denies under an allow-list and, worse, fails
to match under a deny rule. Lower-casing makes the value match the rule as authored.

The residual is real and is not silently swallowed: when a quoted identifier carries case that
the fold would otherwise have destroyed, its name is returned in `ReadSet.case_merged` so the
caller can put it in the audit record. A database holding both `payroll` and `"Payroll"` as
distinct tables cannot be governed correctly by this vocabulary, and the fix for that belongs
in the platform's matcher, not here.

**3. An unqualified name resolves through the connection's `search_path`, not through
`public`.** `mcp-mssql` can hardcode `dbo` because SQL Server effectively always uses it. Here
`search_path` is per-role and per-database (`ALTER ROLE svc_x SET search_path = reporting`),
and this server never sets it. Assuming `public` would let a rule allowing `public.orders`
authorize a read of `reporting.orders` — fail-open. So `default_schema` is a required argument
with no default: the caller resolves it from the live connection and refuses when it is
ambiguous. See `_resolve_default_schema` in `tools/postgres.py`. Pass it as a callable and the
probe happens only when a query actually contains an unqualified name — a fully qualified
query neither depends on `search_path` nor should be refused because the role's path is
ambiguous.

**4. Two of the eleven deployments are Amazon Redshift, not PostgreSQL.** Parsing stays on the
`postgres` dialect only, and Redshift-only syntax — `SELECT TOP 10 ...` is the common one —
raises `TableExtractionError` here rather than being re-parsed under the `redshift` dialect.
Falling back to a second dialect was rejected deliberately: a read set derived from whichever
grammar happened to accept the text is chosen by parser convenience rather than by the engine
that will actually run it, and a dialect that parses *more* can just as easily bind a source
differently and under-report. Refusing costs nothing today, because both Redshift deployments
are unconfigured and `UNDETERMINED` is a no-op for them (see `tools/postgres.py`); it only
takes effect once somebody enables policy there, at which point refusing to authorize a query
this module cannot read is the correct answer. If those two ever do get policy, the fix is an
explicit dialect setting driven by configuration — not a guess.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

DIALECT = "postgres"

#: Node types a `FROM` / `JOIN` / `LATERAL` may name and still be fully enumerable.
#:
#: `Table` is walked below; `Subquery`, `Select` and `Union` are recursed into, so their tables
#: surface too; `Values` and `Unnest` are constants that read nothing; `Lateral` is a wrapper
#: whose own source is checked on its own iteration.
#:
#: **Anything else is refused.** `FROM t1, LATERAL my_func(t1.id)` parses to a `Lateral` over
#: an `Anonymous` function call and produces *no table node at all*, so it would otherwise sail
#: through the walk while reading whatever it likes — a set-returning function can wrap an
#: arbitrary query. An allow-list of source shapes catches that; a deny-list of known-bad
#: function names could not.
_ANALYZABLE_SOURCES = (
    exp.Table,
    exp.Subquery,
    exp.Select,
    exp.Union,
    exp.Values,
    exp.Unnest,
    exp.Lateral,
)

#: Functions that read data the tree walk cannot see, wherever they appear in the statement.
#:
#: **This is a deny-list, and a deny-list is the wrong shape** — it is necessarily incomplete,
#: and the rest of this module is built on allow-lists precisely to avoid that. It is here
#: anyway because the alternative is nothing at all: the sources allow-list only inspects
#: `FROM`/`JOIN`/`LATERAL`, and these functions do their reading from the *projection*, where
#: no allow-list is possible because the set of legitimate functions in a `SELECT` list is
#: unbounded. `SELECT dblink('…', 'SELECT * FROM secret')` passes `validate_readonly_query`
#: (its opening keyword is `SELECT`, and the inner statement is a string literal that gets
#: stripped before the semicolon check) and yields zero tables — the "touches nothing"
#: fail-open again, this time reaching an entirely different server.
#:
#: Treated as *unenumerable*, not as denied: the honest statement is "this module cannot
#: establish what that reads", which is the same contract as every other raise here.
_OPAQUE_READERS = frozenset(
    {
        "dblink",
        "dblink_exec",
        "dblink_send_query",
        "dblink_fetch",
        "dblink_get_result",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "xpath_table",
    }
)


class TableExtractionError(Exception):
    """The read set could not be established with certainty.

    Always fatal to the call. Every raise site below is a case where the extractor cannot
    prove what a query touches — and an unprovable read set must never be handed to an
    allow-list check, because the check would then be authorizing a guess.
    """


@dataclass(frozen=True)
class ReadSet:
    """What a query reads, plus what had to be flattened to say it.

    `tables` are normalized policy values, lower-cased `schema.table`. `case_merged` holds the
    correctly-folded names whose case the normalization destroyed — quoted identifiers
    carrying upper case. It is never empty-checked for a decision; it exists so the merge lands
    in the audit record instead of happening silently. See trap 2 in the module docstring.
    """

    tables: frozenset[str]
    case_merged: frozenset[str]


def _fold(identifier: exp.Expression) -> str:
    """One identifier as PostgreSQL will actually resolve it.

    Unquoted identifiers fold to lower case; quoted ones are preserved exactly. sqlglot keeps
    the source spelling for both, so without this `FROM Payroll` and `FROM "Payroll"` are
    indistinguishable here — while the server treats them as two different tables.

    (Redshift folds quoted identifiers to lower case too, unless `enable_case_sensitive_
    identifier` is on. Applying the stricter PostgreSQL rule is the conservative choice: it
    can only ever report a name as *more* distinct than the engine would, never less.)
    """
    name = identifier.name
    return name if getattr(identifier, "quoted", False) else name.lower()


def _schema_resolver(default_schema: str | Callable[[], str]) -> Callable[[], str]:
    """Normalize `default_schema` to a callable invoked at most once, and only if needed.

    Laziness is not an optimization here, it is correctness in two directions. A query whose
    every table is schema-qualified does not depend on `search_path` at all, so it must not be
    refused because the role's path happens to be ambiguous — nor should it pay a database
    round trip to discover a value it will never use.
    """
    if not callable(default_schema):
        return lambda: default_schema

    cache: list[str] = []

    def resolve() -> str:
        if not cache:
            cache.append(default_schema())
        return cache[0]

    return resolve


def extract_referenced_tables(
    query: str, *, default_schema: str | Callable[[], str], database: str | None = None
) -> ReadSet:
    """Every table the query reads, as lower-cased `schema.table`.

    `default_schema` is what an unqualified name resolves to on *this* connection, read from
    its `search_path`. It has no default on purpose — see trap 3 in the module docstring. Pass
    a callable to defer resolving it until an unqualified name is actually seen.

    `database` is the connection's own database name. When given, a three-part name naming a
    *different* database is refused rather than silently reduced to `schema.table`. PostgreSQL
    rejects such a query outright, but Redshift genuinely supports cross-database reads, and on
    Redshift a grant on `public.orders` here would otherwise also unlock
    `otherdb.public.orders`, which policy never meant to cover.

    Raises `TableExtractionError` whenever the answer is not certain.
    """
    try:
        statements = sqlglot.parse(query, dialect=DIALECT)
    except SqlglotError as exc:
        raise TableExtractionError(f"Could not parse the query: {exc}") from exc
    except RecursionError as exc:
        # A deeply nested query can blow the parser's stack. Refusing is the only safe answer:
        # a half-walked tree is a partial read set.
        raise TableExtractionError("Query is too deeply nested to analyze") from exc

    real = [statement for statement in statements if statement is not None]
    if not real:
        raise TableExtractionError("Query contained no statement to analyze")
    if len(real) > 1:
        # `validate_readonly_query` rejects these first; this is defence in depth for any
        # future caller that forgets to run it, and for read-write deployments where that
        # gate does not run at all.
        raise TableExtractionError("Multi-statement queries cannot be analyzed")

    statement = real[0]

    # Trap 1. sqlglot emits `Command` for syntax it recognises but does not model — `EXPLAIN`
    # and `SHOW`, both of which `validate_readonly_query` lets through. Its contents are an
    # opaque string, so any table inside it is invisible to the walk below and the query would
    # be authorized as touching nothing.
    for command in statement.find_all(exp.Command):
        raise TableExtractionError(f"Query contains a construct that cannot be analyzed: {command.this}")

    _assert_analyzable_sources(statement)
    _assert_no_opaque_readers(statement)

    resolve_schema = _schema_resolver(default_schema)
    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}

    tables: set[str] = set()
    case_merged: set[str] = set()
    for table in statement.find_all(exp.Table):
        resolved = resolve_table_reference(
            table, cte_names=cte_names, resolve_default_schema=resolve_schema, database=database
        )
        if resolved is None:
            continue
        tables.add(resolved.lower())
        if resolved != resolved.lower():
            case_merged.add(resolved)
    return ReadSet(tables=frozenset(tables), case_merged=frozenset(case_merged))


def _assert_analyzable_sources(statement: exp.Expression) -> None:
    """Refuse any `FROM` / `JOIN` / `LATERAL` source that is not a table, subquery or constant.

    Walking `exp.Table` alone is not enough, because some sources never become a table node.
    `FROM t1, LATERAL my_func(t1.id)` parses to a `Lateral` over an `Anonymous`, so the query
    would otherwise be authorized against only the tables it *did* declare while the function
    read whatever it liked.
    """
    for node in statement.find_all(exp.From, exp.Join, exp.Lateral):
        source = node.this
        if source is None or not isinstance(source, _ANALYZABLE_SOURCES):
            raise TableExtractionError(
                "Query reads from a function or external source, which cannot be authorized: "
                f"{source.sql(dialect=DIALECT) if source is not None else node.sql(dialect=DIALECT)}"
            )


def _assert_no_opaque_readers(statement: exp.Expression) -> None:
    """Refuse the projection-side readers the sources allow-list cannot see.

    See `_OPAQUE_READERS` for why a deny-list is used here and only here.
    """
    for function in statement.find_all(exp.Anonymous):
        name = (function.name or "").lower()
        if name in _OPAQUE_READERS:
            raise TableExtractionError(f"Query calls {name}(), which reads data that cannot be enumerated")


def resolve_table_reference(
    table: exp.Table,
    *,
    cte_names: set[str],
    resolve_default_schema: Callable[[], str],
    database: str | None,
) -> str | None:
    """One table node to `schema.table`, folded but not yet lower-cased, or None if not a table.

    The return keeps PostgreSQL's own folding so the caller can see which names a lower-cased
    policy value would merge. Callers normalize with `.lower()`.
    """
    parts = list(table.parts)
    if not parts or not table.name:
        # A set-returning function — `generate_series(...)`, `ROWS FROM (...)`, a
        # schema-qualified `my_schema.my_func(1)` — is modelled as a Table with an empty name
        # (and sometimes no parts at all), with the call in a sibling node. Whatever it reads
        # is not enumerable here.
        raise TableExtractionError("Query reads from a function or external source, which cannot be authorized")

    if len(parts) > 3:
        raise TableExtractionError(f"Table names with more than three parts cannot be authorized: {table.sql(DIALECT)}")

    name = _fold(parts[-1])
    schema = _fold(parts[-2]) if len(parts) >= 2 else ""
    catalog = _fold(parts[-3]) if len(parts) >= 3 else ""

    if not schema and not catalog and name.lower() in cte_names:
        # A CTE reference, not a table. Only ever unqualified — `WITH x AS (…) SELECT * FROM
        # public.x` names a real `public.x` — so requiring both parts empty is what keeps a
        # CTE alias from shadowing a real table of the same name.
        return None

    if catalog and database and catalog.lower() != database.lower():
        raise TableExtractionError(f"Cross-database access cannot be authorized: {table.sql(DIALECT)}")

    return f"{schema or resolve_default_schema()}.{name}"


def normalize_table_name(schema: str, table: str) -> str:
    """The same normalization, for callers that already have the parts split.

    Used by the discovery tools, which get names from `information_schema` and from the
    caller's own arguments rather than from a parsed query. Both paths must produce
    byte-identical strings, or a table would be listed under one spelling and authorized under
    another.
    """
    return f"{schema.lower()}.{table.lower()}"
