"""Postgres database tools for MCP."""

import asyncio

import psycopg
import structlog
from mcp.server.mcpserver import MCPServer
from mcp_policy_guard import UNDETERMINED, Guard, PolicyDenied, Resource, audit_call, guarded

from ..config import get_config
from ..sql_validation import ReadOnlyViolationError, validate_readonly_query
from ..table_extraction import (
    TableExtractionError,
    extract_referenced_tables,
    normalize_table_name,
)

logger = structlog.get_logger()

# Timeout configuration (seconds)
CONNECT_TIMEOUT = 10

#: Selector kind the platform's policy store uses for SQL tables. One of a fixed vocabulary —
#: inventing a kind means no rule can ever match it, which on an allow-list denies nothing.
SQL_TABLE = "sql_table"

#: The schema label used to qualify unqualified table names when there is no PDP to consult.
#:
#: Not an authorization input: with `policy_enabled` false, `guard.require` short-circuits to
#: allow before it ever looks at the resources, so nothing is decided from this. It exists so
#: an unguarded deployment still writes a readable `schema.table` into its audit record instead
#: of a bare table name — and so that the eleven deployments running this image today, none of
#: which are configured, pay no round trip to resolve a `search_path` nobody is going to use.
UNGOVERNED_SCHEMA_LABEL = "public"

# Constructed once and shared: `Guard` is thread-safe, holds the httpx client and the
# per-caller snapshot cache, and `server.py` reads `guard.config` off it to build the routes.
#
# Constructing it is inert on its own. With no `MCP_*` variables set — which is every one of
# the eleven deployments running this image today — `GuardConfig.from_env()` logs
# `guard_unconfigured` once and every request is served exactly as it was before.
guard = Guard()

#: The connection's effective default schema, resolved once per process. See
#: `_resolve_default_schema`; only ever populated on a deployment that has a PDP configured.
_default_schema: str | None = None


def register_postgres_tools(mcp: MCPServer) -> None:
    """Register Postgres tools with the MCP server."""

    def _get_connection():
        """Create Postgres connection with timeout settings."""
        config = get_config()
        connect_kwargs = {"connect_timeout": CONNECT_TIMEOUT}
        if config.readonly:
            connect_kwargs["options"] = "-c default_transaction_read_only=on"
        return psycopg.connect(config.connection_string, **connect_kwargs)

    def _resolve_default_schema() -> str:
        """What an unqualified table name resolves to on this connection.

        `mcp-mssql` hardcodes `dbo` because SQL Server effectively always uses it. PostgreSQL
        has no such constant: an unqualified name is resolved through `search_path`, which is
        set per role and per database and which this server never sets. Assuming `public`
        would let a rule allowing `public.orders` authorize a read of `reporting.orders`.

        `current_schemas(false)` is asked rather than `SHOW search_path` because it returns the
        *resolved* list — `"$user"` already expanded, and dropped entirely when no such schema
        exists, which is the usual outcome for these service accounts. `pg_catalog` is excluded
        by the `false`.

        Exactly one entry is the only unambiguous answer. With two or more, PostgreSQL resolves
        an unqualified name to the first schema that actually *contains* the table, and knowing
        which that is needs a catalogue lookup per name — so the read set is genuinely not
        established and the caller turns this into `UNDETERMINED`.

        **This opens a connection before the policy decision, and is the only thing that
        does.** It reads a session setting — no catalogue, no user row — caches the answer for
        the life of the process, and runs only where a PDP is configured. The property that
        matters is untouched: the caller's own query still never executes until
        `guard.require` has passed.
        """
        global _default_schema
        if _default_schema is not None:
            return _default_schema

        with _get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_schemas(false)")
                row = cur.fetchone()

        schemas = [s for s in (row[0] if row and row[0] else []) if s]
        if len(schemas) != 1:
            # Not cached: an empty or ambiguous search_path is a fact about the role, but a
            # failed probe should not be frozen in for the life of the pod.
            raise TableExtractionError(
                f"The connection's search_path resolves to {len(schemas)} schemas "
                f"({', '.join(schemas) or 'none'}), so an unqualified table name is ambiguous. "
                "Qualify table names as schema.table."
            )

        _default_schema = schemas[0]
        logger.info("resolved_default_schema", schema=_default_schema)
        return _default_schema

    def _query_resources(query: str, record: dict):
        """The policy resources for a query — or `UNDETERMINED` when they cannot be established.

        Returns `(resources, detail)`. `detail` is the extractor's own explanation, kept
        separately because `guard.require` overwrites `record["reason"]` with the generic
        "could not be determined" and the specific cause is the useful half.

        **`UNDETERMINED` rather than an early `return`, and that choice is the whole reason
        this change is safe to merge.** `mcp-mssql` returns an error string directly on
        extraction failure. Under enforcement the two are identical. With the guard
        *unconfigured* they diverge completely: `Guard.evaluate` checks `policy_enabled`
        **before** it inspects the sentinel, so `UNDETERMINED` short-circuits to allow, while
        an early return refuses regardless of whether any policy exists.

        Eleven deployments run this image and **none** of them is configured; eight are in
        production namespaces and three track `:latest`, so landing on main is the deploy.
        An early return would mean every query this brand-new parser cannot handle starts
        failing across all of them on merge day — and there is a concrete, named example
        waiting: two of the eleven point at Amazon Redshift, where `SELECT TOP 10 …` does not
        parse under the postgres dialect at all. `UNDETERMINED` fails closed exactly where
        policy exists and stays a genuine no-op everywhere else.

        The exception handler is deliberately broad. `TableExtractionError` is the designed
        path, but sqlglot is new to this server and an unexpected `AttributeError` from a
        query shape nobody anticipated must degrade to "I do not know" — which is a no-op on
        an unconfigured deployment — rather than crash a tool that eight production services
        depend on.
        """
        try:
            # Passed as a callable so the probe happens only if the query actually contains an
            # unqualified name. A fully schema-qualified query does not depend on `search_path`
            # and must not be refused — nor pay a round trip — because the role's path is
            # ambiguous.
            default_schema = (
                _resolve_default_schema if guard.config.policy_enabled else (lambda: UNGOVERNED_SCHEMA_LABEL)
            )
            read_set = extract_referenced_tables(query, default_schema=default_schema, database=get_config().database)
        except Exception as exc:  # noqa: BLE001 — see the docstring; degrading beats crashing
            detail = str(exc) if isinstance(exc, TableExtractionError) else f"{type(exc).__name__}: {exc}"
            record["resources"] = ["<undetermined>"]
            # `audit_call` forwards only `decision`, `reason` and `resources` from its record,
            # so anything finer than that has to be its own event rather than an extra key —
            # which would be silently dropped.
            logger.warning("read_set_undetermined", tool="postgres_query", reason=detail)
            return UNDETERMINED, detail

        if read_set.case_merged:
            # A quoted identifier carrying upper case. The emitted value is lower-cased, which
            # merges `"Payroll"` with `payroll` — two distinct tables in PostgreSQL. The
            # platform matches resource values case-insensitively, so no rule could tell them
            # apart whatever this submitted; logging it is what keeps the merge from being
            # silent. See trap 2 in table_extraction.py.
            logger.warning("policy_value_case_merged", tool="postgres_query", names=sorted(read_set.case_merged))

        resources = [Resource(SQL_TABLE, table) for table in sorted(read_set.tables)]
        record["resources"] = [str(resource) for resource in resources]
        return resources, None

    def _sync_postgres_query(query: str) -> str:
        """Synchronous Postgres query execution.

        Order matters and is deliberate:

          1. `validate_readonly_query` — a deny-list over tokens. Runs first because sqlglot
             parses `DELETE` perfectly happily; enumeration is not policy. Skipped entirely
             on a read-write deployment, which is why step 2 re-checks multi-statement.
          2. `_query_resources` — the allow-list's input, from a real parse. Degrades to
             `UNDETERMINED` whenever the read set cannot be established.
          3. `guard.require` — the decision, made against the tables the model actually
             emitted. Anything an injected instruction persuaded the model to do is already in
             the query text by this point, which is exactly why the check lives here and not
             in the prompt.
          4. Execute.

        **The caller's query never runs until step 3 has passed.**

        Resources are `sql_table` values, lower-cased `schema.table`. That is the answer to
        "what would a rule about this tool be written about?" — a rule says which tables an
        agent may read. Rejected alternatives, so the next person does not have to re-derive
        them:

        * `[]` — would mean "this call touches nothing in particular" and authorize only at
          the function level. False here, and as a *fallback* on extraction failure it would
          convert the parser's failure into an allow. That is what `UNDETERMINED` is for.
        * `sql_column` alongside, as `mcp-mssql` submits — genuinely better granularity, and
          deliberately not done in this change. It needs an `information_schema` cache and
          star-expansion on the hot path of eight production services in a change whose main
          risk is already an SDK major-version port. `sql_table` is the useful unit on its
          own; columns can follow once this has proven itself.
        * `sql_schema` instead of per-table — coarser than the rules people actually want to
          write, and derivable from the table value anyway by a rule matching `hr.*`.
        """
        config = get_config()

        with audit_call("postgres_query", {"query": query}) as record:
            if config.readonly:
                try:
                    validate_readonly_query(query)
                except ReadOnlyViolationError as e:
                    record["decision"] = "deny"
                    record["reason"] = "read-only violation"
                    return f"Error: {e}"

            resources, undetermined_detail = _query_resources(query, record)

            try:
                decision = guard.require("postgres_query", resources)
            except PolicyDenied as denied:
                record["decision"] = "deny"
                record["reason"] = denied.reason
                if undetermined_detail and not denied.is_outage:
                    # Telling the model *why* its query could not be analyzed is not a leak —
                    # it wrote the query — and it is the difference between rephrasing the
                    # query and retrying the identical one in a loop.
                    return f"Error: {undetermined_detail}"
                # Unlike the discovery tools, naming the table here reveals nothing: the model
                # already named it. Being explicit tells the user something they can act on.
                return _denial_message(denied)

            record["decision"] = decision.decision

            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    columns = [desc[0] for desc in cur.description]
                    rows = cur.fetchall()

                    # Format output
                    result_lines = [" | ".join(columns)]
                    result_lines.append("-" * len(result_lines[0]))
                    for row in rows:
                        result_lines.append(" | ".join(str(val) for val in row))

                    return "\n".join(result_lines)

    def _sync_postgres_list_tables(schema: str) -> str:
        """Synchronous Postgres list tables, scoped to what the caller may see.

        Filtering rather than refusing is the point. A listing that said "3 tables hidden"
        would be an enumeration oracle — the caller learns the exact names of what it cannot
        reach, which is often the interesting half of the secret. A scoped caller simply sees
        a smaller database.

        No `search_path` question arises here: `schema` is an explicit parameter, so the
        resource is knowable trivially and exactly.
        """
        with audit_call("postgres_list_tables", {"schema": schema}) as record:
            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = %s
                        AND table_type = 'BASE TABLE'
                        ORDER BY table_name
                        """,
                        (schema,),
                    )
                    tables = [row[0] for row in cur.fetchall()]

            try:
                visible = guard.filter_resources(
                    SQL_TABLE,
                    tables,
                    function_name="postgres_list_tables",
                    key=lambda name: normalize_table_name(schema, name),
                )
            except PolicyDenied as denied:
                # Denied the *function*, not particular tables. Saying so plainly is not an
                # enumeration oracle — it names no table — and it stops the model retrying a
                # listing it will never be allowed to make.
                record["decision"] = "deny"
                record["reason"] = denied.reason
                return _denial_message(denied)

            record["decision"] = "allow" if len(visible) == len(tables) else "partial"
            record["resources"] = [normalize_table_name(schema, name) for name in visible]

            if not visible:
                # Byte-identical to the response for a genuinely empty schema.
                return f"No tables found in schema '{schema}'"

            return f"Tables in schema '{schema}':\n" + "\n".join(f"  - {t}" for t in visible)

    def _sync_postgres_describe_table(table_name: str, schema: str) -> str:
        """Synchronous Postgres describe table, authorized before it queries.

        On denial this returns the **same string** the tool already returns for a table that
        does not exist. Distinguishing the two would turn every denial into a confirmation
        that the table is real — the oracle `postgres_list_tables` filtering exists to avoid,
        reintroduced one name at a time.
        """
        qualified = normalize_table_name(schema, table_name)
        not_found = f"Table '{schema}.{table_name}' not found"

        with audit_call("postgres_describe_table", {"table_name": table_name, "schema": schema}) as record:
            record["resources"] = [qualified]
            try:
                decision = guard.require("postgres_describe_table", [Resource(SQL_TABLE, qualified)])
            except PolicyDenied as denied:
                # The real reason goes to the audit trail; the model is told nothing that
                # distinguishes "denied" from "absent".
                record["decision"] = "deny"
                record["reason"] = denied.reason
                return not_found

            record["decision"] = decision.decision

            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            column_name,
                            data_type,
                            character_maximum_length,
                            is_nullable,
                            column_default
                        FROM information_schema.columns
                        WHERE table_schema = %s
                        AND table_name = %s
                        ORDER BY ordinal_position
                        """,
                        (schema, table_name),
                    )
                    columns = cur.fetchall()

                    if not columns:
                        return not_found

                    result_lines = [f"Table: {schema}.{table_name}", ""]
                    result_lines.append("Column | Type | Nullable | Default")
                    result_lines.append("-" * 60)

                    for col in columns:
                        name, dtype, max_len, nullable, default = col
                        type_str = f"{dtype}({max_len})" if max_len else dtype
                        nullable_str = "YES" if nullable == "YES" else "NO"
                        default_str = str(default) if default else ""
                        result_lines.append(f"{name} | {type_str} | {nullable_str} | {default_str}")

                    return "\n".join(result_lines)

    # `@guarded` sits under `@mcp.tool()` on every handler, so the SDK registers the wrapper.
    #
    # **It is not optional and it is not decoration.** An MCP session is opened by whoever sent
    # `initialize`, and every later message is dispatched inside the task that spawned with it
    # — so a principal bound only by the ASGI middleware stays the session opener's for the
    # life of the session. Without this, two users sharing a session means the second one's
    # query is authorized against the first one's grants, and the audit row names the wrong
    # person. See `mcp_policy_guard.request` for the mechanism.
    #
    # `asyncio.to_thread` copies the context, so the principal bound here travels into the
    # synchronous body where `guard.require` is called.
    @mcp.tool()
    @guarded
    async def postgres_query(query: str) -> str:
        """Execute a read-only SQL query on Postgres database.

        Args:
            query: SQL SELECT query to execute. Only SELECT statements are allowed.

        Returns:
            Query results as formatted text with column headers.
        """
        return await asyncio.to_thread(_sync_postgres_query, query)

    @mcp.tool()
    @guarded
    async def postgres_list_tables(schema: str = "public") -> str:
        """List all tables in the Postgres database.

        Args:
            schema: Schema name to list tables from. Defaults to 'public'.

        Returns:
            List of table names in the specified schema.
        """
        return await asyncio.to_thread(_sync_postgres_list_tables, schema)

    @mcp.tool()
    @guarded
    async def postgres_describe_table(table_name: str, schema: str = "public") -> str:
        """Get the schema/structure of a Postgres table.

        Args:
            table_name: Name of the table to describe.
            schema: Schema name. Defaults to 'public'.

        Returns:
            Table structure with column names, types, and constraints.
        """
        return await asyncio.to_thread(_sync_postgres_describe_table, table_name, schema)


def _denial_message(denied: PolicyDenied) -> str:
    """What to tell the model when a call is refused.

    An outage is not a denial. `PolicyUnavailable` subclasses `PolicyDenied` so the fail-closed
    path cannot be forgotten, but saying "you do not have access to public.orders" while the
    decision point is down sends the user to raise an access request for a permission they
    already hold — and tells the model to stop trying something that will work again in a
    minute.
    """
    if denied.is_outage:
        return "Error: authorization is temporarily unavailable. Retry shortly; this is not a permissions problem."
    if denied.resources:
        names = ", ".join(sorted(r.split(":", 1)[-1] for r in denied.resources))
        return f"Error: You do not have access to {names}."
    return f"Error: {denied.reason}"
