"""Postgres database tools for MCP."""

import asyncio

import psycopg
from mcp.server.fastmcp import FastMCP

from ..audit import audit_log
from ..config import get_postgres_config
from ..sql_validation import ReadOnlyViolationError, validate_readonly_query

# Timeout configuration (seconds)
CONNECT_TIMEOUT = 10


def register_postgres_tools(mcp: FastMCP) -> None:
    """Register Postgres tools with the MCP server."""

    def _get_connection():
        """Create Postgres connection with timeout settings."""
        config = get_postgres_config()
        connect_kwargs = {"connect_timeout": CONNECT_TIMEOUT}
        if config.readonly:
            connect_kwargs["options"] = "-c default_transaction_read_only=on"
        return psycopg.connect(config.connection_string, **connect_kwargs)

    def _sync_postgres_query(query: str) -> str:
        """Synchronous Postgres query execution."""
        config = get_postgres_config()
        if config.readonly:
            try:
                validate_readonly_query(query)
            except ReadOnlyViolationError as e:
                return f"Error: {e}"

        with audit_log("postgres_query", {"query": query}):
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
        """Synchronous Postgres list tables."""
        with audit_log("postgres_list_tables", {"schema": schema}):
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

                    if not tables:
                        return f"No tables found in schema '{schema}'"

                    return f"Tables in schema '{schema}':\n" + "\n".join(f"  - {t}" for t in tables)

    def _sync_postgres_describe_table(table_name: str, schema: str) -> str:
        """Synchronous Postgres describe table."""
        with audit_log("postgres_describe_table", {"table_name": table_name, "schema": schema}):
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
                        return f"Table '{schema}.{table_name}' not found"

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

    @mcp.tool()
    async def postgres_query(query: str) -> str:
        """Execute a read-only SQL query on Postgres database.

        Args:
            query: SQL SELECT query to execute. Only SELECT statements are allowed.

        Returns:
            Query results as formatted text with column headers.
        """
        return await asyncio.to_thread(_sync_postgres_query, query)

    @mcp.tool()
    async def postgres_list_tables(schema: str = "public") -> str:
        """List all tables in the Postgres database.

        Args:
            schema: Schema name to list tables from. Defaults to 'public'.

        Returns:
            List of table names in the specified schema.
        """
        return await asyncio.to_thread(_sync_postgres_list_tables, schema)

    @mcp.tool()
    async def postgres_describe_table(table_name: str, schema: str = "public") -> str:
        """Get the schema/structure of a Postgres table.

        Args:
            table_name: Name of the table to describe.
            schema: Schema name. Defaults to 'public'.

        Returns:
            Table structure with column names, types, and constraints.
        """
        return await asyncio.to_thread(_sync_postgres_describe_table, table_name, schema)
