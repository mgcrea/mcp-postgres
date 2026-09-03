# mcp-postgres

MCP tool server providing read-only PostgreSQL database access for AI agents.

## Tools

| Tool                      | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `postgres_query`          | Execute read-only SQL SELECT queries              |
| `postgres_list_tables`    | List all tables in a schema                       |
| `postgres_describe_table` | Get table structure (columns, types, constraints) |

## Quick Start

```bash
cp .env.example .env
# Edit .env with your Postgres connection details
make install
make server
```

## Environment Variables

| Variable            | Default     | Description                |
| ------------------- | ----------- | -------------------------- |
| `POSTGRES_HOST`     | `localhost` | PostgreSQL host            |
| `POSTGRES_PORT`     | `5432`      | PostgreSQL port            |
| `POSTGRES_USER`     | `postgres`  | Database user              |
| `POSTGRES_PASSWORD` |             | Database password          |
| `POSTGRES_DB`       | `postgres`  | Database name              |
| `POSTGRES_READONLY` | `true`      | Enforce read-only queries  |
| `MCP_TRANSPORT`     | `http`      | Transport: `http`, `stdio` |
| `MCP_PORT`          | `8080`      | Server port (http only)    |

## Authorization

Per-caller authentication and authorization come from
[`mcp-policy-guard`](https://pypi.org/project/mcp-policy-guard/). All of it is **off unless
configured** — with none of these set the server logs `guard_unconfigured` once at startup and
serves every request unauthenticated, exactly as it did before the dependency existed.

| Variable               | Default  | Description                                              |
| ---------------------- | -------- | -------------------------------------------------------- |
| `MCP_REQUIRE_AUTH`     | `false`  | Verify a caller bearer token. Disables the SSE transport |
| `MCP_AUTH_ISSUER`      |          | OIDC issuer whose JWKS verifies tokens                   |
| `MCP_TOOL_ID`          |          | This tool's id at the policy decision point              |
| `MCP_POLICY_URL`       |          | Policy decision point base URL                           |
| `MCP_POLICY_FAIL_MODE` | `closed` | Behaviour when the PDP is unreachable                    |

`MCP_REQUIRE_AUTH` and `MCP_AUTH_ISSUER` must be set together, and `MCP_POLICY_URL` requires
`MCP_REQUIRE_AUTH` — policy is evaluated per caller, so there is nothing to decide against
without authentication. The server refuses to start on either mismatch rather than appear to
enforce while accepting everyone.

> **`JWT_ISSUER` is not one of these.** Several deployments set it; nothing reads it, here or in
> the guard. The variable the guard reads is `MCP_AUTH_ISSUER`. Setting `JWT_ISSUER` has no
> effect whatsoever and does not enable authentication.

**A deny-by-default project blocks this tool until someone writes an explicit allow rule.**
Once `MCP_POLICY_URL` and `MCP_TOOL_ID` are set on a deployment, a caller no rule names is
refused. That is correct behaviour and it looks exactly like a regression.

Policy resources submitted per tool:

| Tool                      | Resources                                                         |
| ------------------------- | ----------------------------------------------------------------- |
| `postgres_query`          | one `sql_table` per table the query reads, as `schema.table`      |
| `postgres_list_tables`    | filtered, not refused — a scoped caller sees a smaller database   |
| `postgres_describe_table` | the named `sql_table`; a denial is indistinguishable from absence |

Tables are parsed out of the SQL with `sqlglot`. When the read set cannot be established — an
unparseable query, `EXPLAIN`/`SHOW`, a set-returning function, an ambiguous `search_path` — the
call submits `UNDETERMINED`, which denies where policy is enforcing and is a no-op where it is
not. See `src/mcp_postgres/table_extraction.py` for the reasoning and the PostgreSQL-specific
traps.

## Endpoints

| Path       | Method | Description                             |
| ---------- | ------ | --------------------------------------- |
| `/healthz` | GET    | Health check for K8s probes             |
| `/`        | GET    | Server info (name, version, transports) |
| `/mcp`     | POST   | MCP Streamable-HTTP transport           |
| `/sse`     | GET    | MCP SSE transport (legacy)              |

## Usage with `.mcp.json`

```json
{
  "mcpServers": {
    "postgres": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "MCP_TRANSPORT=stdio",
        "-e", "POSTGRES_HOST=host.docker.internal",
        "-e", "POSTGRES_PORT=5432",
        "-e", "POSTGRES_USER=postgres",
        "-e", "POSTGRES_PASSWORD=secret",
        "-e", "POSTGRES_DB=mydb",
        "harbor.rgis.dev/rgis-ai-agents/mcp-postgres"
      ]
    }
  }
}
```

> Use `host.docker.internal` to connect to a PostgreSQL instance running on the host machine.

## Docker

```bash
make docker-build
make docker-run
```
