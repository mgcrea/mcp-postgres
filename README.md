# mcp-postgres

<!-- markdownlint-disable MD033 -->
<p align="center">
  <a href="https://github.com/mgcrea/mcp-postgres/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/mgcrea/mcp-postgres/ci.yml?style=for-the-badge&branch=main" alt="build status" />
  </a>
  <a href="https://ghcr.io/mgcrea/mcp-postgres">
    <img src="https://img.shields.io/badge/ghcr.io-mgcrea%2Fmcp--postgres-blue?style=for-the-badge" alt="docker image" />
  </a>
  <a href="https://github.com/mgcrea/mcp-postgres">
    <img src="https://img.shields.io/github/license/mgcrea/mcp-postgres?style=for-the-badge" alt="license" />
  </a>
  <a href="https://github.com/mgcrea/mcp-postgres">
    <img src="https://img.shields.io/badge/python-3.12+-blue?style=for-the-badge" alt="python version" />
  </a>
</p>
<!-- markdownlint-enable MD033 -->

MCP tool server providing PostgreSQL database access for AI agents.

## Tools

| Tool                      | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `postgres_query`          | Execute SQL queries (read-only by default)        |
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

> Set `POSTGRES_READONLY=false` to enable read/write mode (INSERT, UPDATE, DELETE, etc.).

## Endpoints

| Path       | Method | Description                             |
| ---------- | ------ | --------------------------------------- |
| `/healthz` | GET    | Health check for K8s probes             |
| `/`        | GET    | Server info (name, version, transports) |
| `/mcp`     | POST   | MCP Streamable-HTTP transport           |
| `/sse`     | GET    | MCP SSE transport (legacy)              |

## Usage with `.mcp.json`

<!-- prettier-ignore -->
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
        "ghcr.io/mgcrea/mcp-postgres"
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
