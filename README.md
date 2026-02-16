# mcp-postgres

MCP tool server providing read-only PostgreSQL database access for AI agents.

## Tools

| Tool | Description |
|------|-------------|
| `postgres_query` | Execute read-only SQL SELECT queries |
| `postgres_list_tables` | List all tables in a schema |
| `postgres_describe_table` | Get table structure (columns, types, constraints) |

## Quick Start

```bash
cp .env.example .env
# Edit .env with your Postgres connection details
make install
make server
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_USER` | `postgres` | Database user |
| `POSTGRES_PASSWORD` | | Database password |
| `POSTGRES_DB` | `postgres` | Database name |
| `MCP_PORT` | `8080` | Server port |

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/healthz` | GET | Health check for K8s probes |
| `/` | GET | Server info (name, version, transports) |
| `/mcp` | POST | MCP Streamable-HTTP transport |
| `/sse` | GET | MCP SSE transport (legacy) |

## Docker

```bash
make docker-build
make docker-run
```
