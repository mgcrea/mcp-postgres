"""Tests for SQL read-only validation — PostgreSQL variant."""

import pytest

from sql_validation import ReadOnlyViolationError, validate_readonly_query


class TestAllowedQueries:
    """Queries that SHOULD be allowed through validation."""

    def test_simple_select(self):
        validate_readonly_query("SELECT * FROM users")

    def test_select_with_where(self):
        validate_readonly_query("SELECT id, name FROM users WHERE active = true")

    def test_select_with_join(self):
        validate_readonly_query("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id")

    def test_select_with_subquery(self):
        validate_readonly_query("SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)")

    def test_cte_with_select(self):
        validate_readonly_query(
            "WITH active_users AS (SELECT * FROM users WHERE active = true) SELECT * FROM active_users"
        )

    def test_multiple_ctes(self):
        validate_readonly_query("WITH cte1 AS (SELECT 1 AS a), cte2 AS (SELECT 2 AS b) SELECT * FROM cte1, cte2")

    def test_select_with_trailing_semicolon(self):
        validate_readonly_query("SELECT 1;")

    def test_select_with_string_containing_keywords(self):
        validate_readonly_query("SELECT * FROM logs WHERE message = 'DELETE FROM users'")

    def test_select_with_dollar_quoted_string(self):
        validate_readonly_query("SELECT * FROM logs WHERE message = $$DELETE FROM users$$")

    def test_select_with_tagged_dollar_quote(self):
        validate_readonly_query("SELECT * FROM logs WHERE message = $tag$DROP TABLE$tag$")

    def test_select_with_comment_containing_keywords(self):
        validate_readonly_query("/* This deletes nothing */ SELECT * FROM users")

    def test_select_with_line_comment(self):
        validate_readonly_query("-- just a comment\nSELECT * FROM users")

    def test_select_with_double_quoted_identifier(self):
        validate_readonly_query('SELECT "DELETE", "DROP" FROM "INSERT"')

    def test_explain_select(self):
        validate_readonly_query("EXPLAIN SELECT * FROM users")

    def test_explain_analyze_select(self):
        validate_readonly_query("EXPLAIN ANALYZE SELECT * FROM users")

    def test_show_statement(self):
        validate_readonly_query("SHOW search_path")

    def test_show_server_version(self):
        validate_readonly_query("SHOW server_version")

    def test_select_count(self):
        validate_readonly_query("SELECT COUNT(*) FROM users")

    def test_select_with_aggregate_functions(self):
        validate_readonly_query(
            "SELECT department, AVG(salary) FROM employees GROUP BY department HAVING AVG(salary) > 50000"
        )

    def test_select_case_variations(self):
        validate_readonly_query("select * from users")
        validate_readonly_query("Select * From Users")

    def test_select_with_leading_whitespace(self):
        validate_readonly_query("   SELECT * FROM users")

    def test_select_with_escaped_quotes_in_string(self):
        validate_readonly_query("SELECT * FROM users WHERE name = 'O''Brien'")


class TestBlockedQueries:
    """Queries that MUST be blocked by validation."""

    def test_insert(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("INSERT INTO users (name) VALUES ('test')")

    def test_update(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("UPDATE users SET name = 'test' WHERE id = 1")

    def test_delete(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("DELETE FROM users WHERE id = 1")

    def test_drop_table(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("DROP TABLE users")

    def test_alter_table(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("ALTER TABLE users ADD COLUMN age INTEGER")

    def test_create_table(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("CREATE TABLE evil (id INTEGER)")

    def test_truncate(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("TRUNCATE TABLE users")

    def test_grant(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("GRANT ALL ON users TO evil_user")

    def test_revoke(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("REVOKE ALL ON users FROM some_user")

    # --- PostgreSQL-specific attacks ---

    def test_copy_to(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("COPY users TO '/tmp/data.csv'")

    def test_copy_from(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("COPY users FROM '/tmp/data.csv'")

    def test_do_block(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("DO $$ BEGIN DELETE FROM users; END $$")

    def test_select_into(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("SELECT * INTO new_table FROM users")

    def test_call_procedure(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("CALL delete_inactive_users()")

    def test_vacuum(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("VACUUM users")

    def test_reindex(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("REINDEX TABLE users")

    def test_lock_table(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("LOCK TABLE users IN ACCESS EXCLUSIVE MODE")

    def test_set_parameter(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("SET default_transaction_read_only = off")

    def test_refresh_materialized_view(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("REFRESH MATERIALIZED VIEW my_view")

    def test_prepare_insert(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("PREPARE insert_user AS INSERT INTO users VALUES ($1)")

    def test_listen(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("LISTEN my_channel")

    def test_notify(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("NOTIFY my_channel, 'payload'")

    # --- Bypass attempts ---

    def test_comment_before_insert(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("/* harmless */ INSERT INTO users VALUES (1)")

    def test_multi_statement_select_then_drop(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("SELECT 1; DROP TABLE users")

    def test_multi_statement_select_then_delete(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("SELECT * FROM users; DELETE FROM users")

    def test_line_comment_before_insert(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("-- comment\nINSERT INTO users VALUES (1)")

    def test_nested_block_comments(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("/* /* nested */ */ DELETE FROM users")

    def test_empty_query(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("")

    def test_whitespace_only_query(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("   \n\t  ")

    def test_cte_with_insert(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query("WITH cte AS (SELECT * FROM users) INSERT INTO archive SELECT * FROM cte")

    def test_cte_with_delete(self):
        with pytest.raises(ReadOnlyViolationError):
            validate_readonly_query(
                "WITH cte AS (SELECT * FROM users) DELETE FROM users WHERE id IN (SELECT id FROM cte)"
            )
