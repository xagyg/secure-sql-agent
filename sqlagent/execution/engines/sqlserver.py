# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Microsoft SQL Server, through pyodbc and the Microsoft ODBC driver
# (ODBC Driver 18 for SQL Server by default).
#
# Differences from PostgreSQL that matter for security:
#
#   Read-only    SQL Server has no read-only session or transaction, so
#                the login's permissions are the database's own boundary:
#                a dedicated login whose database user is in db_datareader
#                only (no db_datawriter, no EXECUTE, no DDL). The agent's
#                structural checks (sql_policy.py) still allow only a
#                single SELECT.
#   Timeout      the ODBC query timeout (pyodbc Connection.timeout), set
#                before the cursor is created - pyodbc applies it only to
#                cursors created after it is set. On expiry the driver
#                cancels the query and the connection stays usable.
#   Provenance   sp_describe_first_result_set in browse mode 2 traces each
#                result column to the table or VIEW it was read from, as
#                PostgreSQL's column table OIDs do: through aliases,
#                joins and derived tables, but not through a view into its
#                base tables, so a view the security policy allows isn't
#                judged by its base tables' rules. Computed columns,
#                window functions and UNION columns have no source.

import re

from sqlagent.execution.engines.base import Engine


# Tables and views only (INFORMATION_SCHEMA.COLUMNS also lists the columns
# of table-valued functions). INFORMATION_SCHEMA shows only objects the
# login has some permission on.
_TABLES_SQL = """
SELECT TABLE_SCHEMA AS table_schema, TABLE_NAME AS table_name
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_TYPE IN ('BASE TABLE', 'VIEW')
"""

_COLUMNS_SQL = """
SELECT
    c.TABLE_SCHEMA     AS table_schema,
    c.TABLE_NAME       AS table_name,
    c.COLUMN_NAME      AS column_name,
    c.DATA_TYPE        AS data_type,
    c.IS_NULLABLE      AS is_nullable,
    c.ORDINAL_POSITION AS ordinal_position
FROM INFORMATION_SCHEMA.COLUMNS c
JOIN INFORMATION_SCHEMA.TABLES t
  ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
WHERE t.TABLE_TYPE IN ('BASE TABLE', 'VIEW')
ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION
"""

# One row per column pair, in key order, so a composite key keeps its
# pairing (constraint_column_id).
_FOREIGN_KEYS_SQL = """
SELECT
    fk.object_id              AS constraint_id,
    SCHEMA_NAME(pt.schema_id) AS parent_schema,
    pt.name                   AS parent_table,
    pc.name                   AS parent_column,
    SCHEMA_NAME(rt.schema_id) AS referenced_schema,
    rt.name                   AS referenced_table,
    rc.name                   AS referenced_column
FROM sys.foreign_keys fk
JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
JOIN sys.tables pt  ON pt.object_id = fkc.parent_object_id
JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id
                   AND pc.column_id = fkc.parent_column_id
JOIN sys.tables rt  ON rt.object_id = fkc.referenced_object_id
JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id
                   AND rc.column_id = fkc.referenced_column_id
ORDER BY SCHEMA_NAME(pt.schema_id), pt.name, fk.name, fkc.constraint_column_id
"""

_PHYSICAL_COLUMNS_SQL = """
SELECT COLUMN_NAME AS column_name
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
ORDER BY ORDINAL_POSITION
"""

_DESCRIBE_SQL = (
    "EXEC sp_describe_first_result_set "
    "@tsql = ?, @params = NULL, @browse_information_mode = 2"
)

# A plain identifier needs no brackets.
_PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Words the model would otherwise write unbracketed as names. Not the
# whole reserved list: the ones that are plausible table/column names.
_RESERVED = {
    "order", "group", "user", "key", "table", "index", "view", "file",
    "function", "procedure", "schema", "select", "where", "from", "by",
    "public", "current", "date", "plan", "percent", "top", "default",
}


def _odbc_value(value):
    """An ODBC connection string value, braced when it contains anything
    the connection string syntax would read as a delimiter."""
    text = str(value)
    if re.search(r"[;{}=\s]", text) or text != text.strip():
        return "{" + text.replace("}", "}}") + "}"
    return text


def _rows(cursor):
    """pyodbc rows as dicts, keyed by the column names the query gave."""
    if cursor.description is None:
        return []
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


class SqlServerEngine(Engine):
    name = "sqlserver"
    label = "SQL Server"
    dialect = "tsql"
    default_schema = "dbo"
    driver_module = "pyodbc"
    default_driver = "ODBC Driver 18 for SQL Server"
    prompt_rules = """\
* Use table and column names exactly as the schema above shows them,
  including their case (e.g. CompanyName, dbo.Customers) - do not
  invent snake_case names.
* Square brackets are required around a name with a space or a
  reserved word, exactly as the schema above shows them, e.g.
  dbo.[Order Details]. Never use double quotes or backticks.
* Limit rows with TOP n (SELECT TOP 5 ...); SQL Server has no LIMIT.
* Use SQL Server functions: GETDATE() not NOW(), LEN() not LENGTH(),
  YEAR()/MONTH()/DATEPART() for dates, + or CONCAT() to join text."""

    # -- connection ---------------------------------------------------------

    def connection_string(self, profile, password):
        """The ODBC connection string. Never logged: it holds the password."""
        c = profile.connection
        server = c.host + (f",{c.port}" if c.port else "")
        parts = {
            "DRIVER": "{" + (c.driver or self.default_driver) + "}",
            "SERVER": _odbc_value(server),
            "DATABASE": _odbc_value(c.database),
            "UID": _odbc_value(c.user),
            "PWD": _odbc_value(password or ""),
            "Encrypt": "yes" if c.encrypt is not False else "no",
            "TrustServerCertificate": "yes" if c.trust_server_certificate else "no",
            "APP": "secure-sql-agent",
        }
        return "".join(f"{key}={value};" for key, value in parts.items())

    def connect(self, profile):
        import pyodbc
        return pyodbc.connect(
            self.connection_string(profile, profile.password()),
            timeout=15,          # login timeout, seconds
            autocommit=True,     # SELECTs only; no transaction left open
        )

    # -- catalog ------------------------------------------------------------

    def _query(self, conn, sql, params=()):
        cursor = conn.cursor()
        try:
            cursor.execute(sql, params)
            return _rows(cursor)
        finally:
            cursor.close()

    def list_tables(self, conn):
        return {
            f"{row['table_schema']}.{row['table_name']}"
            for row in self._query(conn, _TABLES_SQL)
        }

    def column_rows(self, conn):
        return self._query(conn, _COLUMNS_SQL)

    def foreign_key_rows(self, conn):
        return self._query(conn, _FOREIGN_KEYS_SQL)

    def physical_columns(self, conn, schema, table):
        return [row["column_name"]
                for row in self._query(conn, _PHYSICAL_COLUMNS_SQL, (schema, table))]

    # -- execution ----------------------------------------------------------

    def execute_readonly(self, conn, sql, timeout_seconds):
        # Applies to cursors created from here on (pyodbc), so it is set
        # before the cursor below; it also covers the describe call.
        conn.timeout = timeout_seconds
        cursor = conn.cursor()
        try:
            described = self._describe(cursor, sql)

            cursor.execute(sql)
            if cursor.description is None:
                raise ValueError("The SQL statement did not produce a result set.")
            names = [d[0] for d in cursor.description]
            rows = [dict(zip(names, row)) for row in cursor.fetchall()]
        finally:
            cursor.close()

        return rows, self._column_sources(names, described)

    def _describe(self, cursor, sql):
        """The query's visible result columns, in order, from
        sp_describe_first_result_set (browse mode 2)."""
        cursor.execute(_DESCRIBE_SQL, (sql,))
        described = [row for row in _rows(cursor) if not row.get("is_hidden")]
        return sorted(described, key=lambda r: r["column_ordinal"])

    @staticmethod
    def _column_sources(names, described):
        """
        {output column name: [(table, column) | None, ...]}, as
        PostgresEngine._column_sources. Fails closed: if the description
        doesn't line up with the columns the query actually returned, the
        result is refused rather than passed to the result policy with
        sources that might belong to other columns.
        """
        if len(described) != len(names):
            raise ValueError(
                "The result columns could not be traced to their tables "
                f"({len(names)} returned, {len(described)} described).")

        sources = {}
        for name, info in zip(names, described):
            described_name = info.get("name")
            if name and described_name and name.lower() != described_name.lower():
                raise ValueError(
                    "The result columns could not be traced to their tables "
                    f"('{name}' was described as '{described_name}').")
            source = None
            if info.get("source_table") and info.get("source_column"):
                source = (f"{info['source_schema']}.{info['source_table']}",
                          info["source_column"])
            sources.setdefault(name, []).append(source)
        return sources

    # -- names --------------------------------------------------------------

    def quote_name(self, name):
        if _PLAIN_NAME.fullmatch(name) and name.lower() not in _RESERVED:
            return name
        return "[" + name.replace("]", "]]") + "]"

    # -- errors -------------------------------------------------------------

    def missing_column(self, error_text):
        """SQL Server: "Invalid column name 'PhoneNr'." (error 207). The
        first one if several are reported; the name is unqualified."""
        match = re.search(r"Invalid column name '((?:[^']|'')+)'", error_text)
        return match.group(1).replace("''", "'") if match else None

    def sanitize_error(self, error_text):
        """
        The server's own message(s), without the driver's wrapping:

            ('42S22', "[42S22] [Microsoft][ODBC Driver 18 for SQL Server]
            [SQL Server]Invalid column name 'PhoneNr'. (207) (SQLExecDirectW)")
            -> Invalid column name 'PhoneNr'.

        SQL Server messages carry no PostgreSQL-style HINT/DETAIL, so
        nothing else is removed.
        """
        messages = []
        for part in error_text.split("[SQL Server]")[1:]:
            message = re.split(r"\s*\(\d+\)\s*(?:\(SQL\w+\))?", part, maxsplit=1)[0]
            message = message.strip().rstrip("\"')").strip()
            if message and message not in messages:
                messages.append(message)
        if messages:
            return "\n".join(messages)
        # A driver-level error (e.g. "Query timeout expired"): drop the
        # SQLSTATE tuple and the [vendor][driver] tags.
        text = re.sub(r"\[[^\]]*\]\s*", "", error_text)
        text = re.sub(r"^\(\s*'[0-9A-Z]{5}',\s*[\"']", "", text.strip())
        text = re.sub(r"\s*\(\d+\)\s*(?:\(SQL\w+\))?[\"']?\)?\s*$", "", text)
        return text.strip()

    def strip_row_limit(self, sql, max_rows):
        """sqlglot renders the agent's row cap as "TOP n", or as "FETCH
        FIRST n ROWS ONLY" after an OFFSET."""
        sql = re.sub(rf"\bTOP\s*\(?\s*{max_rows}\s*\)?\s+", "", sql,
                     flags=re.IGNORECASE)
        return re.sub(rf"\s*\bFETCH\s+(?:FIRST|NEXT)\s+{max_rows}\s+ROWS?\s+ONLY\b",
                      "", sql, flags=re.IGNORECASE)
