import mysql.connector
import mysql.connector.pooling
import threading
import time

from config import DB_HOST, DB_NAME, DB_PASSWORD, DB_POOL_SIZE, DB_PORT, DB_QUERY_TIMEOUT_MS, DB_USER


# Pool creation stays lazy so importing the Flask app does not require a live DB.
_pool = None
_pool_lock = threading.Lock()


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name="chatbot_pool",
                    pool_size=DB_POOL_SIZE,
                    host=DB_HOST,
                    port=DB_PORT,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME,
                    connection_timeout=5,
                    autocommit=True,
                )
    return _pool


def get_connection():
    """Wait briefly for a pooled connection instead of failing on a small spike."""
    deadline = time.monotonic() + 1.5
    while True:
        try:
            return _get_pool().get_connection()
        except mysql.connector.errors.PoolError as error:
            if time.monotonic() >= deadline:
                raise RuntimeError("The database is busy. Try again shortly.") from error
            time.sleep(0.05)


def execute_query(sql: str, params: tuple = None):
    """Run a read-only query inside a read-only transaction."""
    connection = get_connection()
    cursor = None
    transaction_started = False
    try:
        cursor = connection.cursor()
        cursor.execute(f"SET SESSION MAX_EXECUTION_TIME = {DB_QUERY_TIMEOUT_MS}")
        connection.start_transaction(readonly=True)
        transaction_started = True
        cursor.execute(sql, params or ())
        columns = [description[0] for description in cursor.description] if cursor.description else []
        rows = cursor.fetchall() if cursor.description else []
        return columns, rows
    except mysql.connector.Error as error:
        raise RuntimeError(f"Database error: {error.msg}") from error
    finally:
        try:
            if cursor is not None:
                cursor.close()
        finally:
            if transaction_started:
                try:
                    connection.rollback()
                except mysql.connector.Error:
                    pass
            connection.close()


def log_audit(user_id, username, role, question, sql, status, error_msg=None, rows=0, ip=None):
    """Record the query outcome before the application returns an answer."""
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """INSERT INTO AuditLog
               (UserID, Username, UserRole, Question, GeneratedSQL,
                ExecutionStatus, ErrorMessage, RowsReturned, IPAddress)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (user_id, username, role, question, sql, status, error_msg, rows, ip),
        )
    except Exception as error:
        raise RuntimeError("The query audit could not be recorded.") from error
    finally:
        try:
            if cursor is not None:
                cursor.close()
        finally:
            if connection is not None:
                connection.close()
