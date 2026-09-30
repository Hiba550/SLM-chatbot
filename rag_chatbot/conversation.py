"""Bounded, session-scoped conversation context and shared model leases."""

import re
import secrets
import time
import mysql.connector

from config import MODEL_MAX_CONCURRENT, MODEL_QUEUE_WAIT_SECONDS, MODEL_TIMEOUT_SECONDS
from db import get_connection


CONVERSATION_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
CONTEXT_TURNS = 4
RETAINED_TURNS = 12
RETAINED_SESSION_TURNS = 360


def valid_conversation_id(value):
    return isinstance(value, str) and bool(CONVERSATION_ID.fullmatch(value))


def recent_turns(session_id, conversation_id):
    """Read only this login's recent successful turns; never accept client history."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """SELECT LEFT(Question, 350), LEFT(AnswerText, 700), LEFT(GeneratedSQL, 900)
                   FROM ChatTurns
                   WHERE SessionID = %s AND ConversationID = %s
                   ORDER BY TurnID DESC LIMIT %s""",
                (session_id, conversation_id, CONTEXT_TURNS),
            )
            rows = cursor.fetchall()
            return [dict(question=row[0], answer=row[1], sql=row[2]) for row in reversed(rows)]
        finally:
            cursor.close()
    except mysql.connector.Error as error:
        raise RuntimeError("Conversation storage is unavailable.") from error
    finally:
        connection.close()


def save_turn(session_id, conversation_id, question, answer, sql):
    """Keep a small rolling history; expired or revoked sessions cannot add turns."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO ChatTurns
                   (SessionID, ConversationID, Question, AnswerText, GeneratedSQL)
                   SELECT SessionID, %s, %s, %s, %s FROM AuthSessions
                   WHERE SessionID = %s AND ExpiresAt > UTC_TIMESTAMP()""",
                (conversation_id, question[:2000], answer[:1200], sql[:4000], session_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("The session ended before the answer could be saved.")
            cursor.execute(
                """SELECT TurnID FROM ChatTurns
                   WHERE SessionID = %s AND ConversationID = %s
                   ORDER BY TurnID DESC LIMIT 1 OFFSET %s""",
                (session_id, conversation_id, RETAINED_TURNS - 1),
            )
            oldest = cursor.fetchone()
            if oldest:
                cursor.execute(
                    """DELETE FROM ChatTurns WHERE SessionID = %s
                       AND ConversationID = %s AND TurnID < %s""",
                    (session_id, conversation_id, oldest[0]),
                )
            cursor.execute(
                """SELECT TurnID FROM ChatTurns WHERE SessionID = %s
                   ORDER BY TurnID DESC LIMIT 1 OFFSET %s""",
                (session_id, RETAINED_SESSION_TURNS - 1),
            )
            session_oldest = cursor.fetchone()
            if session_oldest:
                cursor.execute(
                    "DELETE FROM ChatTurns WHERE SessionID = %s AND TurnID < %s",
                    (session_id, session_oldest[0]),
                )
        finally:
            cursor.close()
    except mysql.connector.Error as error:
        raise RuntimeError("Conversation storage is unavailable.") from error
    finally:
        connection.close()


def clear_turns(session_id, conversation_id):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute("DELETE FROM ChatTurns WHERE SessionID = %s AND ConversationID = %s",
                           (session_id, conversation_id))
        finally:
            cursor.close()
    except mysql.connector.Error as error:
        raise RuntimeError("Conversation storage is unavailable.") from error
    finally:
        connection.close()


def acquire_model_slot():
    """Lease one model call across all workers; wait briefly, then shed load."""
    token = secrets.token_hex(32)
    deadline = time.monotonic() + MODEL_QUEUE_WAIT_SECONDS
    while True:
        connection = get_connection()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """UPDATE ModelSlots
                       SET LeaseToken = %s,
                           LeaseExpiresAt = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL %s SECOND)
                       WHERE SlotID <= %s AND LeaseExpiresAt < UTC_TIMESTAMP(6)
                       ORDER BY SlotID LIMIT 1""",
                    (token, MODEL_TIMEOUT_SECONDS + 15, MODEL_MAX_CONCURRENT),
                )
                if cursor.rowcount == 1:
                    return token
            finally:
                cursor.close()
        except mysql.connector.Error as error:
            raise RuntimeError("Model capacity service is unavailable.") from error
        finally:
            connection.close()
        if time.monotonic() >= deadline:
            return None
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def release_model_slot(token):
    if not token:
        return
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """UPDATE ModelSlots SET LeaseToken = NULL,
                   LeaseExpiresAt = '1970-01-01 00:00:00.000000'
                   WHERE LeaseToken = %s""",
                (token,),
            )
        finally:
            cursor.close()
    finally:
        connection.close()
