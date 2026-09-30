"""Revocable HttpOnly sessions with live account authorization on every request."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import jsonify, request
from config import IS_PRODUCTION, SESSION_SECRET, SESSION_TTL_MINS
from access_control import user_access
from db import execute_query, get_connection
from policy import access_problem, capabilities, policy_fingerprint

COOKIE_NAME = "insightbot_session"


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _write(sql, params):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
        finally:
            cursor.close()
    finally:
        connection.close()


def enforce_rate_limit(kind, subject, limit, window_seconds):
    """Count requests in MySQL so concurrent workers share the same limit."""
    bucket = _digest(kind + ":" + str(subject).lower())
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO RequestThrottle (BucketKey, WindowStart, Attempts)
                   VALUES (%s, UTC_TIMESTAMP(), 1)
                   ON DUPLICATE KEY UPDATE
                     Attempts = IF(WindowStart < UTC_TIMESTAMP() - INTERVAL %s SECOND,
                                   1, Attempts + 1),
                     WindowStart = IF(WindowStart < UTC_TIMESTAMP() - INTERVAL %s SECOND,
                                      UTC_TIMESTAMP(), WindowStart)""",
                (bucket, window_seconds, window_seconds),
            )
            cursor.execute("SELECT Attempts FROM RequestThrottle WHERE BucketKey = %s", (bucket,))
            attempts = cursor.fetchone()[0]
            return attempts <= limit
        finally:
            cursor.close()
    finally:
        connection.close()


def create_session(user, password_hash):
    # Incremental cleanup keeps session and throttle indexes bounded without
    # making a maintenance sweep part of every login.
    if secrets.randbelow(64) == 0:
        _write("DELETE FROM AuthSessions WHERE ExpiresAt < UTC_TIMESTAMP() LIMIT 1000", ())
        _write("DELETE FROM RequestThrottle WHERE WindowStart < UTC_TIMESTAMP() - INTERVAL 1 DAY LIMIT 1000", ())
    token = secrets.token_urlsafe(48)
    session_id = _digest(token)
    expires = datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL_MINS)
    _write("INSERT INTO AuthSessions (SessionID, UserID, AccessFingerprint, CredentialStamp, ExpiresAt) VALUES (%s,%s,%s,%s,%s)",
           (session_id, user["user_id"], policy_fingerprint(user), _digest(password_hash), expires.replace(tzinfo=None)))
    user["session_id"] = session_id
    user["expires_at"] = expires.isoformat()
    return token


def csrf_token(session_id):
    return hmac.new(SESSION_SECRET.encode(), ("csrf:" + session_id).encode(), hashlib.sha256).hexdigest()


def session_payload(user):
    return {"username": user["username"], "fullName": user["full_name"], "role": user["role"],
            "region": user.get("region"), "deptId": user.get("dept_id"), "department": user.get("dept_name"),
            "expiresAt": user["expires_at"], "sessionId": user["session_id"],
            "csrfToken": csrf_token(user["session_id"]), "access": capabilities(user)}


def set_session_cookie(response, token):
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL_MINS * 60,
                        secure=IS_PRODUCTION, httponly=True, samesite="Strict", path="/")
    return response


def revoke_session():
    token = request.cookies.get(COOKIE_NAME)
    if token:
        _write("DELETE FROM AuthSessions WHERE SessionID = %s", (_digest(token),))


def resolve_user():
    token = request.cookies.get(COOKIE_NAME, "")
    if not token or len(token) > 128:
        return None, "Sign in to continue.", 401
    _, rows = execute_query(
        """SELECT u.UserID, u.Username, u.FullName, LOWER(r.RoleName), u.Region, u.DeptID,
                  u.IsActive, u.PasswordHash, d.DeptName, s.AccessFingerprint,
                  s.CredentialStamp, s.ExpiresAt, u.RoleID, r.Description
           FROM AuthSessions s JOIN AppUsers u ON s.UserID = u.UserID
           JOIN Roles r ON u.RoleID = r.RoleID LEFT JOIN Departments d ON u.DeptID = d.DeptID
           WHERE s.SessionID = %s AND s.ExpiresAt > UTC_TIMESTAMP()""", (_digest(token),))
    if not rows:
        return None, "Your session has expired. Sign in again.", 401
    uid, name, full, role, region, dept, active, password_hash, department, fingerprint, stamp, expires, role_id, role_description = rows[0]
    if not active:
        _write("DELETE FROM AuthSessions WHERE SessionID = %s", (_digest(token),))
        return None, "This account is disabled. Contact your administrator.", 401
    user = {"user_id": uid, "username": name, "full_name": full, "role": role,
            "role_id": role_id, "role_description": role_description,
            "region": region, "dept_id": dept, "dept_name": department,
            "session_id": _digest(token), "expires_at": expires.replace(tzinfo=timezone.utc).isoformat()}
    try:
        user["data_access"], user["data_access_mode"], user["role_access_mode"] = user_access(uid, role_id, role)
    except Exception:
        return None, "Workspace permissions could not be loaded. Apply the admin access migration and try again.", 503
    if not hmac.compare_digest(stamp, _digest(str(password_hash))) or not hmac.compare_digest(fingerprint, policy_fingerprint(user)):
        _write("DELETE FROM AuthSessions WHERE SessionID = %s", (user["session_id"],))
        return None, "Your account access has changed. Sign in again to refresh your workspace.", 401
    problem = access_problem(role, region, dept)
    return (None, problem, 403) if problem else (user, None, 200)


def login_required(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        try:
            user, error, status = resolve_user()
        except Exception:
            return jsonify(error="Account access could not be verified. Try again shortly."), 503
        if error:
            response = jsonify(error=error, code="session_invalid")
            response.delete_cookie(COOKIE_NAME, path="/")
            return response, status
        expected_session = request.headers.get("X-Session-ID")
        if expected_session and not hmac.compare_digest(expected_session, user["session_id"]):
            return jsonify(error="The signed-in account changed in another tab. Sign in again.", code="session_invalid"), 401
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(supplied, csrf_token(user["session_id"])):
                return jsonify(error="Your request could not be verified. Refresh the page and try again.", code="csrf_invalid"), 403
        request.current_user = user
        return function(*args, **kwargs)
    return decorated


def capability_required(name):
    def decorate(function):
        @wraps(function)
        @login_required
        def decorated(*args, **kwargs):
            if not capabilities(request.current_user).get(name, False):
                return jsonify(error="Your role does not have access to this workspace feature.", code="access_denied"), 403
            return function(*args, **kwargs)
        return decorated
    return decorate
