"""Administrator-only user, role, schema-map, and workspace overview APIs."""

import re
from datetime import date, datetime

from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from access_control import permission_catalog, role_access
from auth import capability_required
from config import DB_NAME
from db import execute_query, get_connection
from policy import ANALYTIC_TABLES, ROLE_DETAILS, ROLE_TABLES, SOURCE_COLUMNS, access_problem, columns_for


admin_api = Blueprint("admin_api", __name__, url_prefix="/admin")
_SAFE_SOURCE_KEYS = {name.lower(): name for name in ANALYTIC_TABLES}
_BUILT_IN_ROLES = set(ROLE_DETAILS)
_SENSITIVE_SCHEMA_COLUMNS = {
    "passwordhash", "sessionid", "credentialstamp", "accessfingerprint",
    "leasetoken", "bucketkey",
}
_VIEW_SOURCES = {
    "v_SalesOrders": ["SalesOrders", "Customers", "Employees"],
    "v_InventoryStatus": ["Inventory", "Products", "Categories", "Warehouses"],
    "v_FinancialSummary": ["FinancialTransactions", "Accounts"],
    "v_ManagementKPI": ["SalesOrders", "Employees", "Departments"],
}


def _json_object():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("Send the changes as a JSON object.")
    return body


def _write_transaction(callback):
    connection = get_connection()
    try:
        connection.start_transaction()
        cursor = connection.cursor()
        try:
            result = callback(cursor)
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()


def _security_event(cursor, event_type, target_type, target_identifier, details=None):
    """Record an administrator mutation in the same transaction as the change."""
    actor = request.current_user
    cursor.execute(
        """INSERT INTO SecurityEvents
           (ActorUserID, ActorUsername, EventType, TargetType, TargetIdentifier, Details, IPAddress)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (actor["user_id"], actor["username"], event_type, target_type,
         str(target_identifier)[:100], str(details)[:500] if details else None,
         (request.remote_addr or "unknown")[:50]),
    )


def _role_rows():
    columns, rows = execute_query(
        """SELECT r.RoleID, LOWER(r.RoleName) AS RoleName, r.Description,
                  COUNT(u.UserID) AS UserCount
           FROM Roles r LEFT JOIN AppUsers u ON u.RoleID = r.RoleID
           GROUP BY r.RoleID, r.RoleName, r.Description ORDER BY r.RoleName"""
    )
    return [dict(zip(columns, row)) for row in rows]


def _source_grants(cursor, owner_type, owner_id, grants):
    source_table = "RoleSourceGrants" if owner_type == "role" else "UserSourceGrants"
    column_table = "RoleColumnGrants" if owner_type == "role" else "UserColumnGrants"
    owner_column = "RoleID" if owner_type == "role" else "UserID"
    for grant in grants:
        cursor.execute(
            f"INSERT INTO {source_table} ({owner_column}, SourceName, GrantAllColumns) VALUES (%s,%s,%s)",
            (owner_id, grant["name"], 1 if grant["allColumns"] else 0),
        )
        if not grant["allColumns"]:
            for column in grant["columns"]:
                cursor.execute(
                    f"INSERT INTO {column_table} ({owner_column}, SourceName, ColumnName) VALUES (%s,%s,%s)",
                    (owner_id, grant["name"], column),
                )


def _normal_name(value):
    if not isinstance(value, str):
        raise ValueError("Enter a role name.")
    name = value.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,49}", name):
        raise ValueError("Role names must start with a letter and use 2–50 letters, numbers, hyphens, or underscores.")
    return name


def _role_for_user(user_id):
    columns, rows = execute_query(
        """SELECT u.UserID, u.Username, u.FullName, u.RoleID, LOWER(r.RoleName) AS RoleName,
                  u.Region, u.DeptID, u.IsActive, u.LastLogin, u.CreatedAt
           FROM AppUsers u JOIN Roles r ON u.RoleID = r.RoleID WHERE u.UserID = %s""",
        (user_id,),
    )
    return dict(zip(columns, rows[0])) if rows else None


@admin_api.get("/overview")
@capability_required("canReviewAccess")
def admin_overview():
    _, users = execute_query(
        """SELECT COUNT(*) AS TotalUsers,
                  COALESCE(SUM(CASE WHEN IsActive = 1 THEN 1 ELSE 0 END),0) AS ActiveUsers,
                  COALESCE(SUM(CASE WHEN IsActive = 0 THEN 1 ELSE 0 END),0) AS DisabledUsers
           FROM AppUsers"""
    )
    _, role_summary = execute_query("SELECT COUNT(*) FROM Roles")
    _, activity_summary = execute_query(
        """SELECT COUNT(*) AS Requests30d,
                  COALESCE(SUM(CASE WHEN ExecutionStatus = 'Success' THEN 1 ELSE 0 END),0) AS Successful30d,
                  COALESCE(SUM(CASE WHEN ExecutionStatus IN ('Blocked','Error') THEN 1 ELSE 0 END),0) AS Issues30d
           FROM AuditLog WHERE LoggedAt >= UTC_TIMESTAMP() - INTERVAL 30 DAY"""
    )
    trend_columns, trend_rows = execute_query(
        """SELECT DATE(LoggedAt) AS Day, COUNT(*) AS Requests,
                  SUM(CASE WHEN ExecutionStatus = 'Success' THEN 1 ELSE 0 END) AS Successful,
                  SUM(CASE WHEN ExecutionStatus IN ('Blocked','Error') THEN 1 ELSE 0 END) AS Issues
           FROM AuditLog WHERE LoggedAt >= UTC_TIMESTAMP() - INTERVAL 13 DAY
           GROUP BY DATE(LoggedAt) ORDER BY Day"""
    )
    recent_columns, recent_rows = execute_query(
        """SELECT Username, UserRole, LEFT(Question,160) AS Question, ExecutionStatus,
                  RowsReturned, LoggedAt FROM AuditLog ORDER BY LoggedAt DESC LIMIT 8"""
    )
    security_columns, security_rows = execute_query(
        """SELECT ActorUsername, EventType, TargetType, TargetIdentifier, Details, LoggedAt
           FROM SecurityEvents ORDER BY LoggedAt DESC LIMIT 8"""
    )
    user = users[0] if users else (0, 0, 0)
    activity = activity_summary[0] if activity_summary else (0, 0, 0)
    return jsonify(
        users={"total": int(user[0]), "active": int(user[1]), "disabled": int(user[2])},
        roles=int(role_summary[0][0]) if role_summary else 0,
        sources=len(ANALYTIC_TABLES),
        activity={"requests30d": int(activity[0]), "successful30d": int(activity[1]), "issues30d": int(activity[2])},
        trend=[_jsonable_record(dict(zip(trend_columns, row))) for row in trend_rows],
        recent=[dict(zip(recent_columns, row)) for row in recent_rows],
        securityEvents=[_jsonable_record(dict(zip(security_columns, row))) for row in security_rows],
    )


@admin_api.get("/catalog")
@capability_required("canViewSchema")
def schema_catalog():
    _, object_rows = execute_query(
        """SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES
           WHERE TABLE_SCHEMA = %s ORDER BY TABLE_TYPE, TABLE_NAME""",
        (DB_NAME,),
    )
    _, column_rows = execute_query(
        """SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA
           FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s
           ORDER BY TABLE_NAME, ORDINAL_POSITION""",
        (DB_NAME,),
    )
    _, relationship_rows = execute_query(
        """SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
           FROM information_schema.KEY_COLUMN_USAGE
           WHERE TABLE_SCHEMA = %s AND REFERENCED_TABLE_NAME IS NOT NULL
           ORDER BY TABLE_NAME, COLUMN_NAME""",
        (DB_NAME,),
    )
    objects = {name: {"name": name, "type": kind, "columns": []} for name, kind in object_rows}
    column_meta = {}
    for table, column, dtype, nullable, key, extra in column_rows:
        if table not in objects:
            continue
        meta = {"name": column, "type": dtype, "nullable": nullable == "YES",
                "key": key or "", "generated": "generated" in str(extra).lower()}
        if str(column).lower() not in _SENSITIVE_SCHEMA_COLUMNS:
            objects[table]["columns"].append(meta)
        column_meta[(table.lower(), column.lower())] = meta

    relationships = []
    related_pairs = set()
    for table, column, target, target_column in relationship_rows:
        if table in objects and target in objects:
            relationships.append({"fromTable": table, "fromColumn": column,
                                  "toTable": target, "toColumn": target_column, "kind": "foreign-key"})
            related_pairs.add((table.lower(), target.lower()))
    object_names = {name.lower(): name for name in objects}
    for view, tables in _VIEW_SOURCES.items():
        live_view = object_names.get(view.lower())
        if not live_view:
            continue
        for table in tables:
            live_table = object_names.get(table.lower())
            if live_table and (live_view.lower(), live_table.lower()) not in related_pairs:
                relationships.append({"fromTable": live_view, "fromColumn": "", "toTable": live_table,
                                      "toColumn": "", "kind": "view-source"})

    sources = []
    for name, item in objects.items():
        item["queryable"] = str(name).lower() in _SAFE_SOURCE_KEYS
        item["protected"] = not item["queryable"]
        item["group"] = _source_group(name)
        item["relationships"] = sum(1 for edge in relationships if edge["fromTable"] == name or edge["toTable"] == name)
        sources.append(item)
    return jsonify(sources=sources, relationships=relationships,
                   summary={"objects": len(sources), "tables": sum(x["type"] == "BASE TABLE" for x in sources),
                            "views": sum(x["type"] == "VIEW" for x in sources),
                            "relationships": len(relationships),
                            "fields": sum(len(x["columns"]) for x in sources),
                            "grantable": sum(bool(x["queryable"]) for x in sources)})


def _source_group(name):
    canonical = _SAFE_SOURCE_KEYS.get(str(name).lower(), name)
    if canonical.startswith("v_"):
        return "Views"
    if canonical in {"SalesOrders", "SalesOrderItems", "SalesReturns", "Customers"}:
        return "Sales"
    if canonical in {"Products", "Categories", "Warehouses", "Inventory", "StockMovements"}:
        return "Inventory"
    if canonical in {"Accounts", "FinancialTransactions", "Payroll", "Expenses"}:
        return "Finance"
    if canonical in {"Departments", "Employees", "Shifts", "Qualifications", "LeaveTypes", "LeaveEligibility", "LeaveTransactions", "Attendance"}:
        return "People & operations"
    return "Protected system"


@admin_api.get("/roles")
@capability_required("canManageRoles")
def list_roles():
    result = []
    for item in _role_rows():
        role_name = str(item["RoleName"]).lower()
        data_access, mode = role_access(item["RoleID"], role_name)
        item["scopeMode"] = mode
        item["sources"] = permission_catalog(data_access)
        item["locked"] = role_name == "admin"
        item["baseSources"] = permission_catalog({
            name: columns_for(role_name, name) for name in ROLE_TABLES.get(role_name, [])
            if columns_for(role_name, name)
        }) if role_name in _BUILT_IN_ROLES else permission_catalog()
        result.append(item)
    return jsonify(roles=result, catalog=permission_catalog())


@admin_api.post("/roles")
@capability_required("canManageRoles")
def create_role():
    try:
        body = _json_object()
        name = _normal_name(body.get("name"))
        description = str(body.get("description", "")).strip()
        if len(description) > 200:
            raise ValueError("Role description must be 200 characters or fewer.")
        grants = _validated_grants(body.get("sources", []))

        def save(cursor):
            cursor.execute("INSERT INTO Roles (RoleName, Description) VALUES (%s,%s)", (name, description or None))
            role_id = cursor.lastrowid
            cursor.execute("INSERT INTO RoleDataScopes (RoleID, UpdatedBy) VALUES (%s,%s)",
                           (role_id, request.current_user["user_id"]))
            _source_grants(cursor, "role", role_id, grants)
            _security_event(cursor, "role.created", "role", role_id,
                            f"name={name}; sources={len(grants)}")
            return role_id

        role_id = _write_transaction(save)
        return jsonify(roleId=role_id, name=name, status="created"), 201
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        return jsonify(error="The role could not be saved. Check the role name and try again."), 409


@admin_api.patch("/roles/<int:role_id>")
@capability_required("canManageRoles")
def update_role(role_id):
    try:
        body = _json_object()
        name = _normal_name(body.get("name"))
        description = str(body.get("description", "")).strip()
        if len(description) > 200:
            raise ValueError("Role description must be 200 characters or fewer.")
        grants = _validated_grants(body.get("sources", []))
        existing = _role_for_id(role_id)
        if not existing:
            return jsonify(error="That role no longer exists."), 404
        if existing["RoleName"] == "admin":
            return jsonify(error="The administrator role is protected from scope changes."), 403
        if existing["RoleName"] in _BUILT_IN_ROLES and name != existing["RoleName"]:
            return jsonify(error="Built-in roles cannot be renamed because their row-level protections depend on the role key."), 400
        if existing["RoleName"] in ROLE_TABLES:
            baseline = {source: columns_for(existing["RoleName"], source)
                        for source in ROLE_TABLES[existing["RoleName"]]
                        if columns_for(existing["RoleName"], source)}
            grants = _validated_grants(body.get("sources", []), baseline)

        def save(cursor):
            cursor.execute("UPDATE Roles SET RoleName = %s, Description = %s WHERE RoleID = %s",
                           (name, description or None, role_id))
            cursor.execute("INSERT INTO RoleDataScopes (RoleID, UpdatedBy) VALUES (%s,%s) ON DUPLICATE KEY UPDATE UpdatedBy = VALUES(UpdatedBy)",
                           (role_id, request.current_user["user_id"]))
            cursor.execute("DELETE FROM RoleSourceGrants WHERE RoleID = %s", (role_id,))
            _source_grants(cursor, "role", role_id, grants)
            cursor.execute("DELETE FROM AuthSessions WHERE UserID IN (SELECT UserID FROM AppUsers WHERE RoleID = %s)", (role_id,))
            _security_event(cursor, "role.updated", "role", role_id,
                            f"name={name}; sources={len(grants)}; sessions_revoked=true")

        _write_transaction(save)
        return jsonify(roleId=role_id, name=name, status="updated", sessionsRevoked=True)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        return jsonify(error="The role could not be updated. Check that its name is unique."), 409


def _role_for_id(role_id):
    columns, rows = execute_query("SELECT RoleID, LOWER(RoleName) AS RoleName, Description FROM Roles WHERE RoleID = %s", (role_id,))
    return dict(zip(columns, rows[0])) if rows else None


def _validated_grants(raw, allowed=None):
    from access_control import validate_grant_list
    return validate_grant_list(raw, allowed)


@admin_api.get("/users")
@capability_required("canManageUsers")
def list_users():
    columns, rows = execute_query(
        """SELECT u.UserID, u.Username, u.FullName, u.RoleID, LOWER(r.RoleName) AS Role,
                  r.Description AS RoleDescription, u.Region, u.DeptID, d.DeptName AS Department,
                  u.IsActive, u.LastLogin, u.CreatedAt
           FROM AppUsers u JOIN Roles r ON u.RoleID = r.RoleID
           LEFT JOIN Departments d ON u.DeptID = d.DeptID
           ORDER BY u.FullName LIMIT 1000"""
    )
    roles = _role_rows()
    departments = _department_rows()
    return jsonify(users=[_jsonable_record(dict(zip(columns, row))) for row in rows],
                   roles=[_jsonable_record(item) for item in roles], departments=departments,
                   limit=1000)


def _department_rows():
    _, rows = execute_query("SELECT DeptID, DeptName FROM Departments ORDER BY DeptName")
    return [{"id": int(row[0]), "name": str(row[1])} for row in rows]


def _jsonable_record(record):
    return {
        key: (value.isoformat(sep=" ") if isinstance(value, datetime)
              else value.isoformat() if isinstance(value, date)
              else value)
        for key, value in record.items()
    }


@admin_api.post("/users")
@capability_required("canManageUsers")
def create_user():
    try:
        body = _json_object()
        username = str(body.get("username", "")).strip()
        full_name = str(body.get("fullName", "")).strip()
        password = body.get("password")
        role_id = _positive_int(body.get("roleId"), "Choose a role.")
        region = _optional_text(body.get("region"), 50, "Region")
        dept_id = _optional_int(body.get("deptId"), "Department")
        is_active = _optional_bool(body.get("isActive", True), "Account status")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
            raise ValueError("Usernames must be 3–50 letters, numbers, dots, hyphens, or underscores.")
        if not full_name or len(full_name) > 100:
            raise ValueError("Enter a full name of 1–100 characters.")
        _validate_password(password, username, full_name)
        role = _role_for_id(role_id)
        if not role:
            raise ValueError("Choose an existing role.")
        _validate_assignment(role["RoleName"], region, dept_id)
        _validate_department(dept_id)
        password_hash = generate_password_hash(password)

        def save(cursor):
            cursor.execute(
                """INSERT INTO AppUsers (Username, PasswordHash, FullName, RoleID, Region, DeptID, IsActive)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (username, password_hash, full_name, role_id, region, dept_id, 1 if is_active else 0),
            )
            user_id = cursor.lastrowid
            _security_event(cursor, "user.created", "user", user_id,
                            f"username={username}; role_id={role_id}; active={str(is_active).lower()}")
            return user_id

        user_id = _write_transaction(save)
        return jsonify(userId=user_id, status="created"), 201
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        return jsonify(error="The user could not be created. The username may already be in use."), 409


@admin_api.patch("/users/<int:user_id>")
@capability_required("canManageUsers")
def update_user(user_id):
    try:
        body = _json_object()
        current = _role_for_user(user_id)
        if not current:
            return jsonify(error="That account no longer exists."), 404
        full_name = _optional_text(body.get("fullName"), 100, "Full name") if "fullName" in body else current["FullName"]
        username = str(body.get("username", current["Username"])).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
            raise ValueError("Usernames must be 3–50 letters, numbers, dots, hyphens, or underscores.")
        role_id = _positive_int(body["roleId"], "Choose a role.") if "roleId" in body else int(current["RoleID"])
        region = _optional_text(body.get("region"), 50, "Region") if "region" in body else current["Region"]
        dept_id = _optional_int(body.get("deptId"), "Department") if "deptId" in body else current["DeptID"]
        is_active = _optional_bool(body["isActive"], "Account status") if "isActive" in body else bool(current["IsActive"])
        password = body.get("password")
        if password is not None:
            _validate_password(password, username, full_name or current["FullName"])
        role = _role_for_id(role_id)
        if not role:
            raise ValueError("Choose an existing role.")
        _validate_assignment(role["RoleName"], region, dept_id)
        _validate_department(dept_id)
        actor = request.current_user
        changing_self_admin = int(user_id) == int(actor["user_id"]) and (role["RoleName"] != "admin" or not is_active)
        if changing_self_admin:
            raise ValueError("You cannot disable your own administrator account or remove its administrator role.")

        def save(cursor):
            cursor.execute("SELECT UserID FROM AppUsers WHERE RoleID = %s AND IsActive = 1 FOR UPDATE",
                           (int(_admin_role_id(cursor)),))
            active_admins = cursor.fetchall()
            if current["RoleName"] == "admin" and current["IsActive"] and (
                    role["RoleName"] != "admin" or not is_active) and len(active_admins) <= 1:
                raise ValueError("At least one active administrator account must remain.")
            if password is None:
                cursor.execute(
                    """UPDATE AppUsers SET Username=%s, FullName=%s, RoleID=%s, Region=%s,
                       DeptID=%s, IsActive=%s WHERE UserID=%s""",
                    (username, full_name, role_id, region, dept_id, 1 if is_active else 0, user_id),
                )
            else:
                cursor.execute(
                    """UPDATE AppUsers SET Username=%s, FullName=%s, PasswordHash=%s,
                       RoleID=%s, Region=%s, DeptID=%s, IsActive=%s WHERE UserID=%s""",
                    (username, full_name, generate_password_hash(password), role_id, region,
                     dept_id, 1 if is_active else 0, user_id),
                )
            if int(current["RoleID"]) != role_id:
                cursor.execute("DELETE FROM UserDataScopes WHERE UserID = %s", (user_id,))
            cursor.execute("DELETE FROM AuthSessions WHERE UserID = %s", (user_id,))
            _security_event(cursor, "user.updated", "user", user_id,
                            f"username={username}; role_id={role_id}; active={str(is_active).lower()}; "
                            f"password_changed={str(password is not None).lower()}; sessions_revoked=true")

        _write_transaction(save)
        return jsonify(userId=user_id, status="updated", sessionsRevoked=True)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        return jsonify(error="The account could not be updated. Check that its username is unique."), 409


def _admin_role_id(cursor):
    cursor.execute("SELECT RoleID FROM Roles WHERE LOWER(RoleName) = 'admin' LIMIT 1")
    row = cursor.fetchone()
    return row[0] if row else -1


def _validate_assignment(role, region, dept_id):
    problem = access_problem(role, region, dept_id)
    if problem:
        raise ValueError(problem)


def _validate_department(dept_id):
    if dept_id is None:
        return
    _, rows = execute_query("SELECT DeptID FROM Departments WHERE DeptID = %s", (dept_id,))
    if not rows:
        raise ValueError("Choose a department from the current workspace database.")


def _positive_int(value, message):
    parsed = _optional_int(value, "Role")
    if parsed is None:
        raise ValueError(message)
    return parsed


def _optional_int(value, field):
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError(field + " must be a valid number.")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(field + " must be a valid number.")
    if parsed < 1:
        raise ValueError(field + " must be a positive number.")
    return parsed


def _optional_text(value, limit, field):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(field + " must be text.")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(field + " is too long.")
    return value or None


def _optional_bool(value, field):
    if not isinstance(value, bool):
        raise ValueError(field + " must be enabled or disabled.")
    return value


def _validate_password(password, username="", full_name=""):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        raise ValueError("Set a temporary password between 12 and 256 characters.")
    if password != password.strip():
        raise ValueError("The password cannot begin or end with spaces.")
    lowered = password.casefold()
    compact_name = re.sub(r"[^a-z0-9]", "", str(full_name).casefold())
    compact_password = re.sub(r"[^a-z0-9]", "", lowered)
    blocked = {"admin@123", "sales@123", "inv@123", "fin@123", "hr@123", "mgr@123",
               "password1234", "administrator", "welcome12345"}
    if lowered in blocked or str(username).casefold() in lowered or (compact_name and compact_name in compact_password):
        raise ValueError("Choose a password that does not contain the username, full name, or a demo password.")
    character_groups = sum((any(ch.islower() for ch in password), any(ch.isupper() for ch in password),
                            any(ch.isdigit() for ch in password), any(not ch.isalnum() for ch in password)))
    if len(password) < 16 and character_groups < 3:
        raise ValueError("Use at least 16 characters, or combine three of: uppercase, lowercase, numbers, and symbols.")


@admin_api.get("/users/<int:user_id>/data-access")
@capability_required("canManageUsers")
def get_user_scope(user_id):
    user = _role_for_user(user_id)
    if not user:
        return jsonify(error="That account no longer exists."), 404
    role_data, role_mode = role_access(user["RoleID"], user["RoleName"])
    if user["RoleName"] == "admin":
        return jsonify(mode="inherit", locked=True, roleSources=permission_catalog(role_data), sources=permission_catalog(role_data))
    _, rows = execute_query(
        """SELECT s.ScopeMode, g.SourceName, g.GrantAllColumns, c.ColumnName
           FROM UserDataScopes s LEFT JOIN UserSourceGrants g ON g.UserID = s.UserID
           LEFT JOIN UserColumnGrants c ON c.UserID = g.UserID AND c.SourceName = g.SourceName
           WHERE s.UserID = %s""", (user_id,)
    )
    mode = "custom" if rows else "inherit"
    grants = _group_scope_rows(rows)
    return jsonify(mode=mode, locked=False, roleSources=permission_catalog(role_data), sources=grants)


@admin_api.put("/users/<int:user_id>/data-access")
@capability_required("canManageUsers")
def update_user_scope(user_id):
    try:
        body = _json_object()
        user = _role_for_user(user_id)
        if not user:
            return jsonify(error="That account no longer exists."), 404
        if user["RoleName"] == "admin":
            return jsonify(error="Administrator data access is protected."), 403
        mode = body.get("mode", "inherit")
        if mode not in {"inherit", "custom"}:
            raise ValueError("Choose role access or a custom access scope.")
        role_data, _ = role_access(user["RoleID"], user["RoleName"])
        grants = _validated_grants(body.get("sources", []), role_data) if mode == "custom" else []

        def save(cursor):
            cursor.execute("DELETE FROM UserDataScopes WHERE UserID = %s", (user_id,))
            if mode == "custom":
                cursor.execute("INSERT INTO UserDataScopes (UserID, UpdatedBy) VALUES (%s,%s)",
                               (user_id, request.current_user["user_id"]))
                _source_grants(cursor, "user", user_id, grants)
            cursor.execute("DELETE FROM AuthSessions WHERE UserID = %s", (user_id,))
            _security_event(cursor, "user.scope_updated", "user", user_id,
                            f"mode={mode}; sources={len(grants)}; sessions_revoked=true")

        _write_transaction(save)
        return jsonify(userId=user_id, mode=mode, status="updated", sessionsRevoked=True)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        return jsonify(error="The user's data scope could not be updated."), 503


def _group_scope_rows(rows):
    sources = {}
    for mode, source, all_columns, column in rows:
        if not source:
            continue
        canonical = _SAFE_SOURCE_KEYS.get(str(source).lower())
        if not canonical:
            continue
        entry = sources.setdefault(canonical, {"name": canonical, "allColumns": False, "columns": []})
        entry["allColumns"] = entry["allColumns"] or bool(all_columns)
        if column and column not in entry["columns"]:
            entry["columns"].append(column)
    return list(sources.values())
