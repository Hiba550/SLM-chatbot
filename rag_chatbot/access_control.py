"""Database-backed, role and user-level data grants for chat queries."""

from db import execute_query
from policy import ANALYTIC_TABLES, ROLE_TABLES, SOURCE_COLUMNS, columns_for


_SAFE_SOURCES = {name.lower(): name for name in ANALYTIC_TABLES}


def _scope_rows(role_id=None, user_id=None):
    """Read configured grants in one bounded query. Missing scope rows mean role defaults."""
    rows = []
    if role_id is not None:
        rows.append(
            """SELECT 'role' AS ScopeType, s.ScopeMode, g.SourceName,
                      g.GrantAllColumns, c.ColumnName
               FROM RoleDataScopes s
               LEFT JOIN RoleSourceGrants g ON g.RoleID = s.RoleID
               LEFT JOIN RoleColumnGrants c ON c.RoleID = g.RoleID AND c.SourceName = g.SourceName
               WHERE s.RoleID = %s"""
        )
    if user_id is not None:
        rows.append(
            """SELECT 'user' AS ScopeType, s.ScopeMode, g.SourceName,
                      g.GrantAllColumns, c.ColumnName
               FROM UserDataScopes s
               LEFT JOIN UserSourceGrants g ON g.UserID = s.UserID
               LEFT JOIN UserColumnGrants c ON c.UserID = g.UserID AND c.SourceName = g.SourceName
               WHERE s.UserID = %s"""
        )
    if not rows:
        return []
    sql = " UNION ALL ".join(rows)
    params = tuple(value for value in (role_id, user_id) if value is not None)
    _, result = execute_query(sql, params)
    return result


def _parse_scope(rows, scope_type):
    mode = "inherit"
    sources = {}
    for row_type, row_mode, source, all_columns, column in rows:
        if row_type != scope_type:
            continue
        mode = str(row_mode or "inherit").lower()
        if not source:
            continue
        canonical = _SAFE_SOURCES.get(str(source).lower())
        if not canonical:
            continue
        item = sources.setdefault(canonical, {"all": False, "columns": set()})
        item["all"] = item["all"] or bool(all_columns)
        if column:
            item["columns"].add(str(column))
    return mode, sources


def _role_default(role):
    return {
        source: columns_for(role, source)
        for source in ROLE_TABLES.get(str(role or "").lower(), [])
        if columns_for(role, source)
    }


def _from_scope(mode, entries, base=None):
    if mode != "custom":
        return {source: list(columns) for source, columns in (base or {}).items()}
    result = {}
    for source, entry in entries.items():
        if entry["all"]:
            columns = list(SOURCE_COLUMNS.get(source, []))
        else:
            allowed = {name.lower(): name for name in SOURCE_COLUMNS.get(source, [])}
            columns = [allowed[name.lower()] for name in entry["columns"] if name.lower() in allowed]
        if columns:
            result[source] = columns
    return result


def role_access(role_id, role):
    rows = _scope_rows(role_id=role_id)
    mode, entries = _parse_scope(rows, "role")
    if str(role or "").lower() == "admin":
        return _role_default("admin"), "default"
    return _from_scope(mode, entries, _role_default(role)), mode


def user_access(user_id, role_id, role):
    rows = _scope_rows(role_id=role_id, user_id=user_id)
    role_mode, role_entries = _parse_scope(rows, "role")
    user_mode, user_entries = _parse_scope(rows, "user")
    if str(role or "").lower() == "admin":
        return _role_default("admin"), "default", "default"
    role_sources = _from_scope(role_mode, role_entries, _role_default(role))
    if user_mode != "custom":
        return role_sources, "inherit", role_mode
    narrowed = {}
    for source, entry in user_entries.items():
        role_columns = role_sources.get(source)
        if not role_columns:
            continue
        if entry["all"]:
            selected = role_columns
        else:
            granted = {name.lower() for name in entry["columns"]}
            selected = [column for column in role_columns if column.lower() in granted]
        if selected:
            narrowed[source] = list(selected)
    return narrowed, "custom", role_mode


def permission_catalog(role=None, sources=None):
    """Serialize safe grantable objects, optionally intersected with a role."""
    source_names = sources if sources is not None else ANALYTIC_TABLES
    role_map = None if role is None else {name.lower(): columns for name, columns in role.items()}
    source_map = source_names if isinstance(source_names, dict) else None
    if source_map is not None:
        source_names = source_map.keys()
    result = []
    for source in source_names:
        canonical = _SAFE_SOURCES.get(str(source).lower())
        if not canonical:
            continue
        columns = list(source_map.get(canonical, SOURCE_COLUMNS.get(canonical, [])) if source_map is not None
                       else SOURCE_COLUMNS.get(canonical, []))
        if role_map is not None:
            columns = role_map.get(canonical.lower(), [])
        if columns:
            result.append({"name": canonical, "columns": list(columns)})
    return result


def validate_grant_list(raw, allowed_sources=None):
    """Validate an allowlist payload and return canonical table/column grants."""
    if not isinstance(raw, list) or len(raw) > len(ANALYTIC_TABLES):
        raise ValueError("Choose valid data sources for this access scope.")
    allowed = None if allowed_sources is None else {
        name.lower(): {column.lower() for column in columns}
        for name, columns in allowed_sources.items()
    }
    grants = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Each data source grant must be an object.")
        canonical = _SAFE_SOURCES.get(str(item.get("name", "")).lower())
        if not canonical or canonical.lower() in seen:
            raise ValueError("A data source is invalid or listed more than once.")
        seen.add(canonical.lower())
        base_columns = list(SOURCE_COLUMNS[canonical])
        if allowed is not None:
            base_columns = [column for column in base_columns if column.lower() in allowed.get(canonical.lower(), set())]
        if not base_columns:
            raise ValueError("This role has no access to that data source.")
        all_columns = item.get("allColumns", False)
        if not isinstance(all_columns, bool):
            raise ValueError("The whole-table access flag must be true or false.")
        raw_columns = item.get("columns", [])
        if not isinstance(raw_columns, list) or len(raw_columns) > len(SOURCE_COLUMNS[canonical]):
            raise ValueError("Choose valid fields for this data source.")
        permitted = {column.lower(): column for column in base_columns}
        selected = []
        for raw_column in raw_columns:
            column = permitted.get(str(raw_column).lower())
            if not column:
                raise ValueError("A requested field is outside the selected access scope.")
            if column not in selected:
                selected.append(column)
        if all_columns:
            selected = []
        elif not selected:
            raise ValueError("Select the table or at least one field for each granted source.")
        grants.append({"name": canonical, "allColumns": all_columns, "columns": selected})
    return grants
