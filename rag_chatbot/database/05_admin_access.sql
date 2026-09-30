-- Additive migration for the administrator console and granular data grants.
-- Apply once to the configured application database. Existing built-in roles
-- continue to use the reviewed server policy until an administrator saves a
-- custom role scope. A user's optional custom scope can only narrow that role.

CREATE TABLE IF NOT EXISTS RoleDataScopes (
    RoleID INT NOT NULL PRIMARY KEY,
    ScopeMode ENUM('custom') NOT NULL DEFAULT 'custom',
    UpdatedBy INT NULL,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_role_scope_role FOREIGN KEY (RoleID) REFERENCES Roles(RoleID) ON DELETE CASCADE,
    CONSTRAINT fk_role_scope_admin FOREIGN KEY (UpdatedBy) REFERENCES AppUsers(UserID) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS RoleSourceGrants (
    RoleID INT NOT NULL,
    SourceName VARCHAR(64) NOT NULL,
    GrantAllColumns TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (RoleID, SourceName),
    CONSTRAINT fk_role_source_scope FOREIGN KEY (RoleID) REFERENCES RoleDataScopes(RoleID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS RoleColumnGrants (
    RoleID INT NOT NULL,
    SourceName VARCHAR(64) NOT NULL,
    ColumnName VARCHAR(64) NOT NULL,
    PRIMARY KEY (RoleID, SourceName, ColumnName),
    CONSTRAINT fk_role_column_source FOREIGN KEY (RoleID, SourceName)
        REFERENCES RoleSourceGrants(RoleID, SourceName) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UserDataScopes (
    UserID INT NOT NULL PRIMARY KEY,
    ScopeMode ENUM('custom') NOT NULL DEFAULT 'custom',
    UpdatedBy INT NULL,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_scope_user FOREIGN KEY (UserID) REFERENCES AppUsers(UserID) ON DELETE CASCADE,
    CONSTRAINT fk_user_scope_admin FOREIGN KEY (UpdatedBy) REFERENCES AppUsers(UserID) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS UserSourceGrants (
    UserID INT NOT NULL,
    SourceName VARCHAR(64) NOT NULL,
    GrantAllColumns TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (UserID, SourceName),
    CONSTRAINT fk_user_source_scope FOREIGN KEY (UserID) REFERENCES UserDataScopes(UserID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS UserColumnGrants (
    UserID INT NOT NULL,
    SourceName VARCHAR(64) NOT NULL,
    ColumnName VARCHAR(64) NOT NULL,
    PRIMARY KEY (UserID, SourceName, ColumnName),
    CONSTRAINT fk_user_column_source FOREIGN KEY (UserID, SourceName)
        REFERENCES UserSourceGrants(UserID, SourceName) ON DELETE CASCADE
);
