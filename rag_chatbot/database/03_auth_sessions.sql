-- Additive migration: apply to the configured database before starting the app.
CREATE TABLE IF NOT EXISTS AuthSessions (
    SessionID CHAR(64) PRIMARY KEY,
    UserID INT NOT NULL,
    AccessFingerprint CHAR(64) NOT NULL,
    CredentialStamp CHAR(64) NOT NULL,
    ExpiresAt DATETIME NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_session_user (UserID),
    INDEX idx_session_expiry (ExpiresAt),
    FOREIGN KEY (UserID) REFERENCES AppUsers(UserID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS RequestThrottle (
    BucketKey CHAR(64) PRIMARY KEY,
    WindowStart DATETIME NOT NULL,
    Attempts INT NOT NULL,
    INDEX idx_throttle_window (WindowStart)
);
