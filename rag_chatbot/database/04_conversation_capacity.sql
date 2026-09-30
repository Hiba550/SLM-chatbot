-- Apply after 03_auth_sessions.sql. Memory is scoped to one authenticated
-- session and one conversation; deleting the session removes its history.
CREATE TABLE IF NOT EXISTS ChatTurns (
    TurnID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    SessionID CHAR(64) NOT NULL,
    ConversationID VARCHAR(80) NOT NULL,
    Question TEXT NOT NULL,
    AnswerText TEXT NOT NULL,
    GeneratedSQL TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_chat_context (SessionID, ConversationID, TurnID),
    INDEX idx_chat_session_recent (SessionID, TurnID),
    CONSTRAINT fk_chat_session FOREIGN KEY (SessionID)
        REFERENCES AuthSessions(SessionID) ON DELETE CASCADE
);

-- Shared, database-backed leases bound model demand across WSGI threads and
-- processes. Expired leases recover after a worker exits unexpectedly.
CREATE TABLE IF NOT EXISTS ModelSlots (
    SlotID TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    LeaseToken CHAR(64) NULL,
    LeaseExpiresAt DATETIME(6) NOT NULL DEFAULT '1970-01-01 00:00:00.000000'
);
INSERT IGNORE INTO ModelSlots (SlotID) VALUES (1), (2), (3), (4);
