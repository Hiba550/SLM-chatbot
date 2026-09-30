-- Additive audit trail for administrator access changes.
-- Events are deliberately retained when a referenced account is later removed.

CREATE TABLE IF NOT EXISTS SecurityEvents (
    EventID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ActorUserID INT NULL,
    ActorUsername VARCHAR(50) NULL,
    EventType VARCHAR(40) NOT NULL,
    TargetType VARCHAR(24) NOT NULL,
    TargetIdentifier VARCHAR(100) NOT NULL,
    Details VARCHAR(500) NULL,
    IPAddress VARCHAR(50) NULL,
    LoggedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_security_events_logged (LoggedAt),
    INDEX idx_security_events_actor (ActorUserID, LoggedAt),
    INDEX idx_security_events_target (TargetType, TargetIdentifier, LoggedAt)
);
