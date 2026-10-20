ALTER TABLE users MODIFY username VARCHAR(254) NOT NULL;
ALTER TABLE users MODIFY password_hash VARCHAR(255) NOT NULL;
ALTER TABLE users ADD COLUMN email VARCHAR(254) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN full_name VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE users ADD COLUMN locked_until DATETIME(6);
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN totp_secret VARCHAR(512);
ALTER TABLE users ADD COLUMN password_changed_at DATETIME(6);
ALTER TABLE users ADD CONSTRAINT uk_users_email UNIQUE (email);

INSERT INTO roles (name) VALUES ('ROLE_STUDENT'), ('ROLE_LECTURER');

CREATE TABLE email_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6),
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_email_token_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX uk_email_token_hash ON email_tokens (token_hash);
CREATE INDEX ix_email_token_user_purpose ON email_tokens (user_id, purpose, created_at);

CREATE TABLE password_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX ix_password_history_user ON password_history (user_id, created_at);

CREATE TABLE login_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(254) NOT NULL,
    success BOOLEAN NOT NULL,
    kind VARCHAR(20) NOT NULL,
    attempted_at DATETIME(6) NOT NULL
);
CREATE INDEX ix_login_attempts_user_time ON login_attempts (username, kind, attempted_at);

CREATE TABLE recovery_codes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    used_at DATETIME(6),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX ix_recovery_user ON recovery_codes (user_id, code_hash);

CREATE TABLE audit_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    occurred_at DATETIME(6) NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    actor_username VARCHAR(254),
    target_username VARCHAR(254),
    ip VARCHAR(45),
    user_agent VARCHAR(512),
    details VARCHAR(500)
);
CREATE INDEX ix_audit_occurred ON audit_events (occurred_at);
CREATE INDEX ix_audit_type ON audit_events (event_type);
CREATE INDEX ix_audit_actor ON audit_events (actor_username);

CREATE TABLE rate_limits (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    action VARCHAR(40) NOT NULL,
    occurred_at DATETIME(6) NOT NULL
);
CREATE INDEX ix_rate_limits_lookup ON rate_limits (ip, action, occurred_at);
