CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
ON login_attempts(ip, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time
ON login_attempts(attempted_at);
