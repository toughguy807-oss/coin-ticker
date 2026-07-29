-- coin-ticker D1 스키마
-- 트레이드 히스토리를 계정별로 보관한다. 비밀번호는 원문을 저장하지 않고
-- PBKDF2(SHA-256, 10만회) 해시 + 계정마다 다른 salt 로만 남긴다.

CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash     TEXT    NOT NULL,
  pw_salt     TEXT    NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- 한 건 = "A를 얼마 내고 B를 얼마 받았다" 한 번의 교환
CREATE TABLE IF NOT EXISTS trades (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  traded_at    INTEGER NOT NULL,          -- 사용자가 지정한 거래 시각(기본: 기록 시각)
  from_market  TEXT    NOT NULL,          -- 예: KRW-BTC
  to_market    TEXT    NOT NULL,
  from_qty     REAL    NOT NULL,          -- 낸 수량
  to_qty       REAL    NOT NULL,          -- 받은 수량
  ratio        REAL    NOT NULL,          -- 체결 교환비 (1 from = ? to)
  from_price   REAL    NOT NULL,          -- 기록 시점 호가통화 기준 단가
  to_price     REAL    NOT NULL,
  quote        TEXT    NOT NULL,          -- KRW / BTC / USDT
  fee_applied  INTEGER NOT NULL DEFAULT 1,
  memo         TEXT,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trades_user ON trades(user_id, traded_at DESC);
