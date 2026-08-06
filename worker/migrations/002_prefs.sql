-- 사용자 설정 보관
-- A/B 선택·즐겨찾기·알림·테마 등은 원래 브라우저 localStorage 에만 있어
-- 기기를 바꾸면 사라졌다. 계정에 붙여 어디서 접속하든 이어지게 한다.
--
-- 항목이 계속 늘어날 성격이라 컬럼으로 쪼개지 않고 JSON 한 덩어리로 둔다.
-- 서버는 내용을 해석하지 않고 크기만 제한한다 (스키마 변경 없이 항목 추가 가능).

CREATE TABLE IF NOT EXISTS user_prefs (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL
);
