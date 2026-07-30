-- 관리자 구조 도입
-- 비밀번호 분실 시 이메일 인증 대신 관리자가 임시 비밀번호를 발급하는 방식이라
-- 계정에 관리자 플래그가 필요하다. 최초 가입자가 자동으로 관리자가 된다.

ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

-- 임시 비밀번호로 로그인한 계정은 스스로 비밀번호를 바꾸도록 표시해 둔다
ALTER TABLE users ADD COLUMN must_change_pw INTEGER NOT NULL DEFAULT 0;

-- 검증 과정에서 만든 테스트 계정 정리 (세션·기록까지 함께)
DELETE FROM trades   WHERE user_id IN (SELECT id FROM users);
DELETE FROM sessions WHERE user_id IN (SELECT id FROM users);
DELETE FROM users;
