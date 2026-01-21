from src.db import db_conn

def get_user_by_username(username: str):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, totp_secret, is_active FROM users WHERE username=?",
            (username,),
        ).fetchone()
    return dict(row) if row else None
