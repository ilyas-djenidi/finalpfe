# models.py
"""
User model + authentication helpers — backed by Supabase via database.py.
"""

import logging
from typing import Optional

import bcrypt
import pyotp
from flask_login import UserMixin

logger = logging.getLogger(__name__)


class User(UserMixin):
    def __init__(self, user_id: int, username: str, password_hash: str,
                 role: str, permissions: list[str],
                 totp_secret: Optional[str] = None, totp_enabled: bool = False,
                 failed_attempts: int = 0, locked_until: Optional[str] = None):
        self.id              = user_id
        self.username        = username
        self._pass_hash      = password_hash
        self.role            = role
        self._permissions    = set(permissions)
        self.totp_secret     = totp_secret
        self.totp_enabled    = bool(totp_enabled)
        self.failed_attempts = int(failed_attempts or 0)
        self.locked_until    = locked_until

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                self._pass_hash.encode("utf-8"),
            )
        except Exception:
            return False

    def has_permission(self, permission: str) -> bool:
        return permission in self._permissions

    def verify_totp(self, token: str) -> bool:
        if not self.totp_secret or not self.totp_enabled:
            return False
        try:
            return pyotp.TOTP(self.totp_secret).verify(token, valid_window=1)
        except Exception:
            return False

    @property
    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        from datetime import datetime, timezone
        try:
            unlock = datetime.fromisoformat(self.locked_until)
            return datetime.now(timezone.utc) < unlock
        except Exception:
            return False


def _row_to_user(row: dict) -> User:
    return User(
        user_id       = row["id"],
        username      = row["username"],
        password_hash = row["password_hash"],
        role          = row.get("role", "analyst"),
        permissions   = row.get("permissions", []),
        totp_secret   = row.get("totp_secret"),
        totp_enabled  = row.get("totp_enabled", False),
        failed_attempts = row.get("failed_attempts", 0),
        locked_until  = row.get("locked_until"),
    )


def authenticate_user(username: str, password: str) -> tuple[Optional["User"], str]:
    """
    Validate credentials against Supabase.
    Returns (user, error_message). On success error_message is "".
    """
    from datetime import datetime, timezone
    from database import get_user_by_username, update_user

    row = get_user_by_username(username)

    # Always run bcrypt to prevent timing attacks
    dummy_hash = "$2b$12$" + "x" * 53
    candidate_hash = row["password_hash"] if row else dummy_hash

    try:
        password_ok = bcrypt.checkpw(password.encode("utf-8"), candidate_hash.encode("utf-8"))
    except Exception:
        password_ok = False

    if not row:
        return None, "اسم المستخدم أو كلمة المرور غير صحيحة."

    user = _row_to_user(row)

    if user.is_locked:
        return None, "الحساب مقفل مؤقتاً بسبب محاولات دخول متعددة. حاول لاحقاً."

    if not password_ok:
        new_attempts = user.failed_attempts + 1
        locked_until = None
        if new_attempts >= 5:
            from datetime import timedelta
            locked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        update_user(user.id, failed_attempts=new_attempts, locked_until=locked_until)
        return None, "اسم المستخدم أو كلمة المرور غير صحيحة."

    return user, ""


def load_user_from_db(user_id: str) -> Optional[User]:
    """Flask-Login user_loader callback."""
    try:
        from database import get_user_by_id
        row = get_user_by_id(int(user_id))
        return _row_to_user(row) if row else None
    except Exception as exc:
        logger.error("load_user_from_db: %s", exc)
        return None
