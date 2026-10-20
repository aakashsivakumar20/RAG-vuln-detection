from app.database import get_connection


def get_account(request, account_id):
    conn = get_connection()
    row = conn.execute("SELECT id, owner_id, balance, iban FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_account_checked(request, account_id):
    conn = get_connection()
    row = conn.execute("SELECT id, owner_id, balance, iban FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    if row is None or row["owner_id"] != request.user.id:
        raise PermissionError("not your account")
    return dict(row)


def delete_user(request, user_id):
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": user_id}


def admin_delete_user(request, user_id):
    if not request.user.is_authenticated or request.user.role != "admin":
        raise PermissionError("administrators only")
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": user_id}
