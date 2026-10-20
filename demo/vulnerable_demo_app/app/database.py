import sqlite3

DB_PATH = "shop.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_user_by_name(username):
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id, email, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def search_products(term, category):
    conn = get_connection()
    sql = f"SELECT * FROM products WHERE name LIKE '%{term}%' AND category = '{category}'"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def find_user_by_name_safe(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_order_total(order_id):
    conn = get_connection()
    row = conn.execute("SELECT SUM(price * quantity) AS total FROM order_items WHERE order_id = ?", (order_id,)).fetchone()
    conn.close()
    return row["total"] or 0


def delete_comment(comment_id):
    conn = get_connection()
    conn.execute("DELETE FROM comments WHERE id = %s" % comment_id)
    conn.commit()
    conn.close()
