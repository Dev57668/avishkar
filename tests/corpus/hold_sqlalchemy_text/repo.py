from sqlalchemy import text


def find(conn, ident):
    return conn.execute(text(f"SELECT * FROM items WHERE id = {ident}")).fetchall()
