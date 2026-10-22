def q(db, n):
    sql = f"SELECT * FROM u WHERE n='{n}'"
    db.execute(sql)
