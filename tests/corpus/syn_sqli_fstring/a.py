def q(db, n):
    db.execute(f"SELECT * FROM u WHERE n='{n}'")
