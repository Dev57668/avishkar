def q(db, n):
    db.execute("SELECT * FROM u WHERE n='%s'" % n)
